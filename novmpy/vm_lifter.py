from capstone import *
from capstone.x86 import *

from novmpy import handler
from novmpy.bridge import *
from novmpy.match_helper import *
from novmpy.x86_deobf import *
from novmpy.vm_const import *
from novmpy.vm import *
from pyvtil import *

# ref: https://github.com/can1357/NoVmp/blob/master/NoVmp/vmprotect/vtil_lifter.cpp


def search_vmstubs():
    """
    jmp_call stub
    stub:
    push imm4
    call vminit
    """
    stubs = []
    for seg in bridge.get_segs():
        if not seg.is_executable:
            continue
        for i, b in enumerate(bridge.get_bytes(seg.vaddr, seg.memsize)):
            addr = seg.vaddr + i
            if b == 0xE8 or b == 0xE9:
                dst = addr+bridge.read(addr+1, 4)+5
                if bridge.is_readable(dst, 1) and not (dst >= seg.min_addr and dst < seg.max_addr):
                    if bridge.read(dst, 1) == 0x68 and bridge.read(dst+5, 1) == 0xE8:
                        print(f'Discovered vmenter at 0x{addr:X}...')
                        stubs.append((dst-bridge.get_base(), b == 0xE9))
    return stubs


def fix_constant_pool(block: vtil.basic_block):
    vtil.optimizer.stack_pinning_pass(block)
    vtil.optimizer.istack_ref_substitution_pass(block)

    reloc_base = vtil.symbolic.pointer(vtil.symbolic.variable(
        block.begin(), vtil.REG_SP).to_expression())

    def exp_eval(uid):
        var = uid.get_variable()
        if var.is_register() and var.reg().is_image_base():
            return 0
        if var.is_memory() and ((var.mem().base - reloc_base) == 0):
            # TODO:
            return -0  # -base
        return None

    tracer = vtil.cached_tracer()

    it = block.begin()
    while it != block.end():
        ins = it.get()
        if ins.base != vtil.ins.ldd:
            it = it.next()
            continue
        base, off = ins.memory_location()
        if base.is_stack_pointer():
            it = it.next()
            continue

        exp = tracer(vtil.symbolic.variable(it, base))
        res = exp.evaluate(exp_eval)

        if res.is_known():
            rva = res.get_uint64() + off
            if bridge.is_readable(rva, ins.access_size()//8) and\
                    not bridge.is_writeable(rva, ins.access_size()//8):
                value = bridge.read(rva, ins.access_size()//8)
                print(f'fix_constant_pool [{rva:016X}] = {value:016X}')
                ins.base = vtil.ins.mov
                ins.operands = [ins.operands[0],
                                vtil.make_uint(value, ins.access_size())]
        it = it.next()


class VMLifter:
    def __init__(self) -> None:
        self.rtn = vtil.routine()

    def is_valid_vmentry(self, vmentry):
        vmstate, vminit, rage = handler.vmentry_parse(vmentry)
        return vmstate != None

    def lift_il(self, block: vtil.basic_block, state: VMState):
        if state.ip == 0:
            vmstate, vminit, rage = handler.vmentry_parse(
                state.current_handler)
            assert(vmstate != None)

            tmp_state = vmstate
            # rage.extend(vminit.save_regs)

            print('vmstate.ip: {:x}'.format(tmp_state.ip))
            # 0x0048AFF0| vm_init 0x4514a9
            vip = tmp_state.ip
            vip += 0 if tmp_state.config.dir >= 0 else -1
            tmp_state.current_handler = vminit.get_next(tmp_state)
            if block is None:
                block, _ = self.rtn.create_block(vip)
            else:
                new_block = block.fork(vip)
                if new_block is None:
                    return self.rtn.get_block(vip)
                block = new_block
            # push imm
            block.push(vtil.make_int(rage[0].operands[0].imm))
            # call vm_init
            block.push(rage[1].address+rage[1].size)
            for i, j in vminit.pushs:
                if i == CS_OP_IMM:
                    # FIXME!
                    treloc = block.tmp(vtil.arch.bit_count)
                    block.mov(treloc, vtil.REG_IMGBASE)  # 0x140000000
                    block.sub(treloc, 0)  # FIXME! -bridge.get_base()
                    block.push(treloc)
                elif i == CS_OP_REG:
                    if j == X86_REG_EFLAGS:
                        block.pushf()
                    else:
                        block.push(vtil.x86_reg(j))
        else:
            if block is None:
                return None
            tmp_state = state
        # Messages cannot be updated frequently, which can slow down performance.
        bridge.update_msg(f'lifting {block.entry_vip:08X}')
        while True:
            h = handler.factory(tmp_state.current_handler, tmp_state.config)
            if h is None:
                break
            i: handler.VMIns = h.get_instr(tmp_state)
            print(block.sp_offset, i)
            block.label_begin(i.address)
            h.generator(i, block)
            block.label_end()
            assert not isinstance(h, handler.VMInvalid)
            assert not isinstance(h, handler.VMUnknown)

            if isinstance(h, handler.VMNop):
                dst = tmp_state.ip
                if tmp_state.config.dir < 0:
                    dst -= 1
                block.jmp(dst)
                fix_constant_pool(block)
                tmp_state.current_handler = h.get_next(tmp_state)
                self.lift_il(block.fork(dst), tmp_state)
                return block
            elif isinstance(h, handler.VMJmp):
                jmp_dest = block.tmp(vtil.arch.bit_count)
                block.pop(jmp_dest)
                if h.conn_config.dir < 0:
                    block.sub(jmp_dest, 1)
                block.jmp(jmp_dest)

                fix_constant_pool(block)

                flag = vtil.optimizer.aux.branch_analysis_flags(pack=True)
                tracer = vtil.tracer()
                branch_info = vtil.optimizer.aux.analyze_branch(
                    block, tracer, flag)

                print(f"CC {branch_info.cc}")
                print(f"VJMP {branch_info.destinations}")

                def eval_base_remove(uid):
                    var = uid.get_variable()
                    if var.is_register() and var.reg().is_image_base():
                        return 0
                    return None

                targets = []
                for branch in branch_info.destinations:
                    if not branch.is_constant():
                        branch = tracer.rtrace_pexp(branch)
                    if not branch.is_constant():
                        res = branch.evaluate(eval_base_remove)
                        if res.is_known():
                            targets.append(res.get_uint64())
                            continue
                    if not branch.is_constant():
                        continue
                    print(f'Exploring branch => {branch}')
                    targets.append(branch.get_uint64())
                for target in targets:
                    ip = target
                    if h.conn_config.dir < 0:
                        ip += 1
                    if ip > 0x1000 and bridge.is_readable(ip, 1, h.conn_config.dir):
                        tmp_state2 = copy.deepcopy(tmp_state)
                        tmp_state2.config = h.conn_config
                        tmp_state2.ip = ip
                        tmp_state2.key = tmp_state2.ip-tmp_state2.config.rebase
                        next_h = h.get_next(tmp_state2)
                        if bridge.is_readable(next_h, 4):
                            tmp_state2.current_handler = next_h
                            self.lift_il(block.fork(target), tmp_state2)
                break
            elif isinstance(h, handler.VMExit):
                for r in h.pops:
                    if r == X86_REG_EFLAGS:
                        block.popf()
                    else:
                        block.pop(vtil.x86_reg(r))
                jmp_dest = block.tmp(vtil.arch.bit_count)
                block.pop(jmp_dest)
                block.vexit(jmp_dest)

                fix_constant_pool(block)

                jmp_dest = block.back().operands[0]

                tracer = vtil.tracer()
                stack_0 = vtil.symbolic.variable(
                    block.owner.entry_point.begin(), vtil.REG_SP).to_expression()
                stack_1 = tracer.rtrace_p(vtil.symbolic.variable(
                    block.end().prev(), vtil.REG_SP)) + vtil.symbolic.expression(block.sp_offset, vtil.arch.bit_count)
                offset = stack_1 - stack_0
                print(f'sp offset => {offset}')
                if offset.is_constant() and offset.get_int() < 0:
                    mem = vtil.symbolic.variable.memory_t(tracer(vtil.symbolic.variable(
                        block.end().prev(), vtil.REG_SP)) + vtil.symbolic.expression(block.sp_offset, vtil.arch.bit_count), vtil.arch.bit_count)
                    var = vtil.symbolic.variable(block.end().prev(), mem)
                    base_exp = vtil.symbolic.variable(
                        vtil.REG_IMGBASE).to_expression()
                    continue_from = tracer.rtrace_p(var) - base_exp
                    print(f'continue => {continue_from}')
                    if continue_from.is_constant() and self.is_valid_vmentry(continue_from.get_uint()):
                        # block.pop_back()
                        # block.vxcall(jmp_dest)
                        block.wback().base = vtil.ins.vxcall
                        block.wback().vip = tmp_state.ip
                        block.shift_sp(vtil.arch.size, False, block.end())

                        tmp_state = VMState()
                        tmp_state.current_handler = continue_from.get_uint()
                        self.lift_il(block, tmp_state)
                        break

                if jmp_dest.is_immediate():
                    exit_destination = vtil.symbolic.expression(
                        jmp_dest.imm().uval, jmp_dest.bit_count)
                else:
                    var = vtil.symbolic.variable(
                        block.end().prev(), jmp_dest.reg())
                    exit_destination = tracer.rtrace_p(
                        var) - vtil.symbolic.variable(vtil.REG_IMGBASE).to_expression()

                print(f'exit => {exit_destination}')
                if exit_destination.is_constant() and self.is_valid_vmentry(exit_destination.get_uint()):
                    block.pop_back()
                    vmstate, vminit, rage = handler.vmentry_parse(
                        exit_destination.get_uint())

                    for _ins in rage[:-2]:
                        if _ins.id in [X86_INS_PUSHFD, X86_INS_PUSHFQ]:
                            block.pushf()
                            continue
                        elif _ins.id == [X86_INS_POPFD, X86_INS_POPFQ]:
                            block.popf()
                            continue
                        reads, writes = _ins.regs_access()
                        for reg_read in reads:
                            op = vtil.x86_reg(reg_read)
                            if reg_read in [X86_REG_ESP, X86_REG_RSP]:
                                op = vtil.REG_SP
                            if reg_read == X86_REG_EFLAGS:
                                op = vtil.REG_FLAGS
                            block.vpinr(op)
                        block.label_begin(_ins.address)
                        for b in _ins.bytes:
                            block.vemit(vtil.make_uint(b, 8))
                        block.label_end()
                        for reg_write in writes:
                            op = vtil.x86_reg(reg_write)
                            assert reg_write not in [X86_REG_ESP, X86_REG_RSP]
                            if reg_write == X86_REG_EFLAGS:
                                op = vtil.REG_FLAGS
                            block.vpinw(op)
                    block.jmp(vtil.invalid_vip)

                    state = VMState(current_handler=rage[-2].address)
                    block_next = self.lift_il(block, state)

                    # block.pop_back()
                    # block.jmp(block_next.entry_vip)
                    block.wback().operands = [vtil.make_uint(
                        block_next.entry_vip, vtil.arch.bit_count)]
                break
            elif isinstance(h, handler.VMCrc):
                # TODO:
                # create new block
                # translate crc
                # jump back
                # assert(False)
                pass
            tmp_state.current_handler = h.get_next(tmp_state)
        return block

# for k, h in handler.vm_handlers.items():
#     if isinstance(h, handler.VMUnknown):
#         print('-----------------')
#         print(h.config)
#         for i in h.body:
#             print(i)
