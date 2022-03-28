from novmpy.match_helper import *
from novmpy.x86_deobf import *
from novmpy.vm import *
from novmpy.vm_const import *
import struct
from pyvtil import *

vm_handlers = {}

FLAG_CF = vtil.REG_FLAGS.select(1, 0)
FLAG_PF = vtil.REG_FLAGS.select(1, 2)
FLAG_AF = vtil.REG_FLAGS.select(1, 4)
FLAG_ZF = vtil.REG_FLAGS.select(1, 6)
FLAG_SF = vtil.REG_FLAGS.select(1, 7)
FLAG_DF = vtil.REG_FLAGS.select(1, 10)
FLAG_OF = vtil.REG_FLAGS.select(1, 11)

if vtil.arch.size == 4:
    ZAX = vtil.x86_reg.EAX
    ZBX = vtil.x86_reg.EBX
    ZCX = vtil.x86_reg.ECX
    ZDX = vtil.x86_reg.EDX
else:
    ZAX = vtil.x86_reg.RAX
    ZBX = vtil.x86_reg.RBX
    ZCX = vtil.x86_reg.RCX
    ZDX = vtil.x86_reg.RDX


def make_virtual_register(context_offset, size):
    return vtil.register_desc(vtil.register_virtual,
                              int(context_offset//vtil.arch.size),
                              size*8,
                              int(context_offset % vtil.arch.size)*8)


class VMIns(object):
    def __init__(self):
        self.address = 0
        self.id = VM_INS_INVALID
        self.mne = ''
        self.opstr = ''
        self.opsize = 0
        self.data = 0
        self.haddr = 0  # vm handler address
        self.comment = ''

    def __str__(self) -> str:
        if self.opsize == 0:
            s = '{:08X}| {}'.format(self.address, self.mne)
        else:
            s = '{:08X}| {} {}'.format(self.address, self.mne, self.opstr)
        if self.comment:
            s += ';'+self.comment
        return s


def align_size(v):
    if v == 1:
        return 2
    return v


def same_size(x, y):
    return align_size(x) == align_size(y)


def size2name(size):
    s = ''
    if size == 1:
        s = 'byte'
    elif size == 2:
        s = 'word'
    elif size == 4:
        s = 'dword'
    elif size == 8:
        s = 'qword'
    else:
        assert(False)
    return s


def reg2name(index, off, size):
    prefix = 'vm_r{}'.format(index)
    suffix = ''
    if size == 1:
        suffix = 'b'
    elif size == 2:
        suffix = 'w'
    elif size == 4:
        suffix = 'd'
    elif size == 8:
        suffix = 'q'
    if size <= 2:
        if off != 0:
            suffix += 'h'
        else:
            suffix += 'l'
    return prefix+suffix


class VMBase(object):
    def __init__(self, **kwargs):
        self.name = 'vmp_base'
        self.bytecode_size = 0
        self.opsize = 0
        self.address = kwargs.get('address', 0)
        self.hbase = kwargs.get('hbase', 0)
        self.insns = kwargs.get('insns', [])
        self.body = kwargs.get('body', [])
        self.connect = kwargs.get('connect', [])
        self.config: VMConfig = kwargs.get('config', None)
        self.conn_config: VMConfig = kwargs.get('conn_config', None)

    def get_next(self, vmstate: VMState):
        val = vmstate.fetch(self.dec_size)
        off = vmstate.decode_emu(
            self.dec_conn, val, self.dec_reg, self.dec_size)
        b1 = struct.pack('<I', off)
        (off,) = struct.unpack('<i', b1)
        next_h = (self.hbase+off) & get_mask(8*bridge.size)
        return next_h

    def get_instr(self, vmstate):
        raise NotImplementedError('')

    def parse_connect(self):
        mh = MatchHelper(self.connect, self.conn_config)
        args = {}
        if mh.decode(args):
            self.dec_conn = args['decoder']
            self.dec_reg = args['reg']
            self.dec_size = args['size']  # DWORD
            return True
        return False

    def match(self):
        raise NotImplementedError('')

    def generator(self, ins: VMIns, block: vtil.basic_block):
        raise NotImplementedError(str(ins))


class VMNop(VMBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = 'vmp_nop'

    def match(self):
        if len(self.body) != 1:
            return False
        insn: CsInsn = self.body[0]
        if instr_match(insn, X86_INS_LEA, [X86_OP_REG, X86_OP_MEM], [self.config.reg_base, {'base': X86_REG_INVALID, 'index': X86_REG_INVALID, 'scale': 1}]):
            self.hbase = insn.operands[1].mem.disp
            return True
        if bridge.is64bit() and instr_match(insn, X86_INS_LEA, [X86_OP_REG, X86_OP_MEM], [self.config.reg_base, {'base': X86_REG_RIP, 'index': X86_REG_INVALID, 'scale': 1, 'disp': -7}]):
            self.hbase = insn.address
            return True
        return False

    def get_instr(self, vmstate: VMState):
        i = VMIns()
        i.haddr = self.address
        i.id = VM_INS_NOP
        i.address = vmstate.ip-vmstate.config.dir*4
        i.mne = 'nop'
        i.opstr = ''
        i.data = 0
        i.opsize = self.opsize
        return i

    def generator(self, ins: VMIns, block: vtil.basic_block):
        block.nop()


class VMPushReg(VMBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = 'vmp_push_reg'
        self.bytecode_size = 1

    def match(self):
        mh = MatchHelper(self.body, self.config)
        args = {}
        if mh.fetch_byte() and\
                mh.decode(args) and\
                mh.read({'size': 'size1'}) and\
                mh.store(0, {'size': align_size(mh.get_ph('size1'))}):
            self.decoder = args['decoder']
            self.reg = args['reg']
            self.opsize = mh.get_ph('size1')
            return True
        return False

    def get_instr(self, vmstate: VMState):
        i = VMIns()
        i.haddr = self.address
        i.id = VM_INS_PUSH_REG
        i.address = vmstate.ip-vmstate.config.dir*4
        v = vmstate.decode_emu(self.decoder, vmstate.fetch(1), self.reg, 1)
        index = int(v / bridge.size)
        off = int(v % bridge.size)
        i.mne = 'push_reg{}'.format(self.opsize)
        i.opstr = reg2name(index, off, self.opsize)
        i.data = v
        i.opsize = self.opsize
        return i

    def generator(self, ins: VMIns, block: vtil.basic_block):
        block.push(make_virtual_register(ins.data, ins.opsize))


class VMPopReg(VMBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = 'vmp_pop_reg'
        self.bytecode_size = 1

    def match(self):
        mh = MatchHelper(self.body, self.config)
        args = {}
        mh.reset()
        if mh.load(0, {'size': 'size1'}) and\
                mh.fetch_byte() and\
                mh.decode(args) and\
                mh.write({'size': 'size2'}) and\
                same_size(mh.get_ph('size1'), mh.get_ph('size2')):
            self.decoder = args['decoder']
            self.reg = args['reg']
            self.opsize = mh.get_ph('size2')
            return True
        # template 2
        args = {}
        mh.reset()
        if mh.fetch_byte() and\
                mh.decode(args) and\
                mh.load(0, {'size': 'size1'}) and\
                mh.write({'size': 'size2'}) and\
                same_size(mh.get_ph('size1'), mh.get_ph('size2')):
            self.decoder = args['decoder']
            self.reg = args['reg']
            self.opsize = mh.get_ph('size2')
            return True
        return False

    def get_instr(self, vmstate: VMState):
        i = VMIns()
        i.haddr = self.address
        i.id = VM_INS_POP_REG
        i.address = vmstate.ip-vmstate.config.dir*4
        v = vmstate.decode_emu(self.decoder, vmstate.fetch(1), self.reg, 1)
        index = int(v / bridge.size)
        off = int(v % bridge.size)
        i.mne = 'pop_reg{}'.format(self.opsize)
        i.opstr = reg2name(index, off, self.opsize)
        i.data = v
        i.opsize = self.opsize
        return i

    def generator(self, ins: VMIns, block: vtil.basic_block):
        block.pop(make_virtual_register(ins.data, ins.opsize))


class VMPushImm(VMBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = 'vmp_push_imm'

    def match(self):
        args = {}
        mh = MatchHelper(self.body, self.config)
        if mh.fetch({'size': 'size1'}) and\
                mh.decode(args) and\
                mh.store(0, {'size': align_size(mh.get_ph('size1'))}):
            self.decoder = args['decoder']
            self.reg = args['reg']
            self.bytecode_size = args['size']
            self.opsize = args['size']
            return True
        return False

    def get_instr(self, vmstate: VMState):
        i = VMIns()
        i.haddr = self.address
        i.id = VM_INS_PUSH_IMM
        i.address = vmstate.ip-vmstate.config.dir*4
        imm = vmstate.decode_emu(self.decoder, vmstate.fetch(
            self.bytecode_size), self.reg, self.bytecode_size)
        i.mne = 'push_imm{}'.format(self.opsize)
        if self.opsize == 1 or self.opsize == 2:
            i.opstr = '0x{:04X}'.format(imm)
        elif self.opsize == 4:
            i.opstr = '0x{:08X}'.format(imm)
        else:
            i.opstr = '0x{:X}'.format(imm)
        i.data = imm
        i.opsize = self.opsize
        return i

    def generator(self, ins: VMIns, block: vtil.basic_block):
        block.push(vtil.make_uint(ins.data, ins.opsize*8))


class VMCall(VMBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = 'vmp_call'
        self.bytecode_size = 1

    def match(self):
        mh = MatchHelper(self.body, self.config)
        args = {}
        if mh.fetch_byte() and mh.decode(args) and mh.batch(X86_INS_CALL):
            self.decoder = args['decoder']
            self.reg = args['reg']
            self.opsize
            return True
        return False

    def get_instr(self, vmstate: VMState):
        i = VMIns()
        i.haddr = self.address
        i.id = VM_INS_CALL
        i.address = vmstate.ip-vmstate.config.dir*4
        imm = vmstate.decode_emu(self.decoder, vmstate.fetch(
            self.bytecode_size), self.reg, self.bytecode_size)
        i.mne = 'call'
        i.opstr = '#{}_args'.format(imm)
        i.data = imm
        i.opsize = self.opsize
        return i


class VMCrc(VMBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = 'vmp_crc'
        self.bytecode_size = 0
        self.table = 0
        self.xorkey = 0

    def calc_crc(self, addr, size):
        hash = 0
        code = bridge.get_bytes(addr, size)
        for b in code:
            v = bridge.read(self.table+((b ^ hash) & 0xFF)*4, 4)
            hash >>= 8
            hash ^= v
            hash ^= self.xorkey
        return hash ^ 0xFFFFFFFF

    def match(self):
        if len(self.body) < 15:
            return False
        args = {}
        mh = MatchHelper(self.body, self.config)
        # movzx esi, byte ptr [eax]
        # mov esi, dword ptr [esi*4 + 0x7b06b8]
        # XOR
        # INC
        # DEC
        # NOT
        if (mh.load(0, {'reg': 'ph1'}) and
            mh.load(bridge.size, {'reg': 'ph2'}) and
                mh.batch([X86_INS_XOR, X86_INS_INC, X86_INS_DEC, X86_INS_NOT]) and
                mh.store_dword(0)):
            for i in self.body:
                i: CsInsn
                if bridge.is64bit():
                    if (instr_match(i, X86_INS_LEA, [X86_OP_REG, X86_OP_MEM], [None, {'base': X86_REG_RIP, 'index': X86_REG_INVALID, 'scale': 1}])):
                        (op1, op2) = i.operands
                        self.table = i.address+op2.mem.disp+i.size
                elif (instr_match(i, X86_INS_MOV, [X86_OP_REG, X86_OP_MEM], [None, {'base': X86_REG_INVALID, 'scale': 4}])):
                    (op1, op2) = i.operands
                    if op1.reg == op2.mem.base:
                        self.table = op2.mem.disp
                if instr_match(i, X86_INS_XOR, [X86_OP_REG, X86_OP_IMM]):
                    (op1, op2) = i.operands
                    self.xorkey = op2.imm
                    break
            return True
        return False

    def get_instr(self, vmstate: VMState):
        i = VMIns()
        i.haddr = self.address
        i.id = VM_INS_CRC
        i.address = vmstate.ip-vmstate.config.dir*4
        i.mne = 'crc'
        i.data = 0
        i.opsize = self.opsize
        return i

    def generator(self, ins: VMIns, block: vtil.basic_block):
        a0, a1 = block.tmp(vtil.arch.bit_count, vtil.arch.bit_count)
        a2 = block.tmp(32)
        block.pop(a0)
        block.pop(a1)

        block.push(a2)


class VMAdd(VMBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = 'vmp_add'

    def match(self):
        mh = MatchHelper(self.body, self.config)
        args = {}
        if mh.load(0, {'size': 'size'}) and\
                mh.load(align_size(mh.get_ph('size'))) and\
                mh.match(X86_INS_ADD, [X86_OP_REG, X86_OP_REG]) and\
                mh.store(bridge.size) and\
                mh.store_eflags():
            self.opsize = mh.get_ph('size')
            return True
        return False

    def get_instr(self, vmstate: VMState):
        i = VMIns()
        i.haddr = self.address
        i.id = VM_INS_ADD
        i.address = vmstate.ip-vmstate.config.dir*4
        i.mne = 'add{}'.format(self.opsize)
        i.opstr = ''
        i.data = 0
        i.opsize = self.opsize
        return i

    def generator(self, ins: VMIns, block: vtil.basic_block):
        t0, t1, t2 = block.tmp(ins.opsize*8, ins.opsize*8, ins.opsize*8)
        b0, b1, b2, b3 = block.tmp(1, 1, 1, 1)
        block.pop(t0)
        block.pop(t1)

        block.mov(t2, t1)
        block.add(t1, t0)

        block.tl(FLAG_SF, t1, 0)
        block.te(FLAG_ZF, t1, 0)
        block.tul(FLAG_CF, t1, t2)

        block.tl(b2, t2, 0)
        block.tl(b3, t0, 0)
        block.te(b0, b2, b3)

        block.tl(b2, t2, 0)
        block.tl(b3, t1, 0)
        block.tne(b1, b2, b3)

        block.mov(FLAG_OF, b0)
        block.band(FLAG_OF, b1)

        block.push(t1)
        block.pushf()


class VMNor(VMBase):  # not not and
    # (~a)&(~b) = ~(a|b)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = 'vmp_nor'

    def match(self):
        mh = MatchHelper(self.body, self.config)
        args = {}
        if (mh.load(0, {'size': 'size'}) and mh.load(align_size(mh.get_ph('size'))) and
                mh.batch([X86_INS_NOT, X86_INS_NOT, X86_INS_AND]) and
                mh.store(bridge.size) and mh.store_eflags()):
            self.opsize = mh.get_ph('size')
            return True
        return False

    def get_instr(self, vmstate: VMState):
        i = VMIns()
        i.haddr = self.address
        i.id = VM_INS_NOR
        i.address = vmstate.ip-vmstate.config.dir*4
        i.mne = 'nor{}'.format(self.opsize)
        i.opstr = ''
        i.data = 0
        i.opsize = self.opsize
        return i

    def generator(self, ins: VMIns, block: vtil.basic_block):
        t0, t1 = block.tmp(ins.opsize*8, ins.opsize*8)
        block.pop(t0)
        block.pop(t1)
        block.bnot(t0)
        block.bnot(t1)
        block.band(t0, t1)
        block.tl(FLAG_SF, t0, 0)
        block.te(FLAG_ZF, t0, 0)
        block.mov(FLAG_OF, 0)
        block.mov(FLAG_CF, 0)
        block.push(t0)
        block.pushf()


class VMNand(VMBase):  # not not or
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = 'vmp_nand'

    def match(self):
        mh = MatchHelper(self.body, self.config)
        args = {}
        if (mh.load(0, {'size': 'size'}) and mh.load(align_size(mh.get_ph('size'))) and
                mh.batch([X86_INS_NOT, X86_INS_NOT, X86_INS_OR]) and
                mh.store(bridge.size) and mh.store_eflags()):
            self.opsize = mh.get_ph('size')
            return True
        return False

    def get_instr(self, vmstate: VMState):
        i = VMIns()
        i.haddr = self.address
        i.id = VM_INS_NAND
        i.address = vmstate.ip-vmstate.config.dir*4
        i.mne = 'nand{}'.format(self.opsize)
        i.opstr = ''
        i.data = 0
        i.opsize = self.opsize
        return i

    def generator(self, ins: VMIns, block: vtil.basic_block):
        t0, t1 = block.tmp(ins.opsize*8, ins.opsize*8)
        block.pop(t0)
        block.pop(t1)
        block.bnot(t0)
        block.bnot(t1)
        block.bor(t0, t1)
        block.tl(FLAG_SF, t0, 0)
        block.te(FLAG_ZF, t0, 0)
        block.mov(FLAG_OF, 0)
        block.mov(FLAG_CF, 0)
        block.push(t0)
        block.pushf()


class VMStr(VMBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = 'vmp_str'

    def match(self):
        if abs(len(self.body) - 4) > 2:
            return False
        mh = MatchHelper(self.body, self.config)
        if mh.load_zword(0, {'reg': 'ph1'}) and\
                mh.load(bridge.size, {'reg': 'ph2', 'size': 'size'}) and\
                mh.mem_write({'addr': 'ph1', 'val': 'ph2', 'segment': 'ph3', 'size': 'size'}):
            self.segment = mh.get_ph('ph3')
            self.opsize = mh.get_ph('size')
            return True
        return False

    def get_instr(self, vmstate: VMState):
        i = VMIns()
        i.haddr = self.address
        i.id = VM_INS_STR
        i.address = vmstate.ip-vmstate.config.dir*4
        i.mne = 'store'
        s = size2name(self.opsize)
        if self.segment == X86_REG_INVALID:
            i.opstr = s+' '+bridge.reg_name(X86_REG_DS)
        else:
            i.opstr = s+' '+bridge.reg_name(self.segment)
        i.data = self.segment
        i.opsize = self.opsize
        return i

    def generator(self, ins: VMIns, block: vtil.basic_block):
        t0, t1 = block.tmp(vtil.arch.bit_count, ins.opsize*8)
        block.pop(t0)
        block.pop(t1)
        if self.segment == X86_REG_GS:
            block.vemits("mov rax, gs:0x30")
            block.vpinw(ZAX)
            block.add(t0, ZAX)
        elif self.segment == X86_REG_FS:
            block.vemits("mov eax, fs:0x18")
            block.vpinw(ZAX)
            block.add(t0, ZAX)
        block.str(t0, 0, t1)


class VMLdr(VMBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = 'vmp_ldr'

    def match(self):
        if abs(len(self.body) - 3) > 2:
            return False
        mh = MatchHelper(self.body, self.config)
        if mh.load_zword(0, {'reg': 'ph1'}) and \
                mh.mem_read({'addr': 'ph1', 'val': 'ph2', 'segment': 'ph3', 'size': 'size'}) and \
                mh.store(0):
            self.segment = mh.get_ph('ph3')
            self.opsize = mh.get_ph('size')
            return True
        return False

    def get_instr(self, vmstate: VMState):
        i = VMIns()
        i.haddr = self.address
        i.id = VM_INS_LDR
        i.address = vmstate.ip-vmstate.config.dir*4
        i.mne = 'load'
        s = size2name(self.opsize)
        if self.segment == X86_REG_INVALID:
            i.opstr = s+' '+bridge.reg_name(X86_REG_DS)
        else:
            i.opstr = s+' '+bridge.reg_name(self.segment)
        i.data = self.segment
        i.opsize = self.opsize
        return i

    def generator(self, ins: VMIns, block: vtil.basic_block):
        t0, t1 = block.tmp(vtil.arch.bit_count, ins.opsize*8)
        block.pop(t0)
        if self.segment == X86_REG_GS:
            block.vemits("mov rax, gs:0x30")
            block.vpinw(ZAX)
            block.add(t0, ZAX)
        elif self.segment == X86_REG_FS:
            block.vemits("mov eax, fs:0x18")
            block.vpinw(ZAX)
            block.add(t0, ZAX)
        block.ldd(t1, t0, 0)
        block.push(t1)


class VMShift(VMBase):
    # X86_INS_RCL, X86_INS_RCR, X86_INS_ROL, X86_INS_ROR,
    # X86_INS_SAL, X86_INS_SAR, X86_INS_SHL, X86_INS_SHR
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = 'vmp_shift'
        self.ins = X86_INS_INVALID

    def match(self):
        if len(self.body) < 5:
            return False
        mh = MatchHelper(self.body, self.config)
        shi = [X86_INS_RCL, X86_INS_RCR, X86_INS_ROL, X86_INS_ROR,
               X86_INS_SAL, X86_INS_SAR, X86_INS_SHL, X86_INS_SHR]
        args = {}
        if mh.load(0, {'reg': 'ph1', 'size': 'size'}) and \
                mh.load_byte(align_size(mh.get_ph('size')), {'reg': 'p2'}) and\
                mh.among(shi, {'ins': 'ph3'}) and\
                mh.store(bridge.size, {'reg': 'ph1'}) and\
                mh.store_eflags():
            self.ins = mh.get_ph('ph3')
            self.opsize = mh.get_ph('size')
            return True
        return False

    def get_instr(self, vmstate: VMState):
        m = {
            X86_INS_RCL: VM_INS_RCL,
            X86_INS_RCR: VM_INS_RCR,
            X86_INS_ROL: VM_INS_ROL,
            X86_INS_ROR: VM_INS_ROR,
            X86_INS_SAL: VM_INS_SAL,
            X86_INS_SAR: VM_INS_SAR,
            X86_INS_SHL: VM_INS_SHL,
            X86_INS_SHR: VM_INS_SHR
        }
        i2n = {
            VM_INS_RCL: 'rcl',
            VM_INS_RCR: 'rcr',
            VM_INS_ROL: 'rol',
            VM_INS_ROR: 'ror',
            VM_INS_SAL: 'sal',
            VM_INS_SAR: 'sar',
            VM_INS_SHL: 'shl',
            VM_INS_SHR: 'shr',
        }
        i = VMIns()
        i.haddr = self.address
        i.id = m[self.ins]
        i.address = vmstate.ip-vmstate.config.dir*4
        i.mne = '{}{}'.format(i2n[i.id], self.opsize)
        i.data = 0
        i.opsize = self.opsize
        return i

    def generator(self, ins: VMIns, block: vtil.basic_block):
        t0, t1, t2 = block.tmp(ins.opsize*8, ins.opsize*8, 8)
        cf = t1.select(1, t1.bit_count - 1)
        ofx = t0.select(1, t0.bit_count - 1)

        block.pop(t0)
        block.pop(t2)
        block.mov(t1, t0)
        if self.ins == X86_INS_SHL:
            block.bshl(t0, t2)
        elif self.ins == X86_INS_SHR:
            block.bshr(t0, t2)
        elif self.ins == X86_INS_ROL:
            block.brol(t0, t2)
        elif self.ins == X86_INS_ROR:
            block.bror(t0, t2)
        else:
            assert False
        block.tl(FLAG_SF, t0, 0)
        block.te(FLAG_ZF, t0, 0)
        block.mov(FLAG_OF, ofx)
        block.mov(FLAG_CF, cf)
        block.bxor(FLAG_OF, cf)
        block.push(t0)
        block.pushf()


class VMShld(VMBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = 'vmp_shld'

    def match(self):
        if len(self.body) < 7:
            return False
        args = {}
        mh = MatchHelper(self.body, self.config)
        mh.reset()
        if (mh.load(0, {'reg': 'ph1', 'size': 'size'}) and
            mh.load(mh.get_ph('size'), {'reg': 'ph2'}) and
                mh.load_byte(mh.get_ph('size')*2, {'reg': 'ph3'}) and
                mh.batch([X86_INS_SHLD]) and
                mh.store(bridge.size, {'reg': 'ph1'}) and
                mh.store_eflags()):
            self.opsize = mh.get_ph('size')
            return True
        return False

    def get_instr(self, vmstate: VMState):
        i = VMIns()
        i.haddr = self.address
        i.id = VM_INS_SHLD
        i.address = vmstate.ip-vmstate.config.dir*4
        i.mne = 'shld{}'.format(self.opsize)
        i.data = 0
        i.opsize = self.opsize
        return i

    def generator(self, ins: VMIns, block: vtil.basic_block):
        t0, t1, t2, t3 = block.tmp(ins.opsize*8, ins.opsize*8, 8, 8)

        block.pop(t0)
        block.pop(t1)
        block.pop(t2)

        block.bshl(t0, t2)

        block.mov(t3, vtil.make_uint(ins.opsize*8, 8))
        block.sub(t3, t2)

        block.bshr(t1, t3)

        block.bor(t0, t1)

        block.tl(FLAG_SF, t0, 0)
        block.te(FLAG_ZF, t0, 0)
        block.mov(FLAG_OF, vtil.UNDEFINED)
        block.mov(FLAG_CF, vtil.UNDEFINED)
        block.push(t0)
        block.pushf()


class VMShrd(VMBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = 'vmp_shrd'

    def match(self):
        if len(self.body) < 7:
            return False
        args = {}
        mh = MatchHelper(self.body, self.config)
        mh.reset()
        if (mh.load(0, {'reg': 'ph1', 'size': 'size'}) and
            mh.load(mh.get_ph('size'), {'reg': 'ph2'}) and
                mh.load_byte(mh.get_ph('size')*2, {'reg': 'ph3'}) and
                mh.batch([X86_INS_SHRD]) and
                mh.store(bridge.size, {'reg': 'ph1'}) and
                mh.store_eflags()):
            self.opsize = mh.get_ph('size')
            return True
        return False

    def get_instr(self, vmstate: VMState):
        i = VMIns()
        i.haddr = self.address
        i.id = VM_INS_SHRD
        i.address = vmstate.ip-vmstate.config.dir*4
        i.mne = 'shrd{}'.format(self.opsize)
        i.data = 0
        i.opsize = self.opsize
        return i

    def generator(self, ins: VMIns, block: vtil.basic_block):
        t0, t1, t2, t3 = block.tmp(ins.opsize*8, ins.opsize*8, 8, 8)

        block.pop(t0)
        block.pop(t1)
        block.pop(t2)

        block.bshr(t0, t2)

        block.mov(t3, vtil.make_uint(ins.opsize*8, 8))
        block.sub(t3, t2)

        block.bshl(t1, t3)

        block.bor(t0, t1)

        block.tl(FLAG_SF, t0, 0)
        block.te(FLAG_ZF, t0, 0)
        block.mov(FLAG_OF, vtil.UNDEFINED)
        block.mov(FLAG_CF, vtil.UNDEFINED)
        block.push(t0)
        block.pushf()


class VMMul(VMBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = 'vmp_mul'

    def match(self):
        if len(self.body) < 7:
            return False
        args = {}
        mh = MatchHelper(self.body, self.config)
        if (mh.load_byte(2, {'reg': 'ph1'}) and
            mh.load_byte(0, {'reg': 'ph2'}) and
                mh.batch([X86_INS_MUL]) and
                mh.store_word(bridge.size, {'reg': 'ph1'}) and
                mh.store_eflags()):
            self.opsize = 1
            return True
        mh.reset()
        if (mh.load(None, {'reg': 'ph1', 'size': 'size1'}) and
                mh.load(0, {'reg': 'ph2', 'size': 'size1'}) and
                mh.batch([X86_INS_MUL]) and
                mh.store(bridge.size, {'reg': 'ph2'}) and
                mh.store(bridge.size+mh.get_ph('size1'), {'reg': 'ph1'}) and
                mh.store_eflags()):
            self.opsize = mh.get_ph('size1')
            return True
        return False

    def get_instr(self, vmstate: VMState):
        i = VMIns()
        i.haddr = self.address
        i.id = VM_INS_MUL
        i.address = vmstate.ip-vmstate.config.dir*4
        i.mne = 'mul{}'.format(self.opsize)
        i.data = 0
        i.opsize = self.opsize
        return i

    def generator(self, ins: VMIns, block: vtil.basic_block):
        a0, a1, d = block.tmp(ins.opsize*8, ins.opsize*8, ins.opsize*8)
        if ins.opsize == 1:
            a2 = block.tmp(16)
            block.pop(d)
            block.pop(a0)
            block.mov(a2, a0)

            block.mul(a2, d)

            block.push(a2)
            block.pushf()
        else:
            block.pop(d)
            block.pop(a0)
            block.mov(a1, a0)

            block.mul(a0, d)
            block.mulhi(a1, d)

            block.push(a0)
            block.push(a1)
            block.pushf()


class VMImul(VMBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = 'vmp_imul'

    def match(self):
        if len(self.body) < 6:
            return False
        args = {}
        mh = MatchHelper(self.body, self.config)
        mh.reset()
        if (mh.load_byte(2, {'reg': 'ph1'}) and
            mh.load_byte(0, {'reg': 'ph2'}) and
                mh.batch([X86_INS_IMUL]) and
                mh.store_word(bridge.size, {'reg': 'ph1'}) and
                mh.store_eflags()):
            self.opsize = 1
            return True
        mh.reset()
        if (mh.load(None, {'reg': 'ph1', 'size': 'size1'}) and
                mh.load(0, {'reg': 'ph2', 'size': 'size1'}) and
                mh.batch([X86_INS_IMUL]) and
                mh.store(bridge.size, {'reg': 'ph2'}) and
                mh.store(bridge.size+mh.get_ph('size1'), {'reg': 'ph1'}) and
                mh.store_eflags()):
            self.opsize = mh.get_ph('size1')
            return True
        return False

    def get_instr(self, vmstate: VMState):
        i = VMIns()
        i.haddr = self.address
        i.id = VM_INS_IMUL
        i.address = vmstate.ip-vmstate.config.dir*4
        i.mne = 'imul{}'.format(self.opsize)
        i.data = 0
        i.opsize = self.opsize
        return i

    def generator(self, ins: VMIns, block: vtil.basic_block):
        a0, a1, d = block.tmp(ins.opsize*8, ins.opsize*8, ins.opsize*8)
        if ins.opsize == 1:
            a2, a3 = block.tmp(16, 16)
            block.pop(d)
            block.pop(a0)
            block.movsx(a2, a0)
            block.movsx(a3, d)

            block.imul(a2, a3)

            block.mov(FLAG_SF, vtil.UNDEFINED)
            block.mov(FLAG_ZF, vtil.UNDEFINED)
            block.mov(FLAG_OF, vtil.UNDEFINED)
            block.mov(FLAG_CF, vtil.UNDEFINED)

            block.push(a2)
            block.pushf()
        else:
            block.pop(d)
            block.pop(a0)
            block.mov(a1, a0)

            block.imul(a0, d)
            block.imulhi(a1, d)

            block.mov(FLAG_SF, vtil.UNDEFINED)
            block.mov(FLAG_ZF, vtil.UNDEFINED)
            block.mov(FLAG_OF, vtil.UNDEFINED)
            block.mov(FLAG_CF, vtil.UNDEFINED)

            block.push(a0)
            block.push(a1)
            block.pushf()


class VMDiv(VMBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = 'vmp_div'

    def match(self):
        if len(self.body) < 7:
            return False
        args = {}
        mh = MatchHelper(self.body, self.config)
        mh.reset()
        if (mh.load_byte(0, {'reg': 'ph1'}) and
            mh.load_byte(2, {'reg': 'ph2'}) and
                mh.batch([X86_INS_DIV]) and
                mh.store_word(bridge.size, {'reg': 'ph1'}) and
                mh.store_eflags()):
            self.opsize = 1
            return True
        mh.reset()
        if (mh.load(None, {'reg': 'ph1', 'size': 'size'}) and
            mh.load(0, {'reg': 'ph2'}) and
            mh.load(None, {'reg': 'ph3'}) and
                mh.batch([X86_INS_DIV]) and
                mh.store(bridge.size, {'reg': 'ph2'}) and
                mh.store(bridge.size+mh.get_ph('size'), {'reg': 'ph1'}) and
                mh.store_eflags()):
            self.opsize = mh.get_ph('size')
            return True
        return False

    def get_instr(self, vmstate: VMState):
        i = VMIns()
        i.haddr = self.address
        i.id = VM_INS_DIV
        i.address = vmstate.ip-vmstate.config.dir*4
        i.mne = 'div{}'.format(self.opsize)
        i.data = 0
        i.opsize = self.opsize
        return i

    def generator(self, ins: VMIns, block: vtil.basic_block):
        a0, a1, d, c = block.tmp(
            ins.opsize*8, ins.opsize*8, ins.opsize*8, ins.opsize*8)
        if ins.opsize == 1:
            ax0 = block.tmp(16)
            block.pop(a0)
            block.pop(c)
            block.mov(a1, a0)

            block.div(a0, 0, c)
            block.rem(a1, 0, c)

            block.mov(ax0, a1)
            block.bshl(ax0, 8)
            block.bor(ax0, a0)

            block.push(ax0)
            block.pushf()
        else:
            block.pop(d)
            block.pop(a0)
            block.pop(c)
            block.mov(a1, a0)

            block.div(a0, d, c)
            block.rem(a1, d, c)

            block.push(a0)
            block.push(a1)
            block.pushf()


class VMIdiv(VMBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = 'vmp_idiv'

    def match(self):
        if len(self.body) < 7:
            return False
        args = {}
        mh = MatchHelper(self.body, self.config)
        mh.reset()
        if (mh.load_byte(0, {'reg': 'ph1'}) and
            mh.load_byte(2, {'reg': 'ph2'}) and
                mh.batch([X86_INS_IDIV]) and
                mh.store_word(bridge.size, {'reg': 'ph1'}) and
                mh.store_eflags()):
            self.opsize = 1
            return True
        mh.reset()
        if (mh.load(None, {'reg': 'ph1', 'size': 'size'}) and
            mh.load(0, {'reg': 'ph2'}) and
            mh.load(None, {'reg': 'ph3'}) and
                mh.batch([X86_INS_IDIV]) and
                mh.store(bridge.size, {'reg': 'ph2'}) and
                mh.store(bridge.size+mh.get_ph('size'), {'reg': 'ph1'}) and
                mh.store_eflags()):
            self.opsize = mh.get_ph('size')
            return True
        return False

    def get_instr(self, vmstate: VMState):
        i = VMIns()
        i.haddr = self.address
        i.id = VM_INS_IDIV
        i.address = vmstate.ip-vmstate.config.dir*4
        i.mne = 'idiv{}'.format(self.opsize)
        i.data = 0
        i.opsize = self.opsize
        return i

    def generator(self, ins: VMIns, block: vtil.basic_block):
        a0, a1, d, c = block.tmp(
            ins.opsize*8, ins.opsize*8, ins.opsize*8, ins.opsize*8)
        if ins.opsize == 1:
            ax0 = block.tmp(16)
            block.pop(a0)
            block.pop(c)
            block.mov(a1, a0)

            block.idiv(a0, 0, c)
            block.irem(a1, 0, c)

            block.mov(ax0, a1)
            block.bshl(ax0, 8)
            block.bor(ax0, a0)

            block.push(ax0)
            block.pushf()
        else:
            block.pop(d)
            block.pop(a0)
            block.pop(c)
            block.mov(a1, a0)

            block.idiv(a0, d, c)
            block.irem(a1, d, c)

            block.push(a0)
            block.push(a1)
            block.pushf()


class VMRdtsc(VMBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = 'vmp_rdtsc'

    def match(self):
        if len(self.body) < 3:
            return False
        args = {}
        mh = MatchHelper(self.body, self.config)
        mh.reset()
        if (mh.batch([X86_INS_RDTSC]) and
            mh.store_dword(0, {'reg': X86_REG_EDX}) and
                mh.store_dword(4, {'reg': X86_REG_EAX})):
            return True
        return False

    def get_instr(self, vmstate: VMState):
        i = VMIns()
        i.haddr = self.address
        i.id = VM_INS_RDTSC
        i.address = vmstate.ip-vmstate.config.dir*4
        i.mne = 'rdtsc'
        i.data = 0
        i.opsize = self.opsize
        return i

    def generator(self, ins: VMIns, block: vtil.basic_block):
        block.vemits('rdtsc')
        block.vpinw(ZDX)
        block.vpinw(ZAX)

        block.push(vtil.x86_reg.EAX)
        block.push(vtil.x86_reg.EDX)


class VMCpuid(VMBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = 'vmp_cpuid'

    def match(self):
        if len(self.body) < 6:
            return False
        args = {}
        mh = MatchHelper(self.body, self.config)
        if (mh.load_dword(0, {'reg': 'ph1'}) and
            mh.batch([X86_INS_CPUID]) and
            mh.store_dword(12) and
                mh.store_dword(8) and
                mh.store_dword(4) and
                mh.store_dword(0)):
            return True
        return False

    def get_instr(self, vmstate: VMState):
        i = VMIns()
        i.haddr = self.address
        i.id = VM_INS_CPUID
        i.address = vmstate.ip-vmstate.config.dir*4
        i.mne = 'cpuid'
        i.data = 0
        i.opsize = self.opsize
        return i

    def generator(self, ins: VMIns, block: vtil.basic_block):
        block.vpinr(ZCX)
        block.vpinr(ZAX)
        block.vemits('cpuid')
        block.vpinw(ZDX)
        block.vpinw(ZCX)
        block.vpinw(ZBX)
        block.vpinw(ZAX)

        block.push(vtil.x86_reg.EAX)
        block.push(vtil.x86_reg.EBX)
        block.push(vtil.x86_reg.ECX)
        block.push(vtil.x86_reg.EDX)


class VMLockExchange(VMBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = 'vmp_lock_xchg'

    def match(self):
        if len(self.body) > 5:
            return False

        def is_lock_xchg(insn: CsInsn):
            if insn.id != X86_INS_XCHG:
                return False
            if X86_PREFIX_LOCK not in insn.prefix:
                return False
            op1, op2 = insn.operands
            if op1.type == X86_OP_MEM and op2.type == X86_OP_REG:
                self.opsize = op1.size
                return True
            return False
        args = {}
        mh = MatchHelper(self.body, self.config)
        if (mh.load(0, {'reg': 'ph1'}) and
                mh.load(bridge.size, {'reg': 'ph2'}) and
                mh.match_for(is_lock_xchg) and 
                mh.store(0)):
            return True
        return False

    def get_instr(self, vmstate: VMState):
        i = VMIns()
        i.haddr = self.address
        i.id = VM_INS_LOCK_XCHG
        i.address = vmstate.ip-vmstate.config.dir*4
        i.mne = 'lock_xchg'
        i.data = 0
        i.opsize = self.opsize
        return i

    def generator(self, ins: VMIns, block: vtil.basic_block):
        table = {1: (X86_REG_AL, 'byte'),
                 2: (X86_REG_AX, 'word'),
                 4: (X86_REG_EAX, 'dword'),
                 8: (X86_REG_RAX, 'qword')}
        reg, str_type = table[self.opsize]
        # vr = remap(ZAX, opsize)
        vr = vtil.x86_reg(reg)
        block.pop(ZDX)
        block.pop(vr)
        block.vpinr(ZDX)
        block.vpinr(ZAX)
        block.vemits(
            f'lock xchg {str_type} ptr [{bridge.reg_name(ZDX)}], {bridge.reg_name(reg)}')
        block.vpinw(ZAX)

        block.push(vr)


class VMPushCRX(VMBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = 'vmp_push_crx'
        self.cr = X86_REG_INVALID

    def match(self):
        if len(self.body) > 4:
            return False
        mh = MatchHelper(self.body, self.config)
        for cr in [X86_REG_CR0, X86_REG_CR2, X86_REG_CR3, X86_REG_CR4, X86_REG_CR8]:
            mh.reset()
            if mh.match(X86_INS_MOV, [X86_OP_REG, X86_OP_REG], [None, cr]) and mh.store(0):
                self.cr = cr
                self.name = f'vmp_push_{bridge.reg_name(self.cr)}'
                return True
        return False

    def get_instr(self, vmstate: VMState):
        i = VMIns()
        i.haddr = self.address
        i.id = VM_INS_PUSH_CRX
        i.address = vmstate.ip-vmstate.config.dir*4
        i.mne = f'push_{bridge.reg_name(self.cr)}'
        i.opstr = ''
        i.data = 0
        i.opsize = self.opsize
        return i

    def generator(self, ins: VMIns, block: vtil.basic_block):
        block.vemits(f'mov {bridge.reg_name(ZAX)}, {bridge.reg_name(self.cr)}')
        block.vpinw(ZAX)
        block.push(ZAX)


class VMPopCRX(VMBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = 'vmp_pop_crx'
        self.cr = X86_REG_INVALID

    def match(self):
        if len(self.body) > 4:
            return False
        mh = MatchHelper(self.body, self.config)
        for cr in [X86_REG_CR0, X86_REG_CR2, X86_REG_CR3, X86_REG_CR4, X86_REG_CR8]:
            mh.reset()
            if mh.load(0) and mh.match(X86_INS_MOV, [X86_OP_REG, X86_OP_REG], [cr, None]):
                self.cr = cr
                self.name = f'vmp_pop_{bridge.reg_name(self.cr)}'
                return True
        return False

    def get_instr(self, vmstate: VMState):
        i = VMIns()
        i.haddr = self.address
        i.id = VM_INS_POP_CRX
        i.address = vmstate.ip-vmstate.config.dir*4
        i.mne = f'pop_{bridge.reg_name(self.cr)}'
        i.opstr = ''
        i.data = 0
        i.opsize = self.opsize
        return i

    def generator(self, ins: VMIns, block: vtil.basic_block):
        block.pop(ZAX)
        block.vpinr(ZAX)
        block.vemits(f'mov {bridge.reg_name(self.cr)}, {bridge.reg_name(ZAX)}')


class VMPushSP(VMBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = 'vmp_push_sp'

    def match(self):
        if len(self.body) > 4:
            return False
        mh = MatchHelper(self.body, self.config)
        a = {}
        if mh.get_sp({'reg': 'ph1'}) and mh.store(0, a):
            self.opsize = a['size']
            return True
        return False

    def get_instr(self, vmstate: VMState):
        i = VMIns()
        i.haddr = self.address
        i.id = VM_INS_PUSH_SP
        i.address = vmstate.ip-vmstate.config.dir*4
        i.mne = 'push_sp{}'.format(self.opsize)
        i.opstr = ''
        i.data = 0
        i.opsize = self.opsize
        return i

    def generator(self, ins: VMIns, block: vtil.basic_block):
        if ins.opsize == vtil.arch.size:
            block.push(vtil.REG_SP)
        else:
            t0 = block.tmp(ins.opsize*8)
            block.mov(t0, vtil.REG_SP)
            block.push(t0)


class VMPopSP(VMBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = 'vmp_pop_sp'

    def match(self):
        if len(self.body) != 1:
            return False
        mh = MatchHelper(self.body, self.config)
        if mh.load(0, {'reg': 'ph1', 'size': 'size'}) and mh.get_ph('ph1') == self.config.reg_sp:
            self.opsize = mh.get_ph('size')
            return True
        return False

    def get_instr(self, vmstate: VMState):
        i = VMIns()
        i.haddr = self.address
        i.id = VM_INS_POP_SP
        i.address = vmstate.ip-vmstate.config.dir*4
        i.mne = 'pop_sp{}'.format(self.opsize)
        i.opstr = ''
        i.data = 0
        i.opsize = self.opsize
        return i

    def generator(self, ins: VMIns, block: vtil.basic_block):
        block.pop(vtil.REG_SP)


class VMPopFlag(VMBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = 'vmp_pop_flag'

    def match(self):
        if len(self.body) != 3:
            return False
        mh = MatchHelper(self.body, self.config)
        if (mh.match(X86_INS_PUSH, [X86_OP_MEM], [{'base': self.config.reg_sp}]) and
                mh.among([X86_INS_POPFD, X86_INS_POPFQ])):
            self.opsize = bridge.size
            return True
        return False

    def get_instr(self, vmstate: VMState):
        i = VMIns()
        i.haddr = self.address
        i.id = VM_INS_POP_EFLAGS
        i.address = vmstate.ip-vmstate.config.dir*4
        i.mne = 'pop_flag{}'.format(self.opsize)
        i.opstr = ''
        i.data = 0
        i.opsize = self.opsize
        return i

    def generator(self, ins: VMIns, block: vtil.basic_block):
        assert ins.opsize == vtil.arch.size
        block.popf()


def feeling_good(insns_connect):
    """
    dir
    reg_base
    reg_key
    reg_ip
    """
    reg_off = X86_REG_INVALID
    config = VMConfig()
    config.dir = 1
    config.reg_base = get_regbase(insns_connect)
    for insn in reversed(insns_connect):
        # find add edi(base), edx(off)
        if (reg_off == X86_REG_INVALID and instr_match(insn, X86_INS_ADD, [X86_OP_REG, X86_OP_REG], [config.reg_base])):
            op1, op2 = insn.operands
            reg_off = op2.reg
        if reg_off == X86_REG_INVALID:
            continue
        # xor r(off), r(key)
        if instr_match(insn, X86_INS_XOR, [X86_OP_REG, X86_OP_REG], [get_reg32(reg_off), None]):
            op1, op2 = insn.operands
            config.reg_key = op2.reg
            if bridge.is64bit():
                config.reg_key = get_reg64(config.reg_key)
            break

    config.dir = 1
    # get reg_ip
    for insn in insns_connect[:3]:
        r, imm = crease_match(insn)
        if r != X86_REG_INVALID and imm == -4:
            config.dir = -1
        # mov edx(off), dword ptr [ip] ;
        if instr_match(insn, X86_INS_MOV, [X86_OP_REG, X86_OP_MEM], [get_reg32(reg_off), {'disp': 0, 'index': X86_REG_INVALID, 'scale': 1}]):
            config.reg_ip = insn.operands[1].mem.base
            return config

    return None


class VMInit(VMBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = "vmp_init"

    def parse_vminit(self):
        self.config = feeling_good(self.connect)
        i_save_regs = 0
        i_decode_ip = -1
        i_set_sp = -1
        i_set_vregs = -1
        i_set_hbase = -1
        self.config.rebase = -1
        for i, v in enumerate(self.body):
            if self.config.rebase == -1 and i_decode_ip == -1:
                if instr_match(v, [X86_INS_MOV, X86_INS_MOVABS], [X86_OP_REG, X86_OP_IMM]):
                    op1, op2 = v.operands
                    self.config.rebase = op2.imm
            # mov {vIP}, dword ptr [esp + 0x28] ; decode vIP
            if instr_match(v, X86_INS_MOV, [X86_OP_REG, X86_OP_MEM]):
                op1, op2 = v.operands
                if op1.reg == self.config.reg_ip:
                    i_decode_ip = i
            if instr_match(v, X86_INS_MOV, [X86_OP_REG, X86_OP_REG]):
                op1, op2 = v.operands
                # mov {vESP}, esp ;
                if op2.reg in [X86_REG_ESP, X86_REG_RSP]:
                    self.config.reg_sp = op1.reg
                    i_set_sp = i
                # mov ebx, {vIP}; set key
                if op1.reg == self.config.reg_key and op2.reg == self.config.reg_ip:
                    i_set_key = i
            # sub esp({vRegs}), 0xc0
            if instr_match(v, X86_INS_LEA, [X86_OP_REG, X86_OP_MEM]):
                # lea esp({vRegs}), [esp - 0xc0]
                op1, op2 = v.operands
                # if op1.reg == self.config.reg_regs:
                #     i_set_vregs = i
                # lea ebp, [L_SetHBase]
                if op1.reg == self.config.reg_base:
                    i_set_hbase = i
                    i_connect = i+1
                    if bridge.is64bit() and op2.mem.base == X86_REG_RIP:
                        # x64 <CsInsn :lea rbx, [rip - 7]>
                        self.hbase = v.address + v.size + op2.mem.disp
                        pass
                    else:
                        self.hbase = op2.mem.disp
        assert(i_decode_ip != -1 and i_set_sp != -1)
        # parse push list
        m = {}
        self.save_regs = self.body[i_save_regs:i_decode_ip]
        self.pushs = []
        for insn in self.save_regs:
            if instr_match(insn, [X86_INS_MOV, X86_INS_MOVABS], [X86_OP_REG, X86_OP_IMM]):
                m[insn.operands[0].reg] = (X86_OP_IMM, insn.operands[1].imm)
            if instr_match(insn, X86_INS_PUSH, [X86_OP_REG]):
                if insn.operands[0].reg in m:
                    self.pushs.append(m[insn.operands[0].reg])
                else:
                    self.pushs.append((X86_OP_REG, insn.operands[0].reg))
            if insn.id in [X86_INS_PUSHFD, X86_INS_PUSHFQ]:
                self.pushs.append((X86_OP_REG, X86_REG_EFLAGS))
        self.conn_config = self.config
        self.ip_decoder = self.body[i_decode_ip+1:i_set_sp]
        return True

    def decode_ip(self, ct, vmstate: VMState):
        v = vmstate.decode_emu(self.ip_decoder, ct,
                               get_reg32(self.config.reg_ip), 4)
        # FIXME! hardcodes
        if bridge.is64bit():
            v += 0x100000000
            v += vmstate.config.rebase
        return v

    def match(self):
        return True


class VMExit(VMBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = "vmp_exit"
        self.pops = []
        return

    def match(self):
        if not instr_match(self.body[-1], X86_INS_RET):
            return False

        for insn in self.body:
            if instr_match(insn, X86_INS_POP, [X86_OP_REG]):
                self.pops.append(insn.operands[0].reg)
            elif insn.id in [X86_INS_POPFD, X86_INS_POPFQ]:
                self.pops.append(X86_REG_EFLAGS)

        if len(self.pops) >= 7:
            return True

        # x64
        # pop 15 times + popfq
        return False

    def get_instr(self, vmstate):
        i = VMIns()
        i.haddr = self.address
        i.id = VM_INS_EXIT
        i.address = vmstate.ip-vmstate.config.dir*4
        i.mne = 'exit'
        i.opstr = ''
        i.data = 0
        i.opsize = self.opsize
        return i

    def generator(self, ins: VMIns, block: vtil.basic_block):
        pass


class VMUnknown(VMBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = "vmp_unknown"

    def calc_bytecode_size(self):
        n = 0
        for insn in self.body:
            insn: CsInsn
            regs_read, regs_write = insn.regs_access()
            if self.config.reg_ip in regs_write:
                # lea vm_ip, [vm_ip+disp]
                if instr_match(insn, X86_INS_LEA, [X86_OP_REG, X86_OP_MEM], [self.config.reg_ip, {'base': self.config.reg_ip, 'index': X86_REG_INVALID, 'scale': 1}]):
                    n += insn.operands[1].mem.disp
                # add vm_ip, imm
                elif instr_match(insn, X86_INS_ADD, [X86_OP_REG, X86_OP_IMM], [self.config.reg_ip]):
                    n += insn.operands[1].imm
                # sub vm_ip, imm
                elif instr_match(insn, X86_INS_SUB, [X86_OP_REG, X86_OP_IMM], [self.config.reg_ip]):
                    n -= insn.operands[1].imm
                elif instr_match(insn, X86_INS_LODSD):
                    n += 4
                elif instr_match(insn, X86_INS_LODSQ):
                    n += 8
                # mov vm_ip, vm_ip
                elif instr_match(insn, X86_INS_MOV, [X86_OP_REG, X86_OP_REG], [self.config.reg_ip, self.config.reg_ip]):
                    n += 0
                else:
                    print(self.config)
                    dump_insns(self.body)
                    raise NotImplementedError('calc_bytecode_size'+str(insn))
        return abs(n)

    def match(self):
        self.bytecode_size = self.calc_bytecode_size()
        if self.bytecode_size != 0:
            mh = MatchHelper(self.body, self.config)
            args = {}
            if not mh.decode(args):
                return False
            self.decoder = args['decoder']
            self.reg = args['reg']
        return True

    def get_instr(self, vmstate):
        i = VMIns()
        i.haddr = self.address
        i.id = VM_INS_UNKNOWN
        i.address = vmstate.ip-vmstate.config.dir*4
        bytecode = 0
        if self.bytecode_size:
            bytecode = vmstate.decode_emu(self.decoder, vmstate.fetch(
                self.bytecode_size), self.reg, self.bytecode_size)

        i.mne = 'unknown'
        i.opstr = '{}'.format(bytecode)
        i.data = bytecode
        i.opsize = self.bytecode_size
        return i


class VMInvalid(VMBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = 'vmp_invalid'

    def match(self):
        return True

    def get_instr(self, vmstate):
        i = VMIns()
        i.haddr = self.address
        i.id = VM_INS_INVALID
        i.address = vmstate.ip-vmstate.config.dir*4
        i.mne = 'invalid'
        i.opstr = ''
        i.data = 0
        i.opsize = self.opsize
        return i


def vmentry_parse(addr):
    # [unimpl insn]
    # push <imm>
    # call <vm_init>
    insn_x = x86_simple_decode(addr, 5, True)
    if len(insn_x) < 2:
        return (None, None, insn_x)
    if (instr_match(insn_x[-2], X86_INS_PUSH, {X86_OP_IMM}) and
            instr_match(insn_x[-1], X86_INS_CALL, {X86_OP_IMM})):
        vm_imm = insn_x[-2].operands[0].imm
        vm_init = insn_x[-1].operands[0].imm
        h = factory(vm_init, None)
        if h and isinstance(h, VMInit):
            mask = get_mask(bridge.size*8)
            vmstate = VMState()
            vmstate.config = h.config
            vmstate.ip = h.decode_ip(vm_imm, vmstate)
            vmstate.key = (vmstate.ip-vmstate.config.rebase) & mask
            # vmstate.base = h.get_next()
            return (vmstate, h, insn_x)
    return (None, None, insn_x)


class VMJmp(VMBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = 'vmp_jmp'

    def simple_parse(self):
        # breakpoint()
        self.conn_config = feeling_good(self.connect)
        self.conn_config.rebase = self.config.rebase
        if bridge.is64bit():
            new_sp = [self.config.reg_sp]
            for insn in self.body:
                if instr_match(insn, X86_INS_XCHG, [X86_OP_REG, X86_OP_REG]):
                    op1, op2 = insn.operands
                    if op1.reg in new_sp:
                        new_sp.remove(op1.reg)
                        new_sp.append(op2.reg)
                    if op2.reg in new_sp:
                        new_sp.remove(op2.reg)
                        new_sp.append(op1.reg)
                elif instr_match(insn, X86_INS_MOV, [X86_OP_REG, X86_OP_REG]):
                    op1, op2 = insn.operands
                    if op1.reg != op2.reg and op2.reg in new_sp:
                        new_sp.append(op1.reg)
            assert new_sp
            if len(new_sp) > 1:
                print(f'warning! new_sp -> {new_sp} too much')
            self.conn_config.reg_sp = new_sp[-1]
        else:
            # 32 only
            self.conn_config.reg_sp = X86_REG_EBP ^ X86_REG_EDI ^ X86_REG_ESI ^ self.conn_config.reg_ip ^ self.conn_config.reg_base

    def match(self):
        matched = False
        reg_newip = X86_REG_INVALID
        self.simple_parse()
        for insn in self.body:
            if reg_newip == X86_REG_INVALID:
                # mov conn_config.reg_ip, reg
                if instr_match(insn, X86_INS_MOV, [X86_OP_REG, X86_OP_MEM], [None, {'base': self.config.reg_sp, 'disp': 0, 'index': X86_REG_INVALID, 'scale': 1}]):
                    reg_newip = insn.operands[0].reg
                    if reg_newip == self.conn_config.reg_ip:
                        matched = True
            elif instr_match(insn, X86_INS_MOV, [X86_OP_REG, X86_OP_REG], [self.conn_config.reg_ip, reg_newip]):
                matched = True
            elif instr_match(insn, X86_INS_XCHG, [X86_OP_REG, X86_OP_REG], [reg_newip, self.conn_config.reg_ip]):
                matched = True
            if self.conn_config.reg_sp:
                if instr_match(insn, X86_INS_XCHG, [X86_OP_REG, X86_OP_REG], [reg_newip, self.conn_config.reg_ip]):
                    pass
            if matched:
                if bridge.is64bit():
                    # lea base, [imm]
                    if instr_match(insn, X86_INS_LEA, [X86_OP_REG, X86_OP_MEM], [self.conn_config.reg_base, {'base': X86_REG_RIP, 'index': X86_REG_INVALID, 'scale': 1, 'disp': -7}]):
                        self.hbase = insn.address
                        return True
                else:
                    # lea base, [imm]
                    if instr_match(insn, X86_INS_LEA, [X86_OP_REG, X86_OP_MEM], [self.conn_config.reg_base, {'base': X86_REG_INVALID, 'index': X86_REG_INVALID, 'scale': 1}]):
                        self.hbase = insn.operands[1].mem.disp
                        return True
        return False

    def get_instr(self, vmstate):
        i = VMIns()
        i.haddr = self.address
        i.id = VM_INS_JMP
        i.address = vmstate.ip-vmstate.config.dir*4
        i.mne = 'jmp'
        i.opstr = ''
        i.data = 0
        i.opsize = 0
        return i

    def generator(self, ins: VMIns, block: vtil.basic_block):
        pass
        # t0 = block.tmp(vtil.arch.bit_count)
        # block.pop(t0)
        # block.jmp(t0)


def crease_match(insn, reg=None):
    # add r, i
    if instr_match(insn, X86_INS_ADD, [X86_OP_REG, X86_OP_IMM], [reg]):
        return (insn.operands[0].reg, insn.operands[1].imm)
    # lea r, [r + i]
    if instr_match(insn, X86_INS_LEA, [X86_OP_REG, X86_OP_MEM], [reg, {'base': reg, 'index': X86_REG_INVALID, 'scale': 1}]):
        if insn.operands[0].reg == insn.operands[1].mem.base:
            return (insn.operands[0].reg, insn.operands[1].mem.disp)
    # sub r, i
    if instr_match(insn, X86_INS_SUB, [X86_OP_REG, X86_OP_IMM], [reg]):
        return (insn.operands[0].reg, -insn.operands[1].imm)
    return (X86_REG_INVALID, 0)


def get_regbase(insns):
    if instr_match(insns[-1], X86_INS_JMP, [X86_OP_REG]):
        return insns[-1].operands[0].reg
    elif (instr_match(insns[-1], X86_INS_RET) and
            instr_match(insns[-2], X86_INS_PUSH, [X86_OP_REG])):
        return insns[-2].operands[0].reg
    return X86_REG_INVALID


def get_splitline(insns):
    reg_off = X86_REG_INVALID
    reg_base = X86_REG_INVALID
    splitline = -1
    reg_ip = X86_REG_INVALID
    ph = X86_REG_INVALID
    # parse connect
    reg_base = get_regbase(insns)
    if reg_base == X86_REG_INVALID:
        return splitline
    for insn in reversed(insns):
        # find add edi(base), edx(off)
        if (reg_off == X86_REG_INVALID and
                instr_match(insn, X86_INS_ADD, [X86_OP_REG, X86_OP_REG])):
            op1, op2 = insn.operands
            if op1.reg == reg_base:
                reg_off = op2.reg
        if reg_off == X86_REG_INVALID:
            continue
        # mov edx(off), dword ptr [ip] ;
        if instr_match(insn, X86_INS_MOV, [X86_OP_REG, X86_OP_MEM], [get_reg32(reg_off), {'disp': 0, 'index': X86_REG_INVALID, 'scale': 1}]):
            reg_ip = insn.operands[1].mem.base
            if ph == reg_ip:
                splitline = insns.index(insn)
                break
        r, imm = crease_match(insn)
        if r != X86_REG_INVALID:
            if imm == -4 and r == reg_ip:
                splitline = insns.index(insn)
                break
            elif imm == 4:
                ph = r
    return splitline


h_seq = [VMPushReg, VMPopReg,
         VMPushImm,
         VMNor, VMNand, VMShift,
         VMStr, VMLdr,
         VMPushCRX, VMPopCRX,
         VMPushSP, VMPopSP,
         VMShld, VMShrd,
         VMAdd,
         VMMul, VMImul, VMDiv, VMIdiv,
         VMRdtsc, VMCpuid,
         VMLockExchange,
         VMCrc,
         VMPopFlag,
         VMNop, VMJmp, VMCall,
         VMUnknown]


def factory(address, config):
    if address in vm_handlers:
        return vm_handlers[address]
    insns = x86_simple_decode(address, 150, True)
    if not insns:
        print(f'shit {address:X}')
        breakpoint()
    if (splitline := get_splitline(insns)) > 0:
        body = insns[:splitline]
        connect = insns[splitline:]
        if config is None:  # test vminit
            h = VMInit(insns=insns,
                       body=body,
                       connect=connect,
                       address=address)
            if h.parse_vminit() and h.match() and h.parse_connect():
                vm_handlers[address] = h
                return h
            return None
        for g in h_seq:
            h = g(config=config, insns=insns, body=body, connect=connect,
                  conn_config=config, hbase=address, address=address)
            if h.match() and h.parse_connect():
                vm_handlers[address] = h
                return h
    else:
        h = VMExit(config=config,
                   insns=insns,
                   body=insns,
                   hbase=address,
                   address=address)
        if h.match():
            vm_handlers[address] = h
            return h
    # vm invalid
    return VMInvalid(config=config, address=address, insns=insns)
