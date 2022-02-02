from capstone import *
from capstone.x86 import *

import copy
from novmpy.bridge import *


def get_mask(bits):
    if bits < 0:
        return 0
    return 2**bits-1


def shit_disasm(ea, max_insn_count=-1, term_call_imm=False):
    insn_count = 0
    bbs = []
    bb = []
    addr = ea
    branches = [addr]
    walk = {}
    while True:
        if addr in walk:
            break
        walk[addr] = True
        a = [i for i in bridge.disasm_one(addr)]
        if len(a) == 0:
            break
        insn: CsInsn = a[0]
        if insn.id == X86_INS_INVALID:
            break
        if max_insn_count > 0 and insn_count >= max_insn_count:
            break
        # op1: X86Op = insn.op_find(X86_OP_IMM,1)
        if insn.group(X86_GRP_JUMP):
            op1: X86Op = insn.operands[0]
            if insn.id != X86_INS_JMP and op1.type == X86_OP_IMM:
                branches.append(op1.imm)
                branches.append(addr+insn.size)
            # jmp imm
            if insn.id == X86_INS_JMP and op1.type == X86_OP_IMM:
                addr = op1.imm
                continue
            # jmp reg
            elif insn.id == X86_INS_JMP and op1.type == X86_OP_REG:
                bb.append(insn)
                insn_count += 1
                break
        bb.append(insn)
        insn_count += 1
        if insn.group(X86_GRP_RET):
            break
        if term_call_imm:
            if insn.id == X86_INS_CALL and insn.operands[0].type == X86_OP_IMM:
                break
        addr += insn.size
    cur = 0
    cbb = []
    for i in bb:
        if i.address in branches and cur != i.address:
            if cur != 0:
                bbs.append(cbb)
                cbb = []
            cur = i.address
        cbb.append(i)
    if cbb:
        bbs.append(cbb)
    return bbs


map_reg = [
    [X86_REG_RAX, X86_REG_EAX, X86_REG_AX, X86_REG_AH, X86_REG_AL],
    [X86_REG_RCX, X86_REG_ECX, X86_REG_CX, X86_REG_CH, X86_REG_CL],
    [X86_REG_RDX, X86_REG_EDX, X86_REG_DX, X86_REG_DH, X86_REG_DL],
    [X86_REG_RBX, X86_REG_EBX, X86_REG_BX, X86_REG_BH, X86_REG_BL],

    [X86_REG_RSI, X86_REG_ESI, X86_REG_SI, X86_REG_INVALID, X86_REG_SIL],
    [X86_REG_RDI, X86_REG_EDI, X86_REG_DI, X86_REG_INVALID, X86_REG_DIL],
    [X86_REG_RBP, X86_REG_EBP, X86_REG_BP, X86_REG_INVALID, X86_REG_BPL],
    [X86_REG_RSP, X86_REG_ESP, X86_REG_SP, X86_REG_INVALID, X86_REG_SPL],

    [X86_REG_R8, X86_REG_R8D, X86_REG_R8W, X86_REG_INVALID, X86_REG_R8B],
    [X86_REG_R9, X86_REG_R9D, X86_REG_R9W, X86_REG_INVALID, X86_REG_R9B],
    [X86_REG_R10, X86_REG_R10D, X86_REG_R10W, X86_REG_INVALID, X86_REG_R10B],
    [X86_REG_R11, X86_REG_R11D, X86_REG_R11W, X86_REG_INVALID, X86_REG_R11B],
    [X86_REG_R12, X86_REG_R12D, X86_REG_R12W, X86_REG_INVALID, X86_REG_R12B],
    [X86_REG_R13, X86_REG_R13D, X86_REG_R13W, X86_REG_INVALID, X86_REG_R13B],
    [X86_REG_R14, X86_REG_R14D, X86_REG_R14W, X86_REG_INVALID, X86_REG_R14B],
    [X86_REG_R15, X86_REG_R15D, X86_REG_R15W, X86_REG_INVALID, X86_REG_R15B],
    [X86_REG_EFLAGS, X86_REG_INVALID, X86_REG_INVALID,
        X86_REG_INVALID, X86_REG_INVALID]
]

MASK_EFLAGS_SHIFT = {
    'CF': (1 << 0, X86_EFLAGS_MODIFY_CF | X86_EFLAGS_SET_CF | X86_EFLAGS_RESET_CF | X86_EFLAGS_UNDEFINED_CF, X86_EFLAGS_TEST_CF),
    'PF': (1 << 2, X86_EFLAGS_MODIFY_PF | X86_EFLAGS_SET_PF | X86_EFLAGS_RESET_PF | X86_EFLAGS_UNDEFINED_PF, X86_EFLAGS_TEST_PF),
    'AF': (1 << 4, X86_EFLAGS_MODIFY_AF | X86_EFLAGS_SET_AF | X86_EFLAGS_RESET_AF | X86_EFLAGS_UNDEFINED_AF, X86_EFLAGS_TEST_AF),
    'ZF': (1 << 6, X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_SET_ZF | X86_EFLAGS_RESET_ZF | X86_EFLAGS_UNDEFINED_ZF, X86_EFLAGS_TEST_ZF),
    'SF': (1 << 7, X86_EFLAGS_MODIFY_SF | X86_EFLAGS_SET_SF | X86_EFLAGS_RESET_SF | X86_EFLAGS_UNDEFINED_SF, X86_EFLAGS_TEST_SF),
    'OF': (1 << 11, X86_EFLAGS_MODIFY_OF | X86_EFLAGS_SET_OF | X86_EFLAGS_RESET_OF | X86_EFLAGS_UNDEFINED_OF, X86_EFLAGS_TEST_OF),
    'DF': (1 << 10, X86_EFLAGS_MODIFY_DF | X86_EFLAGS_SET_DF | X86_EFLAGS_RESET_DF, X86_EFLAGS_TEST_DF),
}

dict_regs = {
    X86_REG_INVALID: [X86_REG_INVALID, 0, 0],
    X86_REG_RAX: [X86_REG_RAX, 0, 64],
    X86_REG_EAX: [X86_REG_RAX, 0, 32],
    X86_REG_AX: [X86_REG_RAX, 0, 16],
    X86_REG_AH: [X86_REG_RAX, 8, 8],
    X86_REG_AL: [X86_REG_RAX, 0, 8],
    X86_REG_RCX: [X86_REG_RCX, 0, 64],
    X86_REG_ECX: [X86_REG_RCX, 0, 32],
    X86_REG_CX: [X86_REG_RCX, 0, 16],
    X86_REG_CH: [X86_REG_RCX, 8, 8],
    X86_REG_CL: [X86_REG_RCX, 0, 8],
    X86_REG_RDX: [X86_REG_RDX, 0, 64],
    X86_REG_EDX: [X86_REG_RDX, 0, 32],
    X86_REG_DX: [X86_REG_RDX, 0, 16],
    X86_REG_DH: [X86_REG_RDX, 8, 8],
    X86_REG_DL: [X86_REG_RDX, 0, 8],
    X86_REG_RBX: [X86_REG_RBX, 0, 64],
    X86_REG_EBX: [X86_REG_RBX, 0, 32],
    X86_REG_BX: [X86_REG_RBX, 0, 16],
    X86_REG_BH: [X86_REG_RBX, 8, 8],
    X86_REG_BL: [X86_REG_RBX, 0, 8],
    X86_REG_RSI: [X86_REG_RSI, 0, 64],
    X86_REG_ESI: [X86_REG_RSI, 0, 32],
    X86_REG_SI: [X86_REG_RSI, 0, 16],
    X86_REG_SIL: [X86_REG_RSI, 0, 8],
    X86_REG_RDI: [X86_REG_RDI, 0, 64],
    X86_REG_EDI: [X86_REG_RDI, 0, 32],
    X86_REG_DI: [X86_REG_RDI, 0, 16],
    X86_REG_DIL: [X86_REG_RDI, 0, 8],
    X86_REG_RBP: [X86_REG_RBP, 0, 64],
    X86_REG_EBP: [X86_REG_RBP, 0, 32],
    X86_REG_BP: [X86_REG_RBP, 0, 16],
    X86_REG_BPL: [X86_REG_RBP, 0, 8],
    X86_REG_RSP: [X86_REG_RSP, 0, 64],
    X86_REG_ESP: [X86_REG_RSP, 0, 32],
    X86_REG_SP: [X86_REG_RSP, 0, 16],
    X86_REG_SPL: [X86_REG_RSP, 0, 8],
    X86_REG_R8: [X86_REG_R8, 0, 64],
    X86_REG_R8D: [X86_REG_R8, 0, 32],
    X86_REG_R8W: [X86_REG_R8, 0, 16],
    X86_REG_R8B: [X86_REG_R8, 0, 8],
    X86_REG_R9: [X86_REG_R9, 0, 64],
    X86_REG_R9D: [X86_REG_R9, 0, 32],
    X86_REG_R9W: [X86_REG_R9, 0, 16],
    X86_REG_R9B: [X86_REG_R9, 0, 8],
    X86_REG_R10: [X86_REG_R10, 0, 64],
    X86_REG_R10D: [X86_REG_R10, 0, 32],
    X86_REG_R10W: [X86_REG_R10, 0, 16],
    X86_REG_R10B: [X86_REG_R10, 0, 8],
    X86_REG_R11: [X86_REG_R11, 0, 64],
    X86_REG_R11D: [X86_REG_R11, 0, 32],
    X86_REG_R11W: [X86_REG_R11, 0, 16],
    X86_REG_R11B: [X86_REG_R11, 0, 8],
    X86_REG_R12: [X86_REG_R12, 0, 64],
    X86_REG_R12D: [X86_REG_R12, 0, 32],
    X86_REG_R12W: [X86_REG_R12, 0, 16],
    X86_REG_R12B: [X86_REG_R12, 0, 8],
    X86_REG_R13: [X86_REG_R13, 0, 64],
    X86_REG_R13D: [X86_REG_R13, 0, 32],
    X86_REG_R13W: [X86_REG_R13, 0, 16],
    X86_REG_R13B: [X86_REG_R13, 0, 8],
    X86_REG_R14: [X86_REG_R14, 0, 64],
    X86_REG_R14D: [X86_REG_R14, 0, 32],
    X86_REG_R14W: [X86_REG_R14, 0, 16],
    X86_REG_R14B: [X86_REG_R14, 0, 8],
    X86_REG_R15: [X86_REG_R15, 0, 64],
    X86_REG_R15D: [X86_REG_R15, 0, 32],
    X86_REG_R15W: [X86_REG_R15, 0, 16],
    X86_REG_R15B: [X86_REG_R15, 0, 8],
    X86_REG_EFLAGS: [X86_REG_EFLAGS, 0, 64],
}


class RegFlag64:
    def __init__(self):
        self._reg_flags = {}
        for i in map_reg:
            self._reg_flags[i[0]] = 0
        self._reg_flags[X86_REG_EFLAGS] = 0

    def set_(self, reg):
        return self.or_(reg, get_mask(64))

    def cls_(self, reg):
        return self.and_(reg, 0)

    def update(self, insn: CsInsn):
        ignore_reg = False
        result = True

        if insn.id == X86_INS_CWD:
            self.or_(X86_REG_EDX, get_mask(16))
            return result
        elif insn.id == X86_INS_CDQ:
            self.or_(X86_REG_EDX, get_mask(32))
            return result
        elif insn.id == X86_INS_CQO:
            self.or_(X86_REG_EDX, get_mask(64))
            return result

        if insn.id == X86_INS_MOVZX:
            pass

        if insn.id == X86_INS_TEST:
            ignore_reg = True
        if not ignore_reg:
            regs_read, regs_write = insn.regs_access()
            for i in regs_write:
                if i == X86_REG_EFLAGS:
                    continue
                if not self.set_(i):
                    result = False
        if insn.group(X86_GRP_FPU):
            result = False
        else:
            eflags = insn.eflags
            if eflags:
                for k, v in MASK_EFLAGS_SHIFT.items():
                    shift, set_flags, test_flags = v
                    if eflags & set_flags:
                        self.or_(X86_REG_EFLAGS, shift)

        return result

    def get_info(self, reg):
        if reg in dict_regs:
            return dict_regs[reg]
        return dict_regs[X86_REG_INVALID]

    def or_(self, reg, value):
        base, off, bits = self.get_info(reg)
        if base == X86_REG_INVALID:
            return False
        self._reg_flags[base] |= (value & get_mask(bits)) << off
        return True

    def and_(self, reg, value):
        base, off, bits = self.get_info(reg)
        if base == X86_REG_INVALID:
            return False
        self._reg_flags[base] &= (
            (value | (~get_mask(bits))) << off) | (get_mask(off))
        return True

    def fetch(self, reg):
        base, off, bits = self.get_info(reg)
        if base == X86_REG_INVALID:
            return 0
        v = self._reg_flags[base]
        return (v >> (off)) & get_mask(bits)

    def check_read(self, insn: CsInsn):
        regs_read, regs_write = insn.regs_access()
        for rr in regs_read:
            if rr == X86_REG_EFLAGS:
                continue
            if self.fetch(rr):
                return False
        if not insn.group(X86_GRP_FPU):
            eflags = insn.eflags
            if eflags:
                value = self.fetch(X86_REG_EFLAGS)
                for k, v in MASK_EFLAGS_SHIFT.items():
                    shift, set_flags, test_flags = v
                    if eflags & test_flags:
                        if value & shift:
                            return False

        return True

    def empty(self):
        flag = 0
        m = get_mask(32)
        for k, v in self._reg_flags.items():
            flag |= v & m
        return flag == 0

    def check(self, rf, reg):
        v = self.fetch(reg)
        if v != 0:
            v2 = rf.fetch(reg)
            self.and_(reg, ~v2)

    def check_overwrite(self, insn, rf):
        self.check(rf, X86_REG_RAX)
        self.check(rf, X86_REG_RBX)
        self.check(rf, X86_REG_RCX)
        self.check(rf, X86_REG_RDX)
        self.check(rf, X86_REG_RSI)
        self.check(rf, X86_REG_RDI)
        self.check(rf, X86_REG_RSP)
        self.check(rf, X86_REG_RBP)
        self.check(rf, X86_REG_R8)
        self.check(rf, X86_REG_R9)
        self.check(rf, X86_REG_R10)
        self.check(rf, X86_REG_R11)
        self.check(rf, X86_REG_R12)
        self.check(rf, X86_REG_R13)
        self.check(rf, X86_REG_R14)
        self.check(rf, X86_REG_R15)
        self.check(rf, X86_REG_EFLAGS)

        return self.empty()


def x86_deobfusctor(insn_array, dump=False):
    # very slow!
    if len(insn_array) < 2:
        return insn_array
    new_array = []
    useless = [False]*len(insn_array)
    flags = [RegFlag64() for i in insn_array]
    for i in reversed(range(0, len(insn_array))):
        if insn_array[i].id == X86_INS_NOP:
            useless[i] = True
        if len(insn_array[i].regs_access()[1]) == 0:
            continue
        if insn_array[i].id == X86_INS_XCHG or insn_array[i].id == X86_INS_MOV or insn_array[i].group(X86_GRP_CMOV):
            op1 = insn_array[i].operands[0]
            op2 = insn_array[i].operands[1]
            if op1.type == op2.type and op1.size == op2.size and op1.reg == op2.reg:
                useless[i] = True
        if (not flags[i].update(insn_array[i])) or flags[i].empty():
            continue
        if insn_array[i].id == X86_INS_CALL:
            continue
        if len(insn_array[i].operands) > 1:
            op1 = insn_array[i].operands[0]
            if op1.type == CS_OP_MEM:
                continue
        flag = copy.deepcopy(flags[i])
        for j in range(i+1, len(insn_array)):
            if useless[j]:
                continue
            insn: CsInsn = insn_array[j]
            if not flag.check_read(insn):
                break
            # [i] mov al, bl
            # [i+n] mov eax, 0;  al<----eax
            if len(insn.regs_access()[1]) > 0 and flag.check_overwrite(insn, flags[j]):
                useless[i] = True
                break

    for i, e in enumerate(insn_array):
        insn: CsInsn = insn_array[i]
        if not useless[i]:
            if dump:
                print(f'0x{insn.address:X} {insn.mnemonic} {insn.op_str}')
            new_array.append(e)
        else:
            if dump:
                print(f'; 0x{insn.address:X} {insn.mnemonic} {insn.op_str}')
    return new_array


def x86_simple_decode(ea, max_insn_count=-1, term_call_imm=False):
    s = []
    bbs = shit_disasm(ea, max_insn_count, term_call_imm)
    for bb in bbs:
        s += x86_deobfusctor(bb)
    return s


def get_reg8(reg):
    if reg == X86_REG_INVALID:
        return X86_REG_INVALID
    for i, elems in enumerate(map_reg):
        for j, elem_j in enumerate(elems):
            if (elem_j == reg):
                return elems[4]
    return X86_REG_INVALID


def get_reg16(reg):
    if reg == X86_REG_INVALID:
        return X86_REG_INVALID
    for i, elems in enumerate(map_reg):
        for j, elem_j in enumerate(elems):
            if (elem_j == reg):
                return elems[2]
    return X86_REG_INVALID


def get_reg32(reg):
    if reg == X86_REG_INVALID:
        return X86_REG_INVALID
    for i, elems in enumerate(map_reg):
        for j, elem_j in enumerate(elems):
            if (elem_j == reg):
                return elems[1]
    return X86_REG_INVALID


def extend_reg(reg):
    if bridge.is64bit():
        return get_reg64(reg)
    return get_reg32(reg)


def get_reg64(reg):
    if reg == X86_REG_INVALID:
        return X86_REG_INVALID
    for i, elems in enumerate(map_reg):
        for j, elem_j in enumerate(elems):
            if (elem_j == reg):
                return elems[0]
    return X86_REG_INVALID


def dump_insns(insns):
    for i in insns:
        print(i)


if __name__ == '__main__':
    pass
