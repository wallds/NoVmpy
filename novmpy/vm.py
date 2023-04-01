from novmpy.bridge import *
from capstone import *
from capstone.x86 import *
from novmpy.x86_deobf import *
from novmpy.match_helper import *


class VMConfig:
    def __init__(self):
        self.reg_key = X86_REG_INVALID
        self.reg_ip = X86_REG_INVALID
        self.reg_sp = X86_REG_INVALID
        self.reg_regs = extend_reg(X86_REG_ESP)
        self.reg_base = X86_REG_INVALID
        self.dir = 0
        self.rebase = 0

    def __str__(self):
        return 'VMConfig : r_key({}) r_ip({}) r_sp({}) r_regs({}) r_base({}) dir({}) rebase({})'.format(
            bridge.reg_name(self.reg_key), bridge.reg_name(
                self.reg_ip), bridge.reg_name(self.reg_sp),
            bridge.reg_name(self.reg_regs), bridge.reg_name(self.reg_base), self.dir, hex(self.rebase))

    def __repr__(self) -> str:
        return self.__str__()


class VMState:
    def __init__(self, **kwargs):
        self.ip = kwargs.get('ip', 0)
        self.key = kwargs.get('key', 0)
        self.current_handler = kwargs.get('current_handler', 0)
        self.config: VMConfig = kwargs.get('config', None)

    def get_address(self):
        return self.ip-self.config.dir*4

    def decode_emu(self, decoder, ct, reg, size):
        mask = get_mask(size*8)
        reg_key_op = X86_REG_INVALID
        cached_regs = {}
        if size == 1:
            reg_key_op = get_reg8(self.config.reg_key)
        elif size == 2:
            reg_key_op = get_reg16(self.config.reg_key)
        elif size == 4:
            reg_key_op = get_reg32(self.config.reg_key)
        elif size == 8:
            reg_key_op = get_reg64(self.config.reg_key)
        else:
            raise NotImplementedError('')
        pt = ct & mask
        for insn in decoder:
            insn: CsInsn
            regs_read, regs_write = insn.regs_access()
            # xor r11d, imm  regs_write = [??,r11d]
            if reg in regs_write:
                if insn.id == X86_INS_INC:
                    pt += 1
                elif insn.id == X86_INS_DEC:
                    pt -= 1
                elif insn.id == X86_INS_NOT:
                    pt = ~pt
                elif insn.id == X86_INS_NEG:
                    pt = 0-pt
                elif insn.id == X86_INS_BSWAP:
                    if insn.operands[0].size == 8:
                        pt = ((pt & 0xFF) << (7*8)) |\
                            ((pt & 0xFF00) << (5*8)) |\
                            ((pt & 0xFF0000) << (3*8)) | \
                            ((pt & 0xFF000000) << (1*8)) |\
                            ((pt & 0xFF00000000) >> (1*8)) | \
                            ((pt & 0xFF0000000000) >> (3*8)) |\
                            ((pt & 0xFF000000000000) >> (5*8)) | \
                            ((pt & 0xFF00000000000000) >> (7*8))
                    elif insn.operands[0].size == 4:
                        pt = ((pt & 0xFF) << 24) | ((pt & 0xFF00) << 8) |\
                            ((pt & 0xFF0000) >> 8) | ((pt & 0xFF000000) >> 24)
                elif instr_match(insn, [X86_INS_XOR, X86_INS_ADD, X86_INS_SUB], [X86_OP_REG, X86_OP_IMM], [reg]):
                    if insn.id == X86_INS_XOR:
                        pt ^= insn.operands[1].imm
                    elif insn.id == X86_INS_ADD:
                        pt += insn.operands[1].imm
                    elif insn.id == X86_INS_SUB:
                        pt -= insn.operands[1].imm
                elif instr_match(insn, [X86_INS_ROL, X86_INS_ROR], [X86_OP_REG, X86_OP_IMM], [reg]):
                    n = insn.operands[1].imm & 0x1F
                    if insn.id == X86_INS_ROL:
                        pt = ((pt & mask) << n) | (
                            (pt & mask) >> ((8 * size) - n))
                    elif insn.id == X86_INS_ROR:
                        pt = ((pt & mask) >> n) | (
                            (pt & mask) << ((8 * size) - n))
                elif instr_match(insn, X86_INS_XOR, [X86_OP_REG, X86_OP_REG], [reg, reg_key_op]):
                    pt ^= self.key
                elif instr_match(insn, X86_INS_ADD, [X86_OP_REG, X86_OP_REG]):
                    # add ip, rebase
                    pt += self.config.rebase
                elif instr_match(insn, X86_INS_LEA, [X86_OP_REG, X86_OP_MEM], [reg, {'base': reg, 'index': X86_REG_INVALID, 'scale': 1}]):
                    pt += insn.operands[1].mem.disp
                elif instr_match(insn, X86_INS_LEA, [X86_OP_REG, X86_OP_MEM], [reg, {'base': reg, 'disp': 0, 'scale': 1}]):
                    # fix lea ip, [ip+ecx]
                    pt += self.config.rebase
                else:
                    print(decoder)
                    raise NotImplementedError(insn)
                pt &= mask
            elif bridge.is64bit() and size == 4:
                if instr_match(insn, [X86_INS_MOV, X86_INS_MOVABS], [X86_OP_REG, X86_OP_IMM]):
                    cached_regs[insn.operands[0].reg] = insn.operands[1].imm
                reg_64 = extend_reg(reg)
                if reg_64 in regs_write:
                    if (instr_match(insn, X86_INS_LEA, [X86_OP_REG, X86_OP_MEM], [self.config.reg_ip, {'base': self.config.reg_ip, 'disp': 0, 'scale': 1}]) or
                        instr_match(insn, X86_INS_LEA, [X86_OP_REG, X86_OP_MEM], [self.config.reg_ip, {'index': self.config.reg_ip, 'disp': 0, 'scale': 1}]) or
                            instr_match(insn, X86_INS_ADD, [X86_OP_REG, X86_OP_REG], [self.config.reg_ip])):
                        if insn.id == X86_INS_ADD:
                            src = insn.operands[1].reg
                        else:
                            mem = insn.operands[1].mem
                            src = mem.index if mem.base == self.config.reg_ip else mem.base
                        pt += cached_regs.get(src, self.config.rebase)
                    else:
                        print('warning decode_emu 64', insn)
                    pt &= get_mask(64)
            # update key   -> xor reg_key_op, reg
            if instr_match(insn, X86_INS_XOR, [X86_OP_REG, X86_OP_REG], [reg_key_op, reg]):
                self.key ^= pt & mask
            if instr_match(insn, X86_INS_XOR, [X86_OP_MEM, X86_OP_REG], [None, reg]):
                self.key ^= pt & mask
        return pt

    def fetch(self, size) -> int:
        i = bridge.read(self.ip, size, self.config.dir)
        self.ip += self.config.dir*size
        return i
