from capstone import *
from capstone.x86 import *
from novmpy.x86_deobf import *
from novmpy.bridge import *


class MatchHelper:
    """
    fetch: vm_bytecode
    load, store: stack
    mem: memory pointer
    read, write: vm_regs
    """

    # TODO: zword -> arch size 4 or 8

    def __init__(self, body, config):
        self.body = body
        self.index = 0
        self.config = config
        self.placeholder = {}

    def reset(self):
        self.index = 0
        self.placeholder = {}
        return True

    def update_index(self, new_index):
        self.index = new_index

    # maybe we can use __getitem__
    def get_ph(self, key):
        if key in self.placeholder:
            return self.placeholder[key]
        raise KeyError()

    def check_placeholder(self, args, k, v):
        # placeholder mode when args[k] is a str
        if k in args:
            if isinstance(args[k], str):
                ph_name = args[k]
                # do match when ph in dict
                if ph_name in self.placeholder:
                    if self.placeholder[ph_name] != v:
                        return False
                else:
                    self.placeholder[ph_name] = v
            else:
                return args[k] == v
        else:
            # not a placeholder, so just put in dict
            args[k] = v
        return True
    # match functions

    def get_sp(self, args):
        for i in range(self.index, len(self.body)):
            insn: CsInsn = self.body[i]
            if instr_match(insn, X86_INS_MOV, [X86_OP_REG, X86_OP_REG], [None, self.config.reg_sp]):
                op1, op2 = insn.operands
                if not self.check_placeholder(args, 'reg', op1.reg):
                    continue
                self.update_index(i+1)
                return True
        return False

    # stack
    def _load(self, off, args):
        for i in range(self.index, len(self.body)):
            insn: CsInsn = self.body[i]
            if instr_match(insn, [X86_INS_MOV, X86_INS_MOVZX], [X86_OP_REG, X86_OP_MEM], [None, {'base': self.config.reg_sp, 'disp': off, 'index': X86_REG_INVALID, 'scale': 1}]):
                op1, op2 = insn.operands
                if not self.check_placeholder(args, 'reg', op1.reg):
                    continue
                if not self.check_placeholder(args, 'size', op2.size):
                    continue
                self.update_index(i+1)
                return True
        return False

    def _store(self, off, args):
        for i in range(self.index, len(self.body)):
            insn: CsInsn = self.body[i]
            if instr_match(insn, X86_INS_MOV, [X86_OP_MEM, X86_OP_REG], [{'base': self.config.reg_sp, 'disp': off, 'index': X86_REG_INVALID, 'scale': 1}]):
                op1, op2 = insn.operands
                if not self.check_placeholder(args, 'reg', op2.reg):
                    continue
                if not self.check_placeholder(args, 'size', op1.size):
                    continue
                self.update_index(i+1)
                return True
        return False

    def load_byte(self, off=0, args=None):
        # movzx cx, byte ptr [{sp}]
        if args is None:
            args = {}
        args['size'] = 1
        return self._load(off, args)

    def load_word(self, off=0, args=None):
        # movzx cx, word ptr [{sp}]
        if args is None:
            args = {}
        args['size'] = 2
        return self._load(off, args)

    def load_dword(self, off=0, args=None):
        # mov eax, dword ptr [{sp}]
        if args is None:
            args = {}
        args['size'] = 4
        return self._load(off, args)

    def load_qword(self, off=0, args=None):
        # mov eax, dword ptr [{sp}]
        if args is None:
            args = {}
        args['size'] = 8
        return self._load(off, args)

    def load_zword(self, off=0, args=None):
        # mov eax, dword ptr [{sp}]
        if args is None:
            args = {}
        args['size'] = bridge.size
        return self._load(off, args)

    def load(self, off=0, args=None):
        if args is None:
            args = {}
        # mov eax, dword ptr [{sp}]
        return self._load(off, args)

    def store_byte(self, off=0, args=None):
        # movzx cx, byte ptr [{sp}]
        if args is None:
            args = {}
        args['size'] = 1
        return self._store(off, args)

    def store_word(self, off=0, args=None):
        # movzx cx, word ptr [{sp}]
        if args is None:
            args = {}
        args['size'] = 2
        return self._store(off, args)

    def store_dword(self, off=0, args=None):
        # mov eax, dword ptr [{sp}]
        if args is None:
            args = {}
        args['size'] = 4
        return self._store(off, args)

    def store_qword(self, off=0, args=None):
        # mov eax, dword ptr [{sp}]
        if args is None:
            args = {}
        args['size'] = 8
        return self._store(off, args)

    def store(self, off=0, args=None):
        # mov eax, dword ptr [{sp}]
        if args is None:
            args = {}
        return self._store(off, args)

    def _read(self, args):
        id = [X86_INS_MOV, X86_INS_MOVZX]
        # movzx eax, byte ptr []
        # mov eax, dword ptr []
        for i in range(self.index, len(self.body)):
            insn: CsInsn = self.body[i]
            if instr_match(insn, id, [X86_OP_REG, X86_OP_MEM], [None, {'base': self.config.reg_regs, 'disp': 0, 'scale': 1}]):
                op1, op2 = insn.operands
                if not self.check_placeholder(args, 'reg', op1.reg):
                    continue
                if not self.check_placeholder(args, 'size', op2.size):
                    continue
                self.update_index(i)
                return True
        return False

    # vm_regs
    def read_byte(self, args=None):
        if args is None:
            args = {}
        args['size'] = 1
        return self._read(args)

    def read_word(self, args=None):
        if args is None:
            args = {}
        args['size'] = 2
        return self._read(args)

    def read_dword(self, args=None):
        if args is None:
            args = {}
        args['size'] = 4
        return self._read(args)

    def read_qword(self, args=None):
        if args is None:
            args = {}
        args['size'] = 8
        return self._read(args)

    def read(self, args=None):
        if args is None:
            args = {}
        return self._read(args)

    def _write(self, args):
        for i in range(self.index, len(self.body)):
            insn: CsInsn = self.body[i]
            if instr_match(insn, X86_INS_MOV, [X86_OP_MEM, X86_OP_REG], [{'base': self.config.reg_regs, 'disp': 0, 'scale': 1}]):
                op1, op2 = insn.operands
                if not self.check_placeholder(args, 'reg', op2.reg):
                    continue
                if not self.check_placeholder(args, 'size', op1.size):
                    continue
                self.update_index(i)
                return True
        return False

    def write_byte(self, args=None):
        if args is None:
            args = {}
        args['size'] = 1
        return self._write(args)

    def write_word(self, args=None):
        if args is None:
            args = {}
        args['size'] = 2
        return self._write(args)

    def write_dword(self, args=None):
        if args is None:
            args = {}
        args['size'] = 4
        return self._write(args)

    def write_qword(self, args=None):
        if args is None:
            args = {}
        args['size'] = 8
        return self._write(args)

    def write(self, args=None):
        if args is None:
            args = {}
        return self._write(args)

    def _mem_write(self, args):
        # mov dword ptr ds:[ecx], al
        for i in range(self.index, len(self.body)):
            insn: CsInsn = self.body[i]
            if instr_match(insn, X86_INS_MOV, [X86_OP_MEM, X86_OP_REG], [{'index': X86_REG_INVALID, 'disp': 0, 'scale': 1}]):
                op1, op2 = insn.operands
                if not self.check_placeholder(args, 'addr', op1.mem.base):
                    continue
                if not self.check_placeholder(args, 'val', op2.reg):
                    continue
                if not self.check_placeholder(args, 'segment', op1.mem.segment):
                    continue
                if not self.check_placeholder(args, 'size', op1.size):
                    continue
                self.update_index(i)
                return True
        return False

    def mem_write_byte(self, args=None):
        if args is None:
            args = {}
        args['size'] = 1
        return self._mem_write(args)

    def mem_write_word(self, args=None):
        if args is None:
            args = {}
        args['size'] = 2
        return self._mem_write(args)

    def mem_write_dword(self, args=None):
        if args is None:
            args = {}
        # mov dword ptr [ecx], eax
        args['size'] = 4
        return self._mem_write(args)

    def mem_write_qword(self, args=None):
        if args is None:
            args = {}
        args['size'] = 8
        return self._mem_write(args)

    def mem_write_zword(self, args=None):
        if args is None:
            args = {}
        args['size'] = bridge.size
        return self._mem_write(args)

    def mem_write(self, args=None):
        if args is None:
            args = {}
        return self._mem_write(args)

    def _mem_read(self, args):
        # mov al, dword ptr ds:[ecx],
        for i in range(self.index, len(self.body)):
            insn: CsInsn = self.body[i]
            if instr_match(insn, [X86_INS_MOV, X86_INS_MOVZX], [X86_OP_REG, X86_OP_MEM], [None, {'index': X86_REG_INVALID, 'disp': 0, 'scale': 1}]):
                op1, op2 = insn.operands
                if not self.check_placeholder(args, 'addr', op2.mem.base):
                    continue
                if not self.check_placeholder(args, 'val', op1.reg):
                    continue
                if not self.check_placeholder(args, 'segment', op2.mem.segment):
                    continue
                if not self.check_placeholder(args, 'size', op2.size):
                    continue
                self.update_index(i)
                return True
        return False

    def mem_read_byte(self, args=None):
        if args is None:
            args = {}
        args['size'] = 1
        return self._mem_read(args)

    def mem_read_word(self, args=None):
        if args is None:
            args = {}
        args['size'] = 2
        return self._mem_read(args)

    def mem_read_dword(self, args=None):
        if args is None:
            args = {}
        # mov eax, dword ptr [ecx]
        args['size'] = 4
        return self._mem_read(args)

    def mem_read_qword(self, args=None):
        if args is None:
            args = {}
        args['size'] = 8
        return self._mem_read(args)

    def mem_read(self, args=None):
        if args is None:
            args = {}
        return self._mem_read(args)

    def decode(self, args=None):
        if args is None:
            args = {}
        # find decode begin: xor ecx, ebx
        begin = -1
        for i in range(self.index, len(self.body)):
            insn: CsInsn = self.body[i]
            if instr_match(insn, X86_INS_XOR, [X86_OP_REG, X86_OP_REG]):
                op1, op2 = insn.operands
                if extend_reg(op2.reg) == self.config.reg_key:
                    reg1 = op1.reg
                    begin = i
                    break
        if begin == -1:
            return False

        # find decode end: xor ebx, ecx
        end = -1
        for i in range(begin, len(self.body)):
            insn: CsInsn = self.body[i]
            if instr_match(insn, X86_INS_XOR, [X86_OP_REG, X86_OP_REG]):
                op1, op2 = insn.operands
                if extend_reg(op1.reg) == self.config.reg_key:
                    reg2 = op2.reg
                    end = i
                    size = op2.size
                    break

        # <CsInsn 0x1406e9dbb [4152]: push r10>
        # <CsInsn 0x1406e9dc4 [310c24]: xor dword ptr [rsp], ecx>
        # <CsInsn 0x1406e9dd6 [415a]: pop r10>
        if end == -1 and bridge.is64bit():
            for i in range(begin, len(self.body)):
                insn: CsInsn = self.body[i]
                if instr_match(insn, X86_INS_XOR, [X86_OP_MEM, X86_OP_REG]):
                    op1, op2 = insn.operands
                    reg2 = op2.reg
                    end = i
                    size = op1.size
                    break

        if end == -1:
            return False

        if reg1 == reg2:
            args['reg'] = reg1
            args['decoder'] = self.body[begin:end+1]
            args['size'] = size
            self.update_index(end+1)
            return True
        return False

    def _fetch(self, args=None):
        if args is None:
            args = {}
        for i in range(self.index, len(self.body)):
            insn: CsInsn = self.body[i]
            if instr_match(insn, [X86_INS_MOV, X86_INS_MOVZX], [X86_OP_REG, X86_OP_MEM],
                           [None, {'base': self.config.reg_ip, 'disp': 0, 'index': X86_REG_INVALID, 'scale': 1}]):
                op1, op2 = insn.operands
                if not self.check_placeholder(args, 'size', op2.size):
                    continue
                self.update_index(i+1)
                return True
        return False

    # find movzx ecx, byte ptr [ip]
    def fetch_byte(self):
        return self._fetch({'size': 1})

    def fetch_word(self):
        return self._fetch({'size': 2})

    def fetch_dword(self):
        return self._fetch({'size': 4})

    def fetch_qword(self):
        return self._fetch({'size': 8})

    def fetch(self, args=None):
        if args is None:
            args = []
        return self._fetch(args)

    def batch(self, id):
        ids = id if isinstance(id, list) else [id]
        if len(ids) == 0:
            return False
        match_count = 0
        for i in range(self.index, len(self.body)):
            insn: CsInsn = self.body[i]
            if insn.id == ids[match_count]:
                match_count += 1
                if match_count >= len(ids):
                    self.update_index(i+1)
                    return True
        return False

    def among(self, id, args=None):
        if args is None:
            args = {}
        ids = id if isinstance(id, list) else [id]
        if len(ids) == 0:
            return False
        for i in range(self.index, len(self.body)):
            insn: CsInsn = self.body[i]
            if insn.id in ids:
                self.update_index(i+1)
                if not self.check_placeholder(args, 'ins', insn.id):
                    continue
                return True
        return False

    def store_eflags(self):
        eflags = X86_INS_PUSHFQ if bridge.is64bit() else X86_INS_PUSHFD
        # find pushfd
        tmp = -1
        for i in range(self.index, len(self.body)):
            insn: CsInsn = self.body[i]
            if insn.id == eflags:
                tmp = i+1
                break
        if tmp < 0:
            return False

        for i in range(tmp, len(self.body)):
            insn: CsInsn = self.body[i]
            if instr_match(insn, X86_INS_POP, [X86_OP_MEM], [{'base': self.config.reg_sp, 'disp': 0, 'index': X86_REG_INVALID, 'scale': 1}]):
                self.update_index(i+1)
                return True
        return False

    def match_for(self, callback):
        for i in range(self.index, len(self.body)):
            insn: CsInsn = self.body[i]
            if callback(insn):
                self.update_index(i+1)
                return True
        return False

    def match(self, id, optype=None, opx=None):
        if optype is None:
            optype = []
        if opx is None:
            opx = []
        for i in range(self.index, len(self.body)):
            insn: CsInsn = self.body[i]
            if instr_match(insn, id, optype, opx):
                self.update_index(i+1)
                return True
        return False

# id  X86_INS_ADD     [X86_INS_ADD, X86_INS_SUB]
# optype [X86_OP_REG, X86_OP_MEM]
# opx [X86_REG_EAX, {'base': X86_REG_EBP, 'disp': 4}]


def instr_match(insn: CsInsn, id, optype=None, opx=None):
    if optype is None:
        optype = []
    if opx is None:
        opx = []
    ids = id if isinstance(id, list) else [id]
    if insn.id not in ids:
        return False
    if len(insn.operands) < len(optype):
        return False
    for i, item in enumerate(optype):
        op: X86Op = insn.operands[i]
        if op.type != item:
            return False
        # [X86_OP_REG, X86_OP_MEM], [reg, {'base': reg, 'index': X86_REG_INVALID, 'scale': 1}])
        if len(opx) > i:
            if opx[i] is None:
                continue
            if item == X86_OP_REG:
                if op.reg != opx[i]:
                    return False
            elif item == X86_OP_IMM:
                if op.imm != opx[i]:
                    return False
            elif item == X86_OP_MEM:
                # 'segment', 'base', 'index','scale','disp',
                if 'segment' in opx[i] and opx[i]['segment'] != None and op.mem.segment != opx[i]['segment']:
                    return False
                elif 'base' in opx[i] and opx[i]['base'] != None and op.mem.base != opx[i]['base']:
                    return False
                elif 'index' in opx[i] and opx[i]['index'] != None and op.mem.index != opx[i]['index']:
                    return False
                elif 'scale' in opx[i] and opx[i]['scale'] != None and op.mem.scale != opx[i]['scale']:
                    return False
                elif 'disp' in opx[i] and opx[i]['disp'] != None and op.mem.disp != opx[i]['disp']:
                    return False
    return True
