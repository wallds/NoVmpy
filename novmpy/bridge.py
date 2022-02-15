from capstone import *


class BridgeBase:
    def __init__(self):
        # arch size
        self.size = 8 if self.is64bit() else 4

        if self.is64bit():
            self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        else:
            self.md = Cs(CS_ARCH_X86, CS_MODE_32)
        self.md.detail = True

    def read(self, addr, size, dir_=1):
        raise NotImplementedError()

    def is_readable(self, addr, size, dir_):
        raise NotImplementedError()

    def is_writeable(self, addr, size, dir_):
        raise NotImplementedError()

    def get_bytes(self, addr, size):
        raise NotImplementedError()

    def get_segs(self):
        raise NotImplementedError()

    def get_base(self):
        raise NotImplementedError()

    def is64bit(self):
        raise NotImplementedError()

    def update_msg(self, msg):
        raise NotImplementedError()

    def disasm(self, code, offset, count=0):
        return self.md.disasm(code, offset, count)

    def disasm_one(self, offset):
        for x in self.md.disasm(self.get_bytes(offset, 20), offset, 1):
            return x
        return None

    def reg_name(self, reg_id, default=None):
        return self.md.reg_name(reg_id, default)


class BridgeLocal(BridgeBase):  # bridge for local
    def __init__(self, exe_path):
        import cle
        self.ld = cle.Loader(exe_path, False)
        super().__init__()

    def read(self, addr, size, dir_=1):
        addr_ = addr
        if dir_ < 0:
            addr_ -= size
        b = self.get_bytes(addr_, size)
        return int.from_bytes(b, byteorder='little')

    def is_readable(self, addr, size, dir_=1):
        if dir_ > 0:
            return addr >= self.ld.main_object.min_addr and addr+size < self.ld.main_object.max_addr
        else:
            return addr-size >= self.ld.main_object.min_addr and addr <= self.ld.main_object.max_addr

    def get_bytes(self, addr, size):
        return self.ld.memory.load(addr, size)

    def get_segs(self):
        return self.ld.main_object.sections

    def get_base(self):
        return self.ld.main_object.mapped_base

    def is64bit(self):
        return self.ld.main_object.arch.name == 'AMD64'

    def update_msg(self, msg):
        pass


class BridgeIda(BridgeBase):  # bridge for ida:
    def __init__(self):
        super().__init__()

    def read(self, addr, size, dir_=1):
        addr_ = addr
        if dir_ < 0:
            addr_ -= size
        b = self.get_bytes(addr_, size)
        return int.from_bytes(b, byteorder='little')

    def is_readable(self, addr, size, dir_=1):
        import idc
        if dir_ < 0:
            return idc.is_mapped(addr-size)
        if addr == 0xffffffffffffffff:
            return False
        return idc.is_mapped(addr) and idc.is_loaded(addr)

    def is_writeable(self, addr, size, dir_=1):
        import ida_segment
        if dir_ < 0:
            addr -= size
        seg = ida_segment.getseg(addr)
        if seg is not None:
            return (seg.perm & ida_segment.SEGPERM_WRITE) != 0
        return False

    def get_segs(self):
        class dummy_seg():
            pass

        import ida_segment
        n = 0
        seg = ida_segment.getnseg(n)
        while seg is not None:
            dummy = dummy_seg()
            dummy.is_executable = (seg.perm & ida_segment.SEGPERM_EXEC) != 0
            dummy.vaddr = seg.start_ea
            dummy.memsize = seg.size()
            dummy.min_addr = seg.start_ea
            dummy.max_addr = seg.end_ea
            yield dummy
            n += 1
            seg = ida_segment.getnseg(n)

    def get_base(self):
        return 0

    def get_bytes(self, addr, size):
        import ida_bytes
        return ida_bytes.get_bytes(addr, size)

    def is64bit(self):
        import idaapi
        return idaapi.inf_is_64bit()

    def update_msg(self, msg):
        import ida_kernwin
        ida_kernwin.replace_wait_box(msg)
        return not ida_kernwin.user_cancelled()


try:
    local_mode = False
    import idaapi
except:
    local_mode = True


bridge = None

if local_mode:
    bridge = BridgeLocal(
        r'F:\VMP_Sample\Sample_vmp3.4\test_misc\test_misc.x86.vmp.exe')
else:
    bridge = BridgeIda()
