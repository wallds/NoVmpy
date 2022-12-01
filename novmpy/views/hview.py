from __future__ import print_function

from capstone import CsInsn
from ida_kernwin import Choose
from novmpy.handler import vm_handlers
from novmpy.handler import VMJmp
import ida_kernwin
import idaapi
import ida_lines


class HandlerViewer(ida_kernwin.simplecustviewer_t):
    def Create(self, handler):
        if ida_kernwin.find_widget('handler view'):
            self.handler = handler
            self.reload()
            return True
        # Create the customviewer
        if not ida_kernwin.simplecustviewer_t.Create(self, 'handler view'):
            return False
        self.handler = handler
        self.reload()
        return True

    def Show(self, *args):
        return ida_kernwin.simplecustviewer_t.Show(self, *args)

    def reload(self):
        self.ClearLines()
        self.AddLine(ida_lines.COLSTR(
            str(self.handler.config), ida_lines.SCOLOR_AUTOCMT))
        for i in self.handler.body:
            i: CsInsn
            self.AddLine(ida_lines.COLSTR(
                f'{i.address:016X} {i.mnemonic:<8} {i.op_str}', ida_lines.SCOLOR_INSN))

        if isinstance(self.handler, VMJmp):
            self.AddLine(ida_lines.COLSTR(
                str(self.handler.conn_config), ida_lines.SCOLOR_AUTOCMT))
        else:
            self.AddLine('')
        for i in self.handler.connect:
            i: CsInsn
            self.AddLine(ida_lines.COLSTR(
                f'{i.address:016X} {i.mnemonic:<8} {i.op_str}', ida_lines.SCOLOR_INSN))
        self.Refresh()

    @staticmethod
    def get_instance():
        return _handler_viewer

    def show_win(self, handler):
        if not self.Create(handler):
            return False
        ida_kernwin.display_widget(
            self.GetWidget(), idaapi.PluginForm.WOPN_DP_TAB | idaapi.PluginForm.WOPN_RESTORE)
        ida_kernwin.set_dock_pos(
            self.title, "HandlerListView", ida_kernwin.DP_RIGHT)
        self.Show()
        return True


class HandlerListView(Choose):
    class Item():
        def __init__(self, address, name, body_len) -> None:
            self.address = address
            self.name = name
            self.body_len = body_len

        def to_strings(self):
            s = [f'{self.address:016X}', self.name, str(self.body_len)]
            return s

    def __init__(self, title, flags=0):
        Choose.__init__(self, title,
                        [["Address", 15], ["Name", 20], ["BodyLen", 5]],
                        flags=flags | Choose.CH_CAN_REFRESH)

        self.items = []
        self.reload()

    def reload(self):
        self.items = []
        for k, v in vm_handlers.items():
            self.items.append(HandlerListView.Item(
                k, f'{v.name}@{v.opsize}', len(v.body)))

    def OnInit(self):
        return True

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n].to_strings()

    def OnGetIcon(self, n):
        return 81

    def OnGetLineAttr(self, n):
        # return [0xFF0000, 0]
        return None

    def OnRefresh(self, n):
        self.reload()
        return None  # call standard refresh

    def OnSelectLine(self, n):
        ea = self.items[n].address
        print(hex(ea))
        h = vm_handlers.get(ea, None)
        if h is not None:
            print(h.name)
            HandlerViewer.get_instance().show_win(h)
        return (Choose.NOTHING_CHANGED, )

    def OnClose(self):
        return

    def show(self):
        self.reload()
        return self.Show(False) >= 0


# -----------------------------------------------------------------------


_handler_viewer = HandlerViewer()
_handler_list_viewer = HandlerListView("HandlerListView")


def show_handler_list_view():
    _handler_list_viewer.show()
