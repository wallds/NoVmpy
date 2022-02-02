from __future__ import print_function
import ida_kernwin
import idaapi

from novmpy.vm_lifter import search_vmstubs
from novmpy.views import vtil_graph


class novmpy_letsgo_action(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        # breakpoint()
        ea = idaapi.get_screen_ea()
        print('ea:', hex(ea))
        vtil_graph.show_graph(ea)
        return 1

    def update(self, ctx):
        if ctx.widget_type == ida_kernwin.BWN_DISASM:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


class novmpy_search_action(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        # breakpoint()
        for entry, is_mid_routine in search_vmstubs():
            print('entry:', hex(entry), 'is_mid_routine:', is_mid_routine)
        return 1

    def update(self, ctx):
        if ctx.widget_type == ida_kernwin.BWN_DISASM:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


class novmpy_handler_view_action(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        # breakpoint()
        from novmpy.views.hview import show_handler_list_view
        show_handler_list_view()
        return 1

    def update(self, ctx):
        if ctx.widget_type == ida_kernwin.BWN_DISASM:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


_act_dests = [
    ida_kernwin.action_desc_t(
        "novmpy:letsgo", "LetsGo", novmpy_letsgo_action()),
    ida_kernwin.action_desc_t(
        "novmpy:search", "Search", novmpy_search_action()),
    ida_kernwin.action_desc_t(
        "novmpy:handler_view", "Handler List", novmpy_handler_view_action())
]


class HooksUI(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup):
        if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_DISASM:
            for act_dest in _act_dests:
                ida_kernwin.attach_action_to_popup(
                    widget, popup, act_dest.name, "NoVmpy/")


class UIManager():
    def __init__(self) -> None:
        self.ui_action_handler_register()
        self.hooks_ui = HooksUI()
        self.hooks_ui.hook()

    def __del__(self):
        self.hooks_ui = None
        self.ui_action_handler_unregister()

    def ui_action_handler_unregister(self):
        for act_dest in _act_dests:
            ida_kernwin.detach_action_from_menu(
                f"Edit/novmpy/{act_dest.name}", act_dest.name)
            # ida_kernwin.unregister_action(act_dest.name)

    def ui_action_handler_register(self):
        for act_dest in _act_dests:
            if not ida_kernwin.register_action(act_dest):
                print(f'warning failed register_action({act_dest.name})')
            ida_kernwin.attach_action_to_menu(
                f"Edit/novmpy/{act_dest.name}", act_dest.name, ida_kernwin.SETMENU_APP)
