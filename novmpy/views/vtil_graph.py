import collections
import idautils
import ida_lines
# -----------------------------------------------------------------------
# This is an example illustrating how to use the user graphing functionality
# in Python
# (c) Hex-Rays
#
import ida_dbg
import ida_graph
import ida_kernwin
import ida_ida
import ida_name
from ida_nalt import get_str_type
from ida_bytes import is_strlit, get_flags, get_strlit_contents

from pyvtil import *
from novmpy.vm_lifter import VMLifter
from novmpy.vm import VMState
import os


class _base_graph_action_handler_t(ida_kernwin.action_handler_t):
    def __init__(self, graph):
        ida_kernwin.action_handler_t.__init__(self)
        self.graph: MyGraph = graph

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET


class GraphRefresh(_base_graph_action_handler_t):
    def activate(self, ctx):
        print('Refresh graph:', self.graph)
        self.graph.Refresh()


class GraphTrace(_base_graph_action_handler_t):
    def activate(self, ctx):
        place, _, _ = ida_kernwin.get_custom_viewer_place(
            ida_graph.get_graph_viewer(self.graph.GetWidget()), False)
        node_id = ida_graph.viewer_get_curnode(
            ida_graph.get_graph_viewer(self.graph.GetWidget()))
        # print(node_id, place.lnnum)
        if node_id < 0 or place.lnnum < 1:
            return 0
        block = None
        if self.graph.rtn is None:
            return 0
        for vip, b in self.graph.rtn.explored_blocks.items():
            if vip == self.graph.list_vip[node_id]:
                block = b
                break
        if block:
            it = block.begin()
            for i in range(place.lnnum - 1):
                it = it.next()
            ins = it.get()
            if not it.get().base.is_branching():
                it = it.next()
            tracer = vtil.tracer()
            for i in ins.operands:
                if i.is_register() and i.reg() != vtil.REG_IMGBASE:
                    print(
                        f'{i} = {tracer.rtrace(vtil.symbolic.variable(it, i.reg())).simplify(True)}')
        return 0

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET


class GraphErase(_base_graph_action_handler_t):
    def activate(self, ctx):
        place, _, _ = ida_kernwin.get_custom_viewer_place(
            ida_graph.get_graph_viewer(self.graph.GetWidget()), False)
        node_id = ida_graph.viewer_get_curnode(
            ida_graph.get_graph_viewer(self.graph.GetWidget()))
        # print(node_id, place.lnnum)
        ln = place.lnnum - 1
        if node_id < 0 or ln < 0:
            return 0
        block = None
        if self.graph.rtn is None:
            return 0
        for vip, b in self.graph.rtn.explored_blocks.items():
            if vip == self.graph.list_vip[node_id]:
                block = b
                break
        if block:
            it = block.begin()
            if block.size() == ln + 1:
                print('cant erase last instruction')
                return 0
            for i in range(ln):
                it = it.next()
            msg = ida_lines.tag_remove(instruction_tostring(it.get()))
            if ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO, f'Erase:\n{msg}') != ida_kernwin.ASKBTN_YES:
                return 0
            block.erase(it)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET


class GraphApplyAllProfiled(_base_graph_action_handler_t):
    def activate(self, ctx):
        print('apply_all_profiled')
        if self.graph.rtn is None:
            return 0
        vtil.optimizer.apply_all_profiled(self.graph.rtn)
        # self.graph.Refresh()
        # ida_graph.viewer_center_on(ida_graph.get_graph_viewer(self.graph.GetWidget()), 0)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET


class GraphLoad(_base_graph_action_handler_t):
    def activate(self, ctx):
        print('Load')
        _path = ida_kernwin.ask_file(False, '*.vtil', 'Choose vtil file:')
        if _path:
            self.graph.rtn = vtil.routine.load(_path)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET


class GraphSave(_base_graph_action_handler_t):
    def activate(self, ctx):
        print('Save')
        if self.graph.rtn is None:
            return 0
        _path = ida_kernwin.ask_file(
            True, '*.vtil', 'Enter name of vtil file:')
        if _path:
            self.graph.rtn.save(_path)
        return 0

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET


class JumptoAction(_base_graph_action_handler_t):
    def activate(self, ctx):
        gv = ida_graph.get_graph_viewer(ctx.widget)
        print('whoooooops, not impl')
        # s = ida_kernwin.ask_str('', 0, 'addr')
        # if s:
        #     ea = ida_kernwin.str2ea(s)
        #     self.graph.jumpto(nid, lnnum)
        return 0

    def update(self, ctx):
        # FIXME:
        if not self.graph.focus or self.graph.GetWidget() != ctx.widget:
            return ida_kernwin.AST_DISABLE_FOR_WIDGET
        return ida_kernwin.AST_ENABLE_FOR_WIDGET


def pack_operands(operands):
    opstr = []
    for op in operands:
        color = ida_lines.SCOLOR_REG if op.is_register() else ida_lines.SCOLOR_DNUM
        _opstr = ida_lines.COLSTR(f'{str(op)}', color)
        opstr.append(_opstr)
    return opstr


dict_cond = {
    'tg': '>', 'tge': '>=',
    'te': '==', 'tne': '!=',
    'tl': '<', 'tle': '<=',
    'tug': 'u>', 'tuge': 'u>=',
    'tul': 'u<', 'tule': 'u<=',
}


def instruction_tostring(ins: vtil.instruction):
    # @https://github.com/vtil-project/VTIL-BinaryNinja/blob/master/vtil/vtil.py
    s = ''
    comment = ''
    s += ida_lines.COLSTR(f'{ins.base.to_string(ins.access_size()):6}',
                          ida_lines.SCOLOR_INSN)
    s += ' '
    opstr = pack_operands(ins.operands)
    if ins.base.name in dict_cond:
        # op0 = op1 cond op2
        s += opstr[0]
        s += ida_lines.COLSTR(' := (', ida_lines.SCOLOR_SYMBOL)
        s += opstr[1]
        s += ida_lines.COLSTR(f' {dict_cond[ins.base.name]} ',
                              ida_lines.SCOLOR_SYMBOL)
        s += opstr[2]
        s += ida_lines.COLSTR(')', ida_lines.SCOLOR_SYMBOL)
    elif ins.base.name == 'js':
        # op0 ? op1: op2
        s += opstr[0]
        s += ida_lines.COLSTR(' ? ', ida_lines.SCOLOR_SYMBOL)
        s += opstr[1]
        s += ida_lines.COLSTR(' : ', ida_lines.SCOLOR_SYMBOL)
        s += opstr[2]
    elif ins.base.name == 'str':
        # [op0+op1], op2
        s += ida_lines.COLSTR('[', ida_lines.SCOLOR_SYMBOL) + opstr[0]
        s += ida_lines.COLSTR('+', ida_lines.SCOLOR_SYMBOL) + opstr[1]
        s += ida_lines.COLSTR('], ', ida_lines.SCOLOR_SYMBOL) + opstr[2]
    elif ins.base.name == 'ldd':
        # op0, [op1, op2]
        s += opstr[0]
        s += ida_lines.COLSTR(', ', ida_lines.SCOLOR_SYMBOL)
        s += ida_lines.COLSTR('[', ida_lines.SCOLOR_SYMBOL)
        s += opstr[1]
        s += ida_lines.COLSTR('+', ida_lines.SCOLOR_SYMBOL)
        s += opstr[2]
        s += ida_lines.COLSTR(']', ida_lines.SCOLOR_SYMBOL)
    else:
        for i, op in enumerate(ins.operands):
            # chr(cvar.COLOR_ADDR+i+1)
            color = ida_lines.SCOLOR_DNUM
            if op.is_register():
                color = ida_lines.SCOLOR_REG
            s += ida_lines.COLSTR(f'{str(op)}', color)
            if i+1 != len(ins.operands):
                s += ida_lines.COLSTR(', ', ida_lines.SCOLOR_SYMBOL)
    imm = 0
    for i, op in enumerate(ins.operands):
        if op.is_immediate() and op.imm().ival > imm:
            imm = op.imm().ival
    if imm > 0:
        if is_strlit(get_flags(imm)):
            content = get_strlit_contents(imm, -1, get_str_type(imm))
            comment += str(content[:30])
        else:
            comment += ida_name.get_name(imm)
    if comment:
        s += ida_lines.COLSTR(' ; '+comment, ida_lines.SCOLOR_AUTOCMT)
    return s


def remove_suffix(_s: str, _suffix: str):
    # polyfill with Python 3.9- : str.removesuffix
    try:
        return _s.removesuffix(_suffix)
    except AttributeError:
        return _s[:-len(_suffix)] if _suffix and _s.endswith(_suffix) else _s


class MyGraph(ida_graph.GraphViewer):
    def __init__(self, title):
        self.list_vip = []
        self.focus = True
        self.title = title
        self.rtn: vtil.routine = None
        ida_graph.GraphViewer.__init__(self, self.title, True)
        self.color = 0xffffff
        self.jump_to_desc = ida_kernwin.action_desc_t(
            f"graph_{title}:jumpto", "jumpto", JumptoAction(self), "G", "")
        ida_kernwin.register_action(self.jump_to_desc)

    def OnActivate(self):
        self.focus = True

    def OnDeactivate(self):
        self.focus = False

    def OnRefresh(self):
        self.Clear()
        self.list_vip = []
        if self.rtn is None:
            return True
        for vip, b in self.rtn.explored_blocks.items():
            b: vtil.basic_block
            s = hex(vip)+':\n'
            for i in b:
                i: vtil.instruction
                _prefix = f'[{i.sp_index:>2}] ' if i.sp_index > 0 else '     '
                x = '>' if i.sp_reset > 0 else ' '
                x += '+' if i.sp_offset > 0 else '-'
                x += hex(abs(i.sp_offset))
                _prefix += f'{x:<6} '
                if ida_ida.inf_show_line_pref():
                    s += ida_lines.COLSTR(_prefix, ida_lines.SCOLOR_PREFIX)
                s += instruction_tostring(i)+'\n'
            color = self.color
            self.AddNode((remove_suffix(s, '\n'), color))
            self.list_vip.append(vip)

        for vip, b in self.rtn.explored_blocks.items():
            s = self.list_vip.index(vip)
            # if b.size() > 0:
            #     back = b.back()
            #     if back.base.name == 'js':
            #         cond, dst1, dst2 = back.operands
            #         # op1 op2 is imm -> mark tbranch and fbranch
            #         if dst1.is_immediate() and dst2.is_immediate():
            #             # WTF? how to set edge color
            #             # SHIT! They ignore the `edge_info` parameter!
            # https://github.com/idapython/src/blob/3ce5b7f06dfdba36eb84d679c08248734a12036a/pywraps/py_graph.hpp#L431-L432
            #             self.AddEdge(s, list_vip.index(dst1.imm().u64)) # T
            #             self.AddEdge(s, list_vip.index(dst2.imm().u64)) # F
            #             continue

            for next_b in b.next:
                d = self.list_vip.index(next_b.entry_vip)
                self.AddEdge(s, d)
        return True

    def OnGetText(self, node_id):
        return self[node_id]

    def OnPopup(self, form, popup_handle):
        popup = collections.OrderedDict({
            'Refresh': GraphRefresh(self),
            'apply_all_profiled': GraphApplyAllProfiled(self),
            'Trace': GraphTrace(self),
            'Erase': GraphErase(self),
            'Load': GraphLoad(self),
            'Save': GraphSave(self),
        })
        for k, v in popup.items():
            ida_kernwin.attach_dynamic_action_to_popup(
                form, popup_handle,
                ida_kernwin.action_desc_t(k + ":" + self.title, k, v))

    def OnClose(self):
        print('close', self.GetWidget())
        ida_kernwin.detach_action_from_popup(
            self.GetWidget(), self.jump_to_desc.name)
        ida_kernwin.unregister_action(self.jump_to_desc.name)

    def OnHint(self, node_id):
        # cursor in title return [-1, -1]
        tmp = ida_kernwin.get_custom_viewer_place(
            ida_graph.get_graph_viewer(self.GetWidget()), True)
        if len(tmp) != 3:
            return 'node:'+str(node_id)
        place, _, _ = tmp
        return 'nid:'+str(node_id)+'lnnum:'+str(place.lnnum)

    def OnDblClick(self, node_id):
        """
        Triggerd when a node is double-clicked.
        @return: False to ignore the click and True otherwise
        """
        # print("dblclicked on", self[node_id])
        hl = ida_kernwin.get_highlight(self.GetWidget())
        if hl and hl[0].startswith('0x'):
            addr, flag = int(hl[0], 16), hl[1]
            if addr in self.list_vip:
                self.jumpto(self.list_vip.index(addr), 0)
            else:
                ida_kernwin.jumpto(addr)

        return True

    def jumpto(self, nid, lnnum):
        place = ida_graph.create_user_graph_place(nid, lnnum)
        ida_kernwin.jumpto(self.GetWidget(), place, -1, -1)


def show_graph(ea):
    widegt = ida_kernwin.find_widget(f'VTIL: {ea:016X}')
    if widegt:
        ida_kernwin.activate_widget(widegt, True)
        return None
    g = MyGraph(f'VTIL: {ea:016X}')
    root = os.path.join(idautils.GetIdbDir(), 'vms')
    if not os.path.exists(root):
        os.mkdir(root)
    premature = os.path.join(root, f'{ea:016X}.premature.vtil')
    optimized = os.path.join(root, f'{ea:016X}.optimized.vtil')
    if os.path.exists(optimized):
        print(f'Load VTIL from filecache {optimized}')
        g.rtn = vtil.routine.load(optimized)
    else:
        lifter = VMLifter()
        ida_kernwin.show_wait_box("lifting")
        try:
            lifter.lift_il(None, VMState(current_handler=ea))
            print('Saving premature')
            lifter.rtn.save(premature)
            ida_kernwin.replace_wait_box('apply_all_profiled')
            vtil.optimizer.apply_all_profiled(lifter.rtn)
            print('Saving optimized')
            lifter.rtn.save(optimized)
        finally:
            ida_kernwin.hide_wait_box()
        # vtil.debug.dump(lifter.rtn)
        g.rtn = lifter.rtn
    if g.Show():
        # jumpto(g.GetWidget(), ida_graph.create_user_graph_place(0,1), 0, 0)
        ida_graph.viewer_set_titlebar_height(g.GetWidget(), 15)
        # ida_graph.viewer_attach_menu_item(g.GetWidget(), )
        ida_kernwin.attach_action_to_popup(
            g.GetWidget(), None, g.jump_to_desc.name)
        return g
    else:
        return None
