# idapython fix <= 7.6
# DO NOT REMOVE ME
import sys
sys.stdout.encoding = 'utf-8'


# for test
# ida_loader.load_plugin('F:/NoVmpy/novmpy.py')
import idaapi
from novmpy.ui import UIManager

NOVMPY_VERSION = "0.1"


class NoVmpyPlugin(idaapi.plugin_t):
    flags = 0
    comment = ""
    help = ""
    wanted_name = "NoVmpy"
    wanted_hotkey = ""

    def __init__(self):
        super(NoVmpyPlugin, self).__init__()

    def init(self):
        self.ui = UIManager()

        return idaapi.PLUGIN_KEEP

    def run(self, args):
        pass

    def term(self):
        from novmpy.handler import vm_handlers
        vm_handlers.clear()


def PLUGIN_ENTRY():
    return NoVmpyPlugin()
