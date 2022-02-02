from novmpy.bridge import *
from novmpy.vm_lifter import VMLifter
from novmpy.vm_lifter import search_vmstubs
from novmpy.vm import VMState
from pyvtil import *


def main():
    for jmp_rva, is_mid_routine in search_vmstubs():
        print(f'Lifting virtual-machine at 0x{jmp_rva:X}...')
        lifter = VMLifter()
        state = VMState(current_handler=bridge.get_base()+jmp_rva)
        lifter.lift_il(None, state)

        print(f'Saving premature')
        lifter.rtn.save('./test.premature.vtil')
        vtil.optimizer.apply_all_profiled(lifter.rtn)
        print(f'Saving optimized')
        lifter.rtn.save('./test.optimized.vtil')
        vtil.debug.dump(lifter.rtn)


if __name__ == '__main__':
    main()
