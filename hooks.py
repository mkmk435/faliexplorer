import angr
import claripy
import utils
import globals


class HookZwMapViewOfSection(angr.SimProcedure):
    def run(self, SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect):
        if globals.phase == 2:
            # Check if we can control the parameters of ZwMapViewOfSection.
            if SectionHandle.symbolic and (ProcessHandle.symbolic or self.state.solver.eval(ProcessHandle == -1) or BaseAddress.symbolic or (CommitSize.symbolic and ViewSize.symbolic)):
                ret_addr = hex(self.state.callstack.ret_addr)
                if any('ZwOpenSection' not in v for v in SectionHandle.variables):
                    # utils.print_vuln('map physical memory', 'ZwMapViewOfSection - SectionHandle controllable', self.state, {'SectionHandle': str(SectionHandle), 'ProcessHandle': str(ProcessHandle), 'BaseAddress': str(BaseAddress), 'CommitSize': str(CommitSize), 'ViewSize': str(ViewSize)}, {'return address': ret_addr})
                    print("map physical memory', 'ZwMapViewOfSection - SectionHandle controllable")
                else:
                    handles = dict(self.state.globals['open_section_handles'])
                    if SectionHandle not in handles:
                        print('map physical memory', 'ZwMapViewOfSection - unknown handle')
                        # utils.print_vuln('map physical memory', 'ZwMapViewOfSection - unknown handle', self.state, {'SectionHandle': str(SectionHandle), 'ProcessHandle': str(ProcessHandle), 'BaseAddress': str(BaseAddress), 'CommitSize': str(CommitSize), 'ViewSize': str(ViewSize)}, {'return address': ret_addr})
                    elif handles[SectionHandle] == '\\Device\\PhysicalMemory':
                        print('map physical memory', 'ZwMapViewOfSection - map \\Device\\PhysicalMemory')
                        # utils.print_vuln('map physical memory', 'ZwMapViewOfSection - map \\Device\\PhysicalMemory', self.state, {'SectionHandle': str(SectionHandle), 'ProcessHandle': str(ProcessHandle), 'BaseAddress': str(BaseAddress), 'CommitSize': str(CommitSize), 'ViewSize': str(ViewSize)}, {'return address': ret_addr})
        return 0
            