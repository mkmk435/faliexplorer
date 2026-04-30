import angr
import claripy
import utils
import globals



class HookZwOpenSection(angr.SimProcedure):
    def run(self, SectionHandle, DesiredAccess, ObjectAttributes):
        print("Dentro ZwMapViewOfFunction hook")
        ret_addr = hex(self.state.callstack.ret_addr)

        # Trace the handle opened by ZwOpenSection.
        handle = claripy.BVS(f'ZwOpenSection_{ret_addr}', self.state.arch.bits)
        self.state.memory.store(SectionHandle, handle, self.state.arch.bytes, endness=self.state.arch.memory_endness, disable_actions=True, inspect=False)

        # Get the object name.
        object_name_struct = self.state.mem[ObjectAttributes].OBJECT_ATTRIBUTES.ObjectName.deref
        try:
            object_name = object_name_struct.Buffer.deref.wstring.concrete
        except:
            return 0

        # Store the handle and object name.
        self.state.globals['open_section_handles'] += ((handle, object_name),)
        return 0

class HookZwMapViewOfSection(angr.SimProcedure):
    def run(self, SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect):
        # if globals.phase == 2:
        print("Dentro ZwMapViewOfFunction hook")

        # Check if we can control the parameters of ZwMapViewOfSection.
        # print(SectionHandle.symbolic)
        print(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect)

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
            

class HookObReferenceObjectByHandle(angr.SimProcedure):
    # Trace the handle opened by ObReferenceObjectByHandle.
    def run(self, Handle, DesiredAccess, ObjectType, AccessMode, Object, HandleInformation):
        ret_addr = hex(self.state.callstack.ret_addr)
        object = claripy.BVS(f"ObReferenceObjectByHandle_{ret_addr}", self.state.arch.bits)
        self.state.memory.store(Object, object, self.state.arch.bytes, endness=self.state.arch.memory_endness, disable_actions=True, inspect=False)

        # With a tainted handle referencing a process, we propagate the taint to the newly created "object"
        if (globals.star_ps_process_type is not None) and self.state.solver.eval(ObjectType == globals.star_ps_process_type) and utils.tainted_buffer(Handle):
            self.state.globals['tainted_eprocess'] += (str(object), )
        return 0


class HookRtlInitUnicodeString(angr.SimProcedure):
    def run(self, DestinationString, SourceString):
        ret_addr = hex(self.state.callstack.ret_addr)
        
        # Resolve the SourceString.
        try:
            if SourceString.symbolic and utils.tainted_buffer(SourceString):
                raise
            string_orig = self.state.mem[SourceString].wstring.resolved
        except:
            string_orig = claripy.Concat(claripy.BVS(f"RtlInitUnicodeString_{ret_addr}", 8 * 10), claripy.BVV(0, 16))

        # Initalize the DestinationString.
        byte_length = string_orig.length // 8
        new_buffer = utils.next_base_addr()
        self.state.memory.store(new_buffer, string_orig, byte_length, disable_actions=True, inspect=False)
        unistr = self.state.mem[DestinationString].struct._UNICODE_STRING
        self.state.memory.store(DestinationString, claripy.BVV(0, unistr._type.size), unistr._type.size // 8, disable_actions=True, inspect=False)
        unistr.Length = byte_length
        unistr.MaximumLength = byte_length
        unistr.Buffer = new_buffer

        # Store the unicode string if it is tainted.
        if (not SourceString.symbolic and utils.tainted_buffer(self.state.memory.load(SourceString, 0x10, disable_actions=True, inspect=False))) or utils.tainted_buffer(SourceString) or str(SourceString) in self.state.globals['tainted_unicode_strings']:
            self.state.globals['tainted_unicode_strings'] += (str(unistr.Buffer.resolved), )

        return 0
