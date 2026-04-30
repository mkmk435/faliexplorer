import angr
import claripy
import utils
import globals



# Praticamente crea un Handle come variabile simbolica
class HookZwOpenSection(angr.SimProcedure):
    def run(self, SectionHandle, DesiredAccess, ObjectAttributes):
        print("Dentro ZwOpenSection Function hook")
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
                print(f"IOCTL: {self.state.solver.eval(globals.IoControlCode)}")
            else:
                handles = dict(self.state.globals['open_section_handles'])
                if SectionHandle not in handles:
                    print('map physical memory', 'ZwMapViewOfSection - unknown handle')
                    print(f"IOCTL: {hex(self.state.solver.eval(globals.IoControlCode))}")
                    # utils.print_vuln('map physical memory', 'ZwMapViewOfSection - unknown handle', self.state, {'SectionHandle': str(SectionHandle), 'ProcessHandle': str(ProcessHandle), 'BaseAddress': str(BaseAddress), 'CommitSize': str(CommitSize), 'ViewSize': str(ViewSize)}, {'return address': ret_addr})
                elif handles[SectionHandle] == '\\Device\\PhysicalMemory':
                    print('map physical memory', 'ZwMapViewOfSection - map \\Device\\PhysicalMemory')
                    # utils.print_vuln('map physical memory', 'ZwMapViewOfSection - map \\Device\\PhysicalMemory', self.state, {'SectionHandle': str(SectionHandle), 'ProcessHandle': str(ProcessHandle), 'BaseAddress': str(BaseAddress), 'CommitSize': str(CommitSize), 'ViewSize': str(ViewSize)}, {'return address': ret_addr})
                    print(f"IOCTL: {hex(self.state.solver.eval(globals.IoControlCode))}")
        return 0

# semplice reimplementazione della funzione originale
class HookHalTranslateBusAddress(angr.SimProcedure):
    def run(self, InterfaceType, BusNumber, BusAddress, AddressSpace, TranslatedAddress):
        self.state.memory.store(TranslatedAddress, BusNumber + BusAddress, self.state.arch.bytes, endness=self.state.arch.memory_endness, disable_actions=True, inspect=False)
        return 1
            

class HookIoCreateDevice(angr.SimProcedure):
    def run(self, DriverObject, DeviceExtensionSize, DeviceName, DeviceType, DeviceCharacteristics, Exclusive, DeviceObject):
        # Initialize device object.
        devobjaddr = utils.next_base_addr()
        self.state.globals['device_object_addr'] = devobjaddr
        device_object = claripy.BVS('device_object', 8 * 0x400)
        self.state.memory.store(devobjaddr, device_object, 0x400, disable_actions=True, inspect=False)
        self.state.mem[devobjaddr].DEVICE_OBJECT.Flags = 0
        self.state.mem[DeviceObject].PDEVICE_OBJECT = devobjaddr

        # Initialize device extension.
        new_device_extension_addr = utils.next_base_addr()
        size = self.state.solver.min(DeviceExtensionSize)
        device_extension = claripy.BVV(0, 8 * size)
        self.state.memory.store(new_device_extension_addr, device_extension, size, disable_actions=True, inspect=False)
        self.state.mem[devobjaddr].DEVICE_OBJECT.DeviceExtension = new_device_extension_addr

        # Retrieve the device name.
        device_name_str = utils.read_buffer_from_unicode_string(self.state, DeviceName)
        if (device_name_str == "") or (device_name_str == None):
            return 0
        
        utils.print_info(f'device name: {device_name_str}')
        if "DeviceName" not in globals.basic_info:
            globals.basic_info["DeviceName"] = []
        
        if(device_name_str not in globals.basic_info["DeviceName"]):
            globals.basic_info["DeviceName"].append(device_name_str)
        return 0

# Semplicemente prende in input symlink name e Device name e se li salva in globals.basic_info
class HookIoCreateSymbolicLink(angr.SimProcedure):
    def run(self, SymbolicLinkName, DeviceName):
        # Retrieve the symbolic link name.
        device_name_str = utils.read_buffer_from_unicode_string(self.state, DeviceName)
        if (device_name_str == "") or (device_name_str is None):
            return 0
        
        symbolic_link_str = utils.read_buffer_from_unicode_string(self.state, SymbolicLinkName)
        if (symbolic_link_str == "") and (symbolic_link_str == None):
            return 0
        
        utils.print_info(f'Symbolic link \"{symbolic_link_str}\" to \"{device_name_str}\"')

        if "SymbolicLink" not in globals.basic_info:
            globals.basic_info["SymbolicLink"] = []

        if(symbolic_link_str not in globals.basic_info["SymbolicLink"]):
            globals.basic_info["SymbolicLink"].append(symbolic_link_str)
        return 0


# ObReferenceObjectByHandle serve a 'usare' un oggetto dato un handle. allora l'hook simbolizza l'oggetto e lo mette in memoria
# inoltre controlla se l'handle all' oggetto e' tainted, se si' alloraq aggiunge ad una lista di tainted_eprocess
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


# 
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
