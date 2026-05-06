proj = None
cc = None
simgr = None
FIRST_ADDR = 0x444f0000
cfg = None

ioctl_handler = 0
DriverStartIo = 0
phase = 1

controllable_buffers = ['SystemBuffer', 'Type3InputBuffer', 'UserBuffer', 'InputBufferLength', 'OutputBufferLength']
NPD_TARGETS = controllable_buffers

pools = ['ExAllocatePool_0x', 'ExAllocatePool2_0x', 'ExAllocatePool3_0x', 'ExAllocatePoolWithTag_0x', 'MmAllocateNonCachedMemory_0x', 'MmAllocateContiguousMemorySpecifyCache_0x']

free_pools_names = ['ExFreePoolWithTag_free', 'ExFreePool2_free', 'ExFreePool_free']
control_registers = ['cr0', 'cr2', 'cr3', 'cr4', 'cr8']
DO_NOTHING = 0


irp_addr = 0x69696900
irsp_addr = 0x67676700

SystemBuffer = None
Type3InputBuffer = None
UserBuffer = None

IoControlCode = None
OutputBufferLength = None
InputBufferLength = None

basic_info = {}


active_buffers = {}

freed_set = set()