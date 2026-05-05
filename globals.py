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