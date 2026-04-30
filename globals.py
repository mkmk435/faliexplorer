proj = None
cfg = None

FIRST_ADDR = 0x444f0000

mycc = None

irp_addr = 0x696969
irsp_addr = 0x420420

simgr = None

NPD_TARGETS = ['SystemBuffer', 'Type3InputBuffer', 'UserBuffer', 'ExAllocatePool_0x', 'ExAllocatePool2_0x', 'ExAllocatePool3_0x', 'ExAllocatePoolWithTag_0x', 'MmAllocateNonCachedMemory_0x', 'MmAllocateContiguousMemorySpecifyCache_0x']


args = None

vulns_unique = set()
vulns_info = []



SystemBuffer = None
Type3InputBuffer = None
UserBuffer = None
InputBufferLength = None
OutputBufferLength = None
IoControlCode = None