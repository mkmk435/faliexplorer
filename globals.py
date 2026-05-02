proj = None
cc = None
simgr = None
FIRST_ADDR = 0x10000000
cfg = None

controllable_buffers = ['SystemBuffer', 'Type3InputBuffer', 'UserBuffer']
NPD_TARGETS = controllable_buffers

irp_addr = 0x69696900
irsp_addr = 0x67676700

SystemBuffer = None
Type3InputBuffer = None
UserBuffer = None

IoControlCode = None
OutputBufferLength = None
InputBufferLength = None