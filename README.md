

# Current detected vulnerabilities

- Arbitrary Write
- Write NULL
- Arbitrary Physical memory mapping (MmMapIoSpace and ZwMapViewOfSection)
- Arbitrary process termination (Via ZwTerminateProcess)
- Buffer overflow detection (Both on pools and stack)
- Arbitrary MSR Registers R/W : rdmsr/wrmsr
- Arbitrary R/W of control registers (cr0-cr8)
- Arbitrary in/out
- Memory disclosure
- 



# TO:DO
- detect Use after free (If possible)
- Rewrite all UAF and double free logic (remove active_buffers from globals and put as state['active_buffers'])
- Figure something out to detect Race Condition
- Implement arbitrary file write detection (LPE)
- Implement arbitrary registry key manipulation detection
- Search for known CVEs and add.
- Improve performance and reliability, a lot
- Implement the IDA + LLM stuff, as a plugin
- implement if possible detection on linked lists, and other kernel structures
- Search for more dangerous APIs if called with arbitrary parameters 