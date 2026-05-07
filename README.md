

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