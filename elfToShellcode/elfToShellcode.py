import sys
from pwn import *

context.arch = 'amd64'
context.bits = 64



def generateShellcode(elf_file, sysArgs, shellcodeFile):

    arg_list = ''
    
    id = 0
    for i in range(0, sysArgs.__len__()):
        argv = sysArgs[i]    
        arg_list += 'argv_{}:\n\t.ascii \"{}\"\n\t.byte 0x0\n'.format(id, argv)
        id += 1


    arg_list += 'argv_{}:\n\t.byte 0x0\n'.format(id)

    loader = ''

    loaderFile = os.path.join(Path(__file__).parent, 'loader_amd64')
    with open(loaderFile, "rb") as f:
        for b in f.read():
            loader += '0x%02x,' % b
        loader = loader.rstrip(',')


    with open(elf_file,"rb") as f:
        elf_data = f.read()

    sc = '''
    /*set args and argv*/
        xor rbp,rbp         /*argc*/
        
        lea rsi,[rip + argv_list]
        lea rdi,[rsp + 0x8]

    __setup_argv:

        mov al,byte ptr [rsi]
        test al,al
        jz __setup_argv_ok

        mov [rdi],rsi       
        add rdi,0x8
        inc rbp
        
        /* go to next string. */   
    _goto_next_argv:
        mov al,byte ptr [rsi]
        test al,al
        jz _goto_next_argv_ok
        inc rsi
        jmp _goto_next_argv
        
    _goto_next_argv_ok:
        inc rsi
        
        jmp __setup_argv

        
    __setup_argv_ok:
        lea rdi,[rip + elf]
        mov rsi,rbp
        mov [rsp],rbp
        
        lea rdx,[rsp + 0x8]
        
        xor rcx,rcx /*envp = NULL*/
        mov r8,rsp
        mov r9,0x1
        call x_execve

    x_execve:
    .byte {}

    argv_list:
    {}
        
    elf:
    '''.format(loader, arg_list)


    #print(sc)
    # open("/proc/self/fd/1","wb").write(asm(sc) + elf_data)

    shellcode = asm(sc) + elf_data
    with open(shellcodeFile, "wb") as file:
        file.write(shellcode)


def main():

    if sys.argv.__len__() < 3:
        print("Usage : %s <elf> <argv0> [argv...]", file=sys.stderr)
        exit(1)

    elf_file = sys.argv[1]

    shellcodeFile = "./shellcode"
    generateShellcode(elf_file, sys.argv[2:], shellcodeFile)


if __name__=="__main__":
    main()