[BITS 64]

extern start

[SECTION .text]

    global init
    global get_peb
    global wsl_check_ntg

    init:
        push rdi
        mov rdi, rsp
        and rsp, -0x10
        sub rsp, 0x20

        call start

        mov rsp, rdi
        pop rdi
        ret

    get_peb:

        push rdi
        mov rdi, rsp
        sub rsp, 0x20
        
        xor rax, rax
        mov rax, gs:[0x60]

        mov rsp, rdi
        pop rdi
        ret

    wsl_check_ntg:

        push rdi
        mov rdi, rsp
        sub rsp, 0x20

        xor rax, rax
        mov rax, gs:[0x60]
        mov al, [rax+0xBC]
        
        and al, 0x70
        cmp al, 0x70
        jz wsl_bad_env

        xor rax, rax
        mov rsp, rdi
        pop rdi
        ret

    wsl_bad_env:
        xor rax, rax
        add al, 1
        mov rsp, rdi
        pop rdi
        ret

