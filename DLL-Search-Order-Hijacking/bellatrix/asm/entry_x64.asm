; entry stub.

bits 64
default rel

global bx_entry
extern bx_main

%define BX_SHADOW_BYTES 32
%define BX_CTX_BYTES    64

section .text

bx_entry:
    push  rbp
    mov   rbp, rsp
    push  rbx
    push  rsi
    push  rdi
    push  r12

    mov   r12, [gs:0x60]            ; TEB.ProcessEnvironmentBlock
    lea   rbx, [rel bx_entry]       ; blob anchor

    sub   rsp, BX_SHADOW_BYTES + BX_CTX_BYTES + 15
    and   rsp, -16                  ; the ABI wants 16 here

    ; zero the context before any field is written
    lea   rdi, [rsp + BX_SHADOW_BYTES]
    xor   eax, eax
    mov   ecx, BX_CTX_BYTES / 8
    rep   stosq

    lea   rdi, [rsp + BX_SHADOW_BYTES]
    mov   [rdi + 0], r12            ; ctx.peb
    mov   [rdi + 8], rbx            ; ctx.blob_base
    mov   qword [rdi + 16], 0       ; ctx.blob_size, unknown at entry

    mov   rcx, rdi
    call  bx_main

    xor   eax, eax
    lea   rsp, [rbp - 32]
    pop   r12
    pop   rdi
    pop   rsi
    pop   rbx
    pop   rbp
    ret
