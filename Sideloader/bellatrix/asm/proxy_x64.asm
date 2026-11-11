; carrier proxy trampolines.

bits 64
default rel

extern bx_proxy_once

extern bx_real_cor_create_ngen_process
extern bx_real_cor_get_ngen_policy
extern bx_real_cor_get_svc
extern bx_real_cor_init_svc_logger
extern bx_real_cor_set_critical_task_state
extern bx_real_cor_stop_non_critical_task
extern bx_real_cor_svc_log

section .text

%macro TRAMPOLINE 2
global %1
%1:
    push  rax
    push  rcx
    push  rdx
    push  r8
    push  r9
    push  r10
    push  r11
    sub   rsp, 48
    call  bx_proxy_once
    add   rsp, 48
    pop   r11
    pop   r10
    pop   r9
    pop   r8
    pop   rdx
    pop   rcx
    pop   rax
    cmp   qword [rel %2], 0
    je    %%fail
    jmp   qword [rel %2]
%%fail:
    xor   eax, eax
    ret
%endmacro

TRAMPOLINE CorCreateNGenProcess,     bx_real_cor_create_ngen_process
TRAMPOLINE CorGetNGenPolicy,         bx_real_cor_get_ngen_policy
TRAMPOLINE CorGetSvc,                bx_real_cor_get_svc
TRAMPOLINE CorInitSvcLogger,         bx_real_cor_init_svc_logger
TRAMPOLINE CorSetCriticalTaskState,  bx_real_cor_set_critical_task_state
TRAMPOLINE CorStopNonCriticalTask,   bx_real_cor_stop_non_critical_task
TRAMPOLINE CorSvcLog,                bx_real_cor_svc_log
