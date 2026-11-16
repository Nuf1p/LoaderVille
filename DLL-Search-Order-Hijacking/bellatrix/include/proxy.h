/* carrier proxy contract */
#ifndef BELLATRIX_PROXY_H
#define BELLATRIX_PROXY_H

/* Resolve the real module and run the payload. Safe to call repeatedly. */
void bx_proxy_once(void);

/* Trampoline destinations. NULL when the real module could not be reached. */
extern void *bx_real_cor_create_ngen_process;
extern void *bx_real_cor_get_ngen_policy;
extern void *bx_real_cor_get_svc;
extern void *bx_real_cor_init_svc_logger;
extern void *bx_real_cor_set_critical_task_state;
extern void *bx_real_cor_stop_non_critical_task;
extern void *bx_real_cor_svc_log;

#endif /* BELLATRIX_PROXY_H */
