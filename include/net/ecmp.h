#ifndef _EMCP_H
#define _ECMP_H

#include <net/ip_fib.h>
#include <net/flow.h>

#define ECMP_ALG_MAXLEN 32;

/* ECMP algorithms */

enum {
    ECMP_DISABLED,
    ECMP_HASH_THRESHOLD,
    ECMP_HRW,
    ECMP_MODULO_N,
    ECMP_DEFAULT,
    ECMP_ALGS_COUNT
};

/* sysctl header */
extern u8 current_ecmp_alg;

int proc_ecmp_alg(struct ctl_table *ctl_tbl, int write,
                          void __user * buffer, size_t *lenp, loff_t *ppos);
u32 ecmp_hash(const struct flowi4 *flow);
u8 ecmp_hash_threshold(u32 * hash, struct fib_info *fi);
u8 ecmp_hrw(u32 * hash, struct fib_info * fi);
u8 ecmp_modulo_n(u32 * hash, struct fib_info *fi);
u8 ecmp_default(struct fib_info *fi);

int ecmp_init(void);
void ecmp_cleanup(void);

#endif /* _ECMP_H */

