#ifndef _EMCP_H
#define _ECMP_H

#include <linux/string.h>
#include <linux/in.h>
#include <net/ecmp.h>
#include <linux/jhash.h>
#include <linux/sysctl.h>
#include <net/ip_fib.h>


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
struct ctl_table_header *sysctl_table_hdr = NULL;


u8 current_ecmp_alg = ECMP_HASH_THRESHOLD;

EXPORT_SYMBOL_GPL(current_ecmp_alg);

const char *ecmp_alg[ECMP_MODES_COUNT] = {
        "disabled",
        "hash-threshold",
        "hrw",
        "modulo-n",
        "default"
};

static int proc_ecmp_alg(ctl_table *ctl_tbl, int write,
                          void __user *buffer, size_t *lenp, loff_t *ppos);

static u8 ecmp_hash_threshold(u32 * hash, fib_info *fi);

static u8 ecmp_hrw(u32 * hash, fib_info * fi);

static u8 ecmp_modulo_n(u32 * hash, fib_info *fi);

static u8 ecmp_default(fib_info *fi);

int ecmp_init(void);

void ecmp_cleanup(void);

#endif /* _ECMP_H */

