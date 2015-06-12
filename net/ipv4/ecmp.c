#include <net/ecmp.h>
#include <linux/string.h>
#include <linux/in.h>
#include <linux/jhash.h>
#include <linux/sysctl.h>
#include <linux/jiffies.h>
#include <net/ip_fib.h>


char ecmp_alg [] = "hash-threshold";

extern u8 current_ecmp_alg;

/*
 *
 * defined in linux/sysctl.h
 *
 * A sysctl table is an array of struct ctl_table:
 * struct ctl_table
 * {
 *         const char *procname;          Text ID for /proc/sys, or zero
 *         void *data;
 *         int maxlen;
 *         umode_t mode;
 *         struct ctl_table *child;        Deprecated
 *         proc_handler *proc_handler;     Callback for text formatting
 *         struct ctl_table_poll *poll;
 *         void *extra1;
 *         void *extra2;
 * };
 */

static inline int proc_ecmp_alg(struct ctl_table *ctl, int write,
                                void __user * buffer, size_t *lenp, loff_t *ppos)
{
    int ret, i;
    strncpy(ctl->data, ecmp_alg, ctl->maxlen);
    ret = proc_dosctring(ctl, write, buffer, lenp, ppos);

    if (write && !ret){
        strncpy(ecmp_alg, ctl->data, ctl->maxlen);

        for (i= ECMP_DISABLED; i < ECMP_ALGS_COUNT; i++){
            current_ecmp_alg = i;
            break;
        }
    }
    return ret;
}


static inline u32 ecmp_hash(const struct flowi4 *flow)
{

    /* __be16  16-bit value in big-endian byte order
     *
     * static inline void flowi4_init_output(struct flowi4 *fl4, int oif,
                                           __u32 mark, __u8 tos, __u8 scope,
                                           __u8 proto, __u8 flags,
                                           __be32 daddr, __be32 saddr,
       {
               fl4->flowi4_oif = oif;
               fl4->flowi4_iif = LOOPBACK_IFINDEX;
               fl4->flowi4_mark = mark;
               fl4->flowi4_tos = tos;
               fl4->flowi4_scope = scope;
               fl4->flowi4_proto = proto;
               fl4->flowi4_flags = flags;
               fl4->flowi4_secid = 0;
               fl4->daddr = daddr;
               fl4->saddr = saddr;
               fl4->fl4_dport = dport;
               fl4->fl4_sport = sport;
        }
     *
     */

    /* jhash.h: Jenkins hash support.
     *
     * Copyright (C) 2006. Bob Jenkins (bob_jenkins@burtleburtle.net)
     *
     * http://burtleburtle.net/bob/hash/
     *
     * These are the credits from Bob's sources:
     *
     * lookup3.c, by Bob Jenkins, May 2006, Public Domain.
     *
     * These are functions for producing 32-bit hashes for hash table lookup.
     * hashword(), hashlittle(), hashlittle2(), hashbig(), mix(), and final()
     * are externally useful functions.  Routines to test the hash are included
     * if SELF_TEST is defined.  You can use this free for any purpose.  It's in
     * the public domain.  It has no warranty.
     *
     * Copyright (C) 2009-2010 Jozsef Kadlecsik (kadlec@blackhole.kfki.hu)
     *
     * I've modified Bob's hash to be useful in the Linux kernel, and
     * any bugs present are my fault.
     * Jozsef
     *
     * static inline u32 jhash_3words(u32 a, u32 b, u32 c, u32 initval)
     * static inline u32 jhash_2words(u32 a, u32 b, u32 initval)
     * static inline u32 jhash_1word(u32 a, u32 initval)
     * static inline u32 jhash2(const u32 *k, u32 length, u32 initval)
     * static inline u32 jhash(const void *key, u32 length, u32 initval)
     */

    u32 hash;
    u8 * protocol;

    *protocol = flow->flowi4_proto;
    hash = jhash_3words(flow->saddr, flow->daddr, *protocol, 0);

    /* IPPROTO_UDP, IPROTO_TCP are defined in linux/in.h
     *
     *
     *   IPPROTO_TCP = 6,   Transmission Control Protocol
     *   IPPROTO_UDP = 17,  User Datagram Protocol
     *
     */

    if (*protocol == IPPROTO_TCP || *protocol == IPPROTO_UDP){
        hash = jhash_2words(flow->fl4_sport, flow->fl4_dport, hash);
    }

    return hash;

}


static struct ctl_table net_ipv4_ecmp_alg [] = {
        {
                .procname       = "ecmp_alg",
                .data           = &ecmp_alg,
                .maxlen         = ECMP_ALGS_COUNT,
                .mode           = 0644,
                .proc_handler   = proc_ecmp_alg,
        },
        {},
};


static inline u8 ecmp_hash_threshold(u32 * hash, struct fib_info *fi)
{
    return (u8)(*hash / (U32_MAX / fi->fib_nhs));
}

static inline u8 ecmp_hrw(u32 * hash, struct fib_info * fi)
{

    u32 best_weight, weight;
    u8 best_link = 0;
    u8 link = best_link;

    /* setup the best weight for the first link */
    best_weight = hash_2words(*hash, link, 0);

    for(link = 1; link < fi->fib_nhs; link++){
        weight = hash_2words(*hash, link, 0);
        if (weight > best_weight){
            best_link = link;
            best_weight = weight;
        }
    }

    return best_link;
}

static inline u8 ecmp_modulo_n(u32 * hash, struct fib_info *fi)
{
    return (*hash % fi->fib_nhs);
}

static inline u8 ecmp_default(struct fib_info *fi)
{
    u8 w = 0;
    u8 nhsel;

    struct fib_nh *nexthop_nh;

    if (fi->fib_power <= 0) {
        int power = 0;
        for (nhsel = 0,	nexthop_nh = (struct fib_nh *)((fi)->fib_nh);
	         nhsel < (fi)->fib_nhs; nexthop_nh++, nhsel++)
                if (!(nexthop_nh->nh_flags & RTNH_F_DEAD)) {
                    power += nexthop_nh->nh_weight;
                    nexthop_nh->nh_power = nexthop_nh->nh_weight;
                }
        fi->fib_power = power;
        if (power <= 0) {
            // spin_unlock_bh(&fib_multipath_lock);
            /* Race condition: route has just become dead. */
            // res->nh_sel = 0;
            return 0;
        }
    }

    /* w should be random number [0..fi->fib_power-1],
     * it is pretty bad approximation.
     */

    w = jiffies % fi->fib_power;

    for (nhsel = 0,	nexthop_nh = (struct fib_nh *)((fi)->fib_nh);
         nhsel < (fi)->fib_nhs; nexthop_nh++, nhsel++)
            if (!(nexthop_nh->nh_flags & RTNH_F_DEAD) &&
                nexthop_nh->nh_power) {
                w -= nexthop_nh->nh_power;
                if (w <= 0) {
                    nexthop_nh->nh_power--;
                    fi->fib_power--;
                    // res->nh_sel = nhsel;
                    return nhsel;
                }
            }

    /* Race condition: route has just become dead. */
    //res->nh_sel = 0;
    return 0;
}

int ecmp_init(void)
{
    sysctl_table_hdr = register_net_sysctl(&init_net, "net/ipv4",net_ipv4_ecmp_alg);

    if(!sysctl_table_hdr){

        return -2;
    }

    return 0;
}

void ecmp_cleanup(void)
{
    unregister_sysctl_table(sysctl_table_hdr);
}



