

#ifndef _IPV6_H
#define _IPV6_H

#include <uapi/linux/ipv6.h>

#define ipv6_optlen(p) (((p)->hdrlen+1) << 3)
#define ipv6_authlen(p) (((p)->hdrlen+2) << 2)
/*
 * This structure contains configuration options per IPv6 link.
 */
struct ipv6_devconf {
	__s32		forwarding;
	__s32		hop_limit;
	__s32		mtu6;
	__s32		accept_ra;
	__s32		accept_redirects;
	__s32		autoconf;
	__s32		dad_transmits;
	__s32		rtr_solicits;
	__s32		rtr_solicit_interval;
	__s32		rtr_solicit_delay;
	__s32		force_mld_version;
	__s32		mldv1_unsolicited_report_interval;
	__s32		mldv2_unsolicited_report_interval;
	__s32		use_tempaddr;
	__s32		temp_valid_lft;
	__s32		temp_prefered_lft;
	__s32		regen_max_retry;
	__s32		max_desync_factor;
	__s32		max_addresses;
	__s32		accept_ra_defrtr;
	__s32		accept_ra_min_hop_limit;
	__s32		accept_ra_pinfo;
	__s32		ignore_routes_with_linkdown;
#ifdef CONFIG_IPV6_ROUTER_PREF
	__s32		accept_ra_rtr_pref;
	__s32		rtr_probe_interval;
#ifdef CONFIG_IPV6_ROUTE_INFO
	__s32		accept_ra_rt_info_max_plen;
#endif
#endif
	__s32		proxy_ndp;
	__s32		accept_source_route;
	__s32		accept_ra_from_local;
#ifdef CONFIG_IPV6_OPTIMISTIC_DAD
	__s32		optimistic_dad;
	__s32		use_optimistic;
#endif
#ifdef CONFIG_IPV6_MROUTE
	__s32		mc_forwarding;
#endif
	__s32		disable_ipv6;
	__s32		accept_dad;
	__s32		force_tllao;
	__s32           ndisc_notify;
	__s32		suppress_frag_ndisc;
	__s32		accept_ra_mtu;
	struct ipv6_stable_secret {
		bool initialized;
		struct in6_addr secret;
	} stable_secret;
	__s32		use_oif_addrs_only;
	void		*sysctl;
};

struct ipv6_params {
	__s32 disable_ipv6;
	__s32 autoconf;
};
extern struct ipv6_params ipv6_defaults;
#include <linux/icmpv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <net/inet_sock.h>

static inline struct ipv6hdr *ipv6_hdr(const struct sk_buff *skb)
{
	return (struct ipv6hdr *)skb_network_header(skb);
}

static inline struct ipv6hdr *inner_ipv6_hdr(const struct sk_buff *skb)
{
	return (struct ipv6hdr *)skb_inner_network_header(skb);
}

static inline struct ipv6hdr *ipipv6_hdr(const struct sk_buff *skb)
{
	return (struct ipv6hdr *)skb_transport_header(skb);
}

/* 
 This structure contains results of exthdrs parsing
 as offsets from skb->nh.
 */

struct inet6_skb_parm {
	int			iif;
	__be16			ra;
	__u16			dst0;
	__u16			srcrt;
	__u16			dst1;
	__u16			lastopt;
	__u16			nhoff;
	__u16			flags;
#if defined(CONFIG_IPV6_MIP6) || defined(CONFIG_IPV6_MIP6_MODULE)
	__u16			dsthao;
#endif
	__u16			frag_max_size;

#define IP6SKB_XFRM_TRANSFORMED 1
#define IP6SKB_FORWARDED 2
#define IP6SKB_REROUTED 4
#define IP6SKB_ROUTERALERT 8
#define IP6SKB_FRAGMENTED 16
#define IP6SKB_HOPBYHOP 32
};

#define IP6CB(skb) ((struct inet6_skb_parm*)((skb)->cb))
#define IP6CBMTU(skb) ((struct ip6_mtuinfo *)((skb)->cb))

static inline int inet6_iif(const struct sk_buff *skb)
{
	return IP6CB(skb)->iif;
}

struct tcp6_request_sock {
	struct tcp_request_sock	  tcp6rsk_tcp;
};

struct ipv6_mc_socklist;
struct ipv6_ac_socklist;
struct ipv6_fl_socklist;

struct inet6_cork {
	struct ipv6_txoptions *opt;
	u8 hop_limit;
	u8 tclass;
};

/**
 * struct ipv6_pinfo - ipv6 private area
 *
 * In the struct sock hierarchy (tcp6_sock, upd6_sock, etc)
 * this _must_ be the last member, so that inet6_sk_generic
 * is able to calculate its offset from the base struct sock
 * by using the struct proto->slab_obj_size member. -acme
 */
struct ipv6_pinfo {
	struct in6_addr 	saddr;
	struct in6_pktinfo	sticky_pktinfo;
	const struct in6_addr		*daddr_cache;
#ifdef CONFIG_IPV6_SUBTREES
	const struct in6_addr		*saddr_cache;
#endif

	__be32			flow_label;
	__u32			frag_size;

	/*
 * Packed in 16bits.
 * Omit one shift by by putting the signed field at MSB.
 */
#if defined(__BIG_ENDIAN_BITFIELD)
	__s16			hop_limit:9;
	__u16			__unused_1:7;
#else
	__u16			__unused_1:7;
	__s16			hop_limit:9;
#endif

#if defined(__BIG_ENDIAN_BITFIELD)
	/* Packed in 16bits. */
	__s16			mcast_hops:9;
	__u16			__unused_2:6,
				mc_loop:1;
#else
	__u16			mc_loop:1,
				__unused_2:6;
	__s16			mcast_hops:9;
#endif
	int			ucast_oif;
	int			mcast_oif;

	/* pktoption flags */
	union {
		struct {
			__u16	srcrt:1,
				osrcrt:1,
			        rxinfo:1,
			        rxoinfo:1,
				rxhlim:1,
				rxohlim:1,
				hopopts:1,
				ohopopts:1,
				dstopts:1,
				odstopts:1,
                                rxflow:1,
				rxtclass:1,
				rxpmtu:1,
				rxorigdstaddr:1;
				/* 2 bits hole */
		} bits;
		__u16		all;
	} rxopt;

	/* sockopt flags */
	__u16			recverr:1,
	                        sndflow:1,
				repflow:1,
				pmtudisc:3,
				padding:1,	/* 1 bit hole */
				srcprefs:3,	/* 001: prefer temporary address
 * 010: prefer public address
 * 100: prefer care-of address
 */
				dontfrag:1,
				autoflowlabel:1;
	__u8			min_hopcount;
	__u8			tclass;
	__be32			rcv_flowinfo;

	__u32			dst_cookie;
	__u32			rx_dst_cookie;

	struct ipv6_mc_socklist	__rcu *ipv6_mc_list;
	struct ipv6_ac_socklist	*ipv6_ac_list;
	struct ipv6_fl_socklist __rcu *ipv6_fl_list;

	struct ipv6_txoptions	*opt;
	struct sk_buff		*pktoptions;
	struct sk_buff		*rxpmtu;
	struct inet6_cork	cork;
};

/* WARNING: don't change the layout of the members in {raw,udp,tcp}6_sock! */
struct raw6_sock {
	/* inet_sock has to be the first member of raw6_sock */
	struct inet_sock	inet;
	__u32			checksum;	/* perform checksum */
	__u32			offset;		/* checksum offset */
	struct icmp6_filter	filter;
	__u32			ip6mr_table;
	/* ipv6_pinfo has to be the last member of raw6_sock, see inet6_sk_generic */
	struct ipv6_pinfo	inet6;
};

struct udp6_sock {
	struct udp_sock	  udp;
	/* ipv6_pinfo has to be the last member of udp6_sock, see inet6_sk_generic */
	struct ipv6_pinfo inet6;
};

struct tcp6_sock {
	struct tcp_sock	  tcp;
	/* ipv6_pinfo has to be the last member of tcp6_sock, see inet6_sk_generic */
	struct ipv6_pinfo inet6;
};

extern int inet6_sk_rebuild_header(struct sock *sk);

struct tcp6_timewait_sock {
	struct tcp_timewait_sock   tcp6tw_tcp;
};

#if IS_ENABLED(CONFIG_IPV6)
static inline struct ipv6_pinfo *inet6_sk(const struct sock *__sk)
{
	return sk_fullsock(__sk) ? inet_sk(__sk)->pinet6 : NULL;
}

static inline struct raw6_sock *raw6_sk(const struct sock *sk)
{
	return (struct raw6_sock *)sk;
}

static inline void inet_sk_copy_descendant(struct sock *sk_to,
					   const struct sock *sk_from)
{
	int ancestor_size = sizeof(struct inet_sock);

	if (sk_from->sk_family == PF_INET6)
		ancestor_size += sizeof(struct ipv6_pinfo);

	__inet_sk_copy_descendant(sk_to, sk_from, ancestor_size);
}

#define __ipv6_only_sock(sk) (sk->sk_ipv6only)
#define ipv6_only_sock(sk) (__ipv6_only_sock(sk))
#define ipv6_sk_rxinfo(sk) ((sk)->sk_family == PF_INET6 && \
 inet6_sk(sk)->rxopt.bits.rxinfo)

static inline const struct in6_addr *inet6_rcv_saddr(const struct sock *sk)
{
	if (sk->sk_family == AF_INET6)
		return &sk->sk_v6_rcv_saddr;
	return NULL;
}

static inline int inet_v6_ipv6only(const struct sock *sk)
{
	/* ipv6only field is at same position for timewait and other sockets */
	return ipv6_only_sock(sk);
}
#else
#define __ipv6_only_sock(sk) 0
#define ipv6_only_sock(sk) 0
#define ipv6_sk_rxinfo(sk) 0

static inline struct ipv6_pinfo * inet6_sk(const struct sock *__sk)
{
	return NULL;
}

static inline struct inet6_request_sock *
			inet6_rsk(const struct request_sock *rsk)
{
	return NULL;
}

static inline struct raw6_sock *raw6_sk(const struct sock *sk)
{
	return NULL;
}

#define inet6_rcv_saddr(__sk) NULL
#define tcp_twsk_ipv6only(__sk) 0
#define inet_v6_ipv6only(__sk) 0
#endif /* IS_ENABLED(CONFIG_IPV6) */
#endif /* _IPV6_H */

/*
 * Linux INET6 implementation
 *
 * Authors:
 * Pedro Roque <roque@di.fc.ul.pt>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#ifndef _NET_IPV6_H
#define _NET_IPV6_H

#include <linux/ipv6.h>
#include <linux/hardirq.h>
#include <linux/jhash.h>
#include <net/if_inet6.h>
#include <net/ndisc.h>
#include <net/flow.h>
#include <net/flow_dissector.h>
#include <net/snmp.h>

#define SIN6_LEN_RFC2133 24

#define IPV6_MAXPLEN 65535

/*
 * NextHeader field of IPv6 header
 */

#define NEXTHDR_HOP 0	/* Hop-by-hop option header. */
#define NEXTHDR_TCP 6	/* TCP segment. */
#define NEXTHDR_UDP 17	/* UDP message. */
#define NEXTHDR_IPV6 41	/* IPv6 in IPv6 */
#define NEXTHDR_ROUTING 43	/* Routing header. */
#define NEXTHDR_FRAGMENT 44	/* Fragmentation/reassembly header. */
#define NEXTHDR_GRE 47	/* GRE header. */
#define NEXTHDR_ESP 50	/* Encapsulating security payload. */
#define NEXTHDR_AUTH 51	/* Authentication header. */
#define NEXTHDR_ICMP 58	/* ICMP for IPv6. */
#define NEXTHDR_NONE 59	/* No next header */
#define NEXTHDR_DEST 60	/* Destination options header. */
#define NEXTHDR_SCTP 132	/* SCTP message. */
#define NEXTHDR_MOBILITY 135	/* Mobility header. */

#define NEXTHDR_MAX 255

#define IPV6_DEFAULT_HOPLIMIT 64
#define IPV6_DEFAULT_MCASTHOPS 1

/*
 * Addr type
 * 
 * type - unicast | multicast
 * scope - local | site | global
 * v4 - compat
 * v4mapped
 * any
 * loopback
 */

#define IPV6_ADDR_ANY 0x0000U

#define IPV6_ADDR_UNICAST 0x0001U 
#define IPV6_ADDR_MULTICAST 0x0002U 

#define IPV6_ADDR_LOOPBACK 0x0010U
#define IPV6_ADDR_LINKLOCAL 0x0020U
#define IPV6_ADDR_SITELOCAL 0x0040U

#define IPV6_ADDR_COMPATv4 0x0080U

#define IPV6_ADDR_SCOPE_MASK 0x00f0U

#define IPV6_ADDR_MAPPED 0x1000U

/*
 * Addr scopes
 */
#define IPV6_ADDR_MC_SCOPE(a) \
 ((a)->s6_addr[1] & 0x0f)	/* nonstandard */
#define __IPV6_ADDR_SCOPE_INVALID -1
#define IPV6_ADDR_SCOPE_NODELOCAL 0x01
#define IPV6_ADDR_SCOPE_LINKLOCAL 0x02
#define IPV6_ADDR_SCOPE_SITELOCAL 0x05
#define IPV6_ADDR_SCOPE_ORGLOCAL 0x08
#define IPV6_ADDR_SCOPE_GLOBAL 0x0e

/*
 * Addr flags
 */
#define IPV6_ADDR_MC_FLAG_TRANSIENT(a) \
 ((a)->s6_addr[1] & 0x10)
#define IPV6_ADDR_MC_FLAG_PREFIX(a) \
 ((a)->s6_addr[1] & 0x20)
#define IPV6_ADDR_MC_FLAG_RENDEZVOUS(a) \
 ((a)->s6_addr[1] & 0x40)

/*
 * fragmentation header
 */

struct frag_hdr {
	__u8	nexthdr;
	__u8	reserved;
	__be16	frag_off;
	__be32	identification;
};

#define IP6_MF 0x0001
#define IP6_OFFSET 0xFFF8

#define IP6_REPLY_MARK(net, mark) \
 ((net)->ipv6.sysctl.fwmark_reflect ? (mark) : 0)

#include <net/sock.h>

/* sysctls */
extern int sysctl_mld_max_msf;
extern int sysctl_mld_qrv;

#define _DEVINC(net, statname, modifier, idev, field) \
({ \
 struct inet6_dev *_idev = (idev); \
 if (likely(_idev != NULL)) \
 SNMP_INC_STATS##modifier((_idev)->stats.statname, (field)); \
 SNMP_INC_STATS##modifier((net)->mib.statname##_statistics, (field));\
})

/* per device counters are atomic_long_t */
#define _DEVINCATOMIC(net, statname, modifier, idev, field) \
({ \
 struct inet6_dev *_idev = (idev); \
 if (likely(_idev != NULL)) \
 SNMP_INC_STATS_ATOMIC_LONG((_idev)->stats.statname##dev, (field)); \
 SNMP_INC_STATS##modifier((net)->mib.statname##_statistics, (field));\
})

/* per device and per net counters are atomic_long_t */
#define _DEVINC_ATOMIC_ATOMIC(net, statname, idev, field) \
({ \
 struct inet6_dev *_idev = (idev); \
 if (likely(_idev != NULL)) \
 SNMP_INC_STATS_ATOMIC_LONG((_idev)->stats.statname##dev, (field)); \
 SNMP_INC_STATS_ATOMIC_LONG((net)->mib.statname##_statistics, (field));\
})

#define _DEVADD(net, statname, modifier, idev, field, val) \
({ \
 struct inet6_dev *_idev = (idev); \
 if (likely(_idev != NULL)) \
 SNMP_ADD_STATS##modifier((_idev)->stats.statname, (field), (val)); \
 SNMP_ADD_STATS##modifier((net)->mib.statname##_statistics, (field), (val));\
})

#define _DEVUPD(net, statname, modifier, idev, field, val) \
({ \
 struct inet6_dev *_idev = (idev); \
 if (likely(_idev != NULL)) \
 SNMP_UPD_PO_STATS##modifier((_idev)->stats.statname, field, (val)); \
 SNMP_UPD_PO_STATS##modifier((net)->mib.statname##_statistics, field, (val));\
})

/* MIBs */

#define IP6_INC_STATS(net, idev,field) \
 _DEVINC(net, ipv6, 64, idev, field)
#define IP6_INC_STATS_BH(net, idev,field) \
 _DEVINC(net, ipv6, 64_BH, idev, field)
#define IP6_ADD_STATS(net, idev,field,val) \
 _DEVADD(net, ipv6, 64, idev, field, val)
#define IP6_ADD_STATS_BH(net, idev,field,val) \
 _DEVADD(net, ipv6, 64_BH, idev, field, val)
#define IP6_UPD_PO_STATS(net, idev,field,val) \
 _DEVUPD(net, ipv6, 64, idev, field, val)
#define IP6_UPD_PO_STATS_BH(net, idev,field,val) \
 _DEVUPD(net, ipv6, 64_BH, idev, field, val)
#define ICMP6_INC_STATS(net, idev, field) \
 _DEVINCATOMIC(net, icmpv6, , idev, field)
#define ICMP6_INC_STATS_BH(net, idev, field) \
 _DEVINCATOMIC(net, icmpv6, _BH, idev, field)

#define ICMP6MSGOUT_INC_STATS(net, idev, field) \
 _DEVINC_ATOMIC_ATOMIC(net, icmpv6msg, idev, field +256)
#define ICMP6MSGOUT_INC_STATS_BH(net, idev, field) \
 _DEVINC_ATOMIC_ATOMIC(net, icmpv6msg, idev, field +256)
#define ICMP6MSGIN_INC_STATS_BH(net, idev, field) \
 _DEVINC_ATOMIC_ATOMIC(net, icmpv6msg, idev, field)

struct ip6_ra_chain {
	struct ip6_ra_chain	*next;
	struct sock		*sk;
	int			sel;
	void			(*destructor)(struct sock *);
};

extern struct ip6_ra_chain	*ip6_ra_chain;
extern rwlock_t ip6_ra_lock;

/*
 This structure is prepared by protocol, when parsing
 ancillary data and passed to IPv6.
 */

struct ipv6_txoptions {
	/* Length of this structure */
	int			tot_len;

	/* length of extension headers */

	__u16			opt_flen;	/* after fragment hdr */
	__u16			opt_nflen;	/* before fragment hdr */

	struct ipv6_opt_hdr	*hopopt;
	struct ipv6_opt_hdr	*dst0opt;
	struct ipv6_rt_hdr	*srcrt;	/* Routing Header */
	struct ipv6_opt_hdr	*dst1opt;

	/* Option buffer, as read by IPV6_PKTOPTIONS, starts here. */
};

struct ip6_flowlabel {
	struct ip6_flowlabel __rcu *next;
	__be32			label;
	atomic_t		users;
	struct in6_addr		dst;
	struct ipv6_txoptions	*opt;
	unsigned long		linger;
	struct rcu_head		rcu;
	u8			share;
	union {
		struct pid *pid;
		kuid_t uid;
	} owner;
	unsigned long		lastuse;
	unsigned long		expires;
	struct net		*fl_net;
};

#define IPV6_FLOWINFO_MASK cpu_to_be32(0x0FFFFFFF)
#define IPV6_FLOWLABEL_MASK cpu_to_be32(0x000FFFFF)
#define IPV6_FLOWLABEL_STATELESS_FLAG cpu_to_be32(0x00080000)

#define IPV6_TCLASS_MASK (IPV6_FLOWINFO_MASK & ~IPV6_FLOWLABEL_MASK)
#define IPV6_TCLASS_SHIFT 20

struct ipv6_fl_socklist {
	struct ipv6_fl_socklist	__rcu	*next;
	struct ip6_flowlabel		*fl;
	struct rcu_head			rcu;
};

struct ip6_flowlabel *fl6_sock_lookup(struct sock *sk, __be32 label);
struct ipv6_txoptions *fl6_merge_options(struct ipv6_txoptions *opt_space,
					 struct ip6_flowlabel *fl,
					 struct ipv6_txoptions *fopt);
void fl6_free_socklist(struct sock *sk);
int ipv6_flowlabel_opt(struct sock *sk, char __user *optval, int optlen);
int ipv6_flowlabel_opt_get(struct sock *sk, struct in6_flowlabel_req *freq,
			   int flags);
int ip6_flowlabel_init(void);
void ip6_flowlabel_cleanup(void);

static inline void fl6_sock_release(struct ip6_flowlabel *fl)
{
	if (fl)
		atomic_dec(&fl->users);
}

void icmpv6_notify(struct sk_buff *skb, u8 type, u8 code, __be32 info);

int icmpv6_push_pending_frames(struct sock *sk, struct flowi6 *fl6,
			       struct icmp6hdr *thdr, int len);

int ip6_ra_control(struct sock *sk, int sel);

int ipv6_parse_hopopts(struct sk_buff *skb);

struct ipv6_txoptions *ipv6_dup_options(struct sock *sk,
					struct ipv6_txoptions *opt);
struct ipv6_txoptions *ipv6_renew_options(struct sock *sk,
					  struct ipv6_txoptions *opt,
					  int newtype,
					  struct ipv6_opt_hdr __user *newopt,
					  int newoptlen);
struct ipv6_txoptions *ipv6_fixup_options(struct ipv6_txoptions *opt_space,
					  struct ipv6_txoptions *opt);

bool ipv6_opt_accepted(const struct sock *sk, const struct sk_buff *skb,
		       const struct inet6_skb_parm *opt);

static inline bool ipv6_accept_ra(struct inet6_dev *idev)
{
	/* If forwarding is enabled, RA are not accepted unless the special
 * hybrid mode (accept_ra=2) is enabled.
 */
	return idev->cnf.forwarding ? idev->cnf.accept_ra == 2 :
	    idev->cnf.accept_ra;
}

#if IS_ENABLED(CONFIG_IPV6)
static inline int ip6_frag_mem(struct net *net)
{
	return sum_frag_mem_limit(&net->ipv6.frags);
}
#endif

#define IPV6_FRAG_HIGH_THRESH (4 * 1024*1024)	/* 4194304 */
#define IPV6_FRAG_LOW_THRESH (3 * 1024*1024)	/* 3145728 */
#define IPV6_FRAG_TIMEOUT (60 * HZ)	/* 60 seconds */

int __ipv6_addr_type(const struct in6_addr *addr);
static inline int ipv6_addr_type(const struct in6_addr *addr)
{
	return __ipv6_addr_type(addr) & 0xffff;
}

static inline int ipv6_addr_scope(const struct in6_addr *addr)
{
	return __ipv6_addr_type(addr) & IPV6_ADDR_SCOPE_MASK;
}

static inline int __ipv6_addr_src_scope(int type)
{
	return (type == IPV6_ADDR_ANY) ? __IPV6_ADDR_SCOPE_INVALID : (type >> 16);
}

static inline int ipv6_addr_src_scope(const struct in6_addr *addr)
{
	return __ipv6_addr_src_scope(__ipv6_addr_type(addr));
}

static inline bool __ipv6_addr_needs_scope_id(int type)
{
	return type & IPV6_ADDR_LINKLOCAL ||
	       (type & IPV6_ADDR_MULTICAST &&
		(type & (IPV6_ADDR_LOOPBACK|IPV6_ADDR_LINKLOCAL)));
}

static inline __u32 ipv6_iface_scope_id(const struct in6_addr *addr, int iface)
{
	return __ipv6_addr_needs_scope_id(__ipv6_addr_type(addr)) ? iface : 0;
}

static inline int ipv6_addr_cmp(const struct in6_addr *a1, const struct in6_addr *a2)
{
	return memcmp(a1, a2, sizeof(struct in6_addr));
}

static inline bool
ipv6_masked_addr_cmp(const struct in6_addr *a1, const struct in6_addr *m,
		     const struct in6_addr *a2)
{
#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS) && BITS_PER_LONG == 64
	const unsigned long *ul1 = (const unsigned long *)a1;
	const unsigned long *ulm = (const unsigned long *)m;
	const unsigned long *ul2 = (const unsigned long *)a2;

	return !!(((ul1[0] ^ ul2[0]) & ulm[0]) |
		  ((ul1[1] ^ ul2[1]) & ulm[1]));
#else
	return !!(((a1->s6_addr32[0] ^ a2->s6_addr32[0]) & m->s6_addr32[0]) |
		  ((a1->s6_addr32[1] ^ a2->s6_addr32[1]) & m->s6_addr32[1]) |
		  ((a1->s6_addr32[2] ^ a2->s6_addr32[2]) & m->s6_addr32[2]) |
		  ((a1->s6_addr32[3] ^ a2->s6_addr32[3]) & m->s6_addr32[3]));
#endif
}

static inline void ipv6_addr_prefix(struct in6_addr *pfx, 
				    const struct in6_addr *addr,
				    int plen)
{
	/* caller must guarantee 0 <= plen <= 128 */
	int o = plen >> 3,
	    b = plen & 0x7;

	memset(pfx->s6_addr, 0, sizeof(pfx->s6_addr));
	memcpy(pfx->s6_addr, addr, o);
	if (b != 0)
		pfx->s6_addr[o] = addr->s6_addr[o] & (0xff00 >> b);
}

static inline void __ipv6_addr_set_half(__be32 *addr,
					__be32 wh, __be32 wl)
{
#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS) && BITS_PER_LONG == 64
#if defined(__BIG_ENDIAN)
	if (__builtin_constant_p(wh) && __builtin_constant_p(wl)) {
		*(__force u64 *)addr = ((__force u64)(wh) << 32 | (__force u64)(wl));
		return;
	}
#elif defined(__LITTLE_ENDIAN)
	if (__builtin_constant_p(wl) && __builtin_constant_p(wh)) {
		*(__force u64 *)addr = ((__force u64)(wl) << 32 | (__force u64)(wh));
		return;
	}
#endif
#endif
	addr[0] = wh;
	addr[1] = wl;
}

static inline void ipv6_addr_set(struct in6_addr *addr, 
				     __be32 w1, __be32 w2,
				     __be32 w3, __be32 w4)
{
	__ipv6_addr_set_half(&addr->s6_addr32[0], w1, w2);
	__ipv6_addr_set_half(&addr->s6_addr32[2], w3, w4);
}

static inline bool ipv6_addr_equal(const struct in6_addr *a1,
				   const struct in6_addr *a2)
{
#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS) && BITS_PER_LONG == 64
	const unsigned long *ul1 = (const unsigned long *)a1;
	const unsigned long *ul2 = (const unsigned long *)a2;

	return ((ul1[0] ^ ul2[0]) | (ul1[1] ^ ul2[1])) == 0UL;
#else
	return ((a1->s6_addr32[0] ^ a2->s6_addr32[0]) |
		(a1->s6_addr32[1] ^ a2->s6_addr32[1]) |
		(a1->s6_addr32[2] ^ a2->s6_addr32[2]) |
		(a1->s6_addr32[3] ^ a2->s6_addr32[3])) == 0;
#endif
}

#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS) && BITS_PER_LONG == 64
static inline bool __ipv6_prefix_equal64_half(const __be64 *a1,
					      const __be64 *a2,
					      unsigned int len)
{
	if (len && ((*a1 ^ *a2) & cpu_to_be64((~0UL) << (64 - len))))
		return false;
	return true;
}

static inline bool ipv6_prefix_equal(const struct in6_addr *addr1,
				     const struct in6_addr *addr2,
				     unsigned int prefixlen)
{
	const __be64 *a1 = (const __be64 *)addr1;
	const __be64 *a2 = (const __be64 *)addr2;

	if (prefixlen >= 64) {
		if (a1[0] ^ a2[0])
			return false;
		return __ipv6_prefix_equal64_half(a1 + 1, a2 + 1, prefixlen - 64);
	}
	return __ipv6_prefix_equal64_half(a1, a2, prefixlen);
}
#else
static inline bool ipv6_prefix_equal(const struct in6_addr *addr1,
				     const struct in6_addr *addr2,
				     unsigned int prefixlen)
{
	const __be32 *a1 = addr1->s6_addr32;
	const __be32 *a2 = addr2->s6_addr32;
	unsigned int pdw, pbi;

	/* check complete u32 in prefix */
	pdw = prefixlen >> 5;
	if (pdw && memcmp(a1, a2, pdw << 2))
		return false;

	/* check incomplete u32 in prefix */
	pbi = prefixlen & 0x1f;
	if (pbi && ((a1[pdw] ^ a2[pdw]) & htonl((0xffffffff) << (32 - pbi))))
		return false;

	return true;
}
#endif

struct inet_frag_queue;

enum ip6_defrag_users {
	IP6_DEFRAG_LOCAL_DELIVER,
	IP6_DEFRAG_CONNTRACK_IN,
	__IP6_DEFRAG_CONNTRACK_IN	= IP6_DEFRAG_CONNTRACK_IN + USHRT_MAX,
	IP6_DEFRAG_CONNTRACK_OUT,
	__IP6_DEFRAG_CONNTRACK_OUT	= IP6_DEFRAG_CONNTRACK_OUT + USHRT_MAX,
	IP6_DEFRAG_CONNTRACK_BRIDGE_IN,
	__IP6_DEFRAG_CONNTRACK_BRIDGE_IN = IP6_DEFRAG_CONNTRACK_BRIDGE_IN + USHRT_MAX,
};

struct ip6_create_arg {
	__be32 id;
	u32 user;
	const struct in6_addr *src;
	const struct in6_addr *dst;
	int iif;
	u8 ecn;
};

void ip6_frag_init(struct inet_frag_queue *q, const void *a);
bool ip6_frag_match(const struct inet_frag_queue *q, const void *a);

/*
 * Equivalent of ipv4 struct ip
 */
struct frag_queue {
	struct inet_frag_queue	q;

	__be32			id;		/* fragment id */
	u32			user;
	struct in6_addr		saddr;
	struct in6_addr		daddr;

	int			iif;
	unsigned int		csum;
	__u16			nhoffset;
	u8			ecn;
};

void ip6_expire_frag_queue(struct net *net, struct frag_queue *fq,
			   struct inet_frags *frags);

static inline bool ipv6_addr_any(const struct in6_addr *a)
{
#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS) && BITS_PER_LONG == 64
	const unsigned long *ul = (const unsigned long *)a;

	return (ul[0] | ul[1]) == 0UL;
#else
	return (a->s6_addr32[0] | a->s6_addr32[1] |
		a->s6_addr32[2] | a->s6_addr32[3]) == 0;
#endif
}

static inline u32 ipv6_addr_hash(const struct in6_addr *a)
{
#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS) && BITS_PER_LONG == 64
	const unsigned long *ul = (const unsigned long *)a;
	unsigned long x = ul[0] ^ ul[1];

	return (u32)(x ^ (x >> 32));
#else
	return (__force u32)(a->s6_addr32[0] ^ a->s6_addr32[1] ^
			     a->s6_addr32[2] ^ a->s6_addr32[3]);
#endif
}

/* more secured version of ipv6_addr_hash() */
static inline u32 __ipv6_addr_jhash(const struct in6_addr *a, const u32 initval)
{
	u32 v = (__force u32)a->s6_addr32[0] ^ (__force u32)a->s6_addr32[1];

	return jhash_3words(v,
			    (__force u32)a->s6_addr32[2],
			    (__force u32)a->s6_addr32[3],
			    initval);
}

static inline bool ipv6_addr_loopback(const struct in6_addr *a)
{
#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS) && BITS_PER_LONG == 64
	const __be64 *be = (const __be64 *)a;

	return (be[0] | (be[1] ^ cpu_to_be64(1))) == 0UL;
#else
	return (a->s6_addr32[0] | a->s6_addr32[1] |
		a->s6_addr32[2] | (a->s6_addr32[3] ^ cpu_to_be32(1))) == 0;
#endif
}

/*
 * Note that we must __force cast these to unsigned long to make sparse happy,
 * since all of the endian-annotated types are fixed size regardless of arch.
 */
static inline bool ipv6_addr_v4mapped(const struct in6_addr *a)
{
	return (
#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS) && BITS_PER_LONG == 64
		*(unsigned long *)a |
#else
		(__force unsigned long)(a->s6_addr32[0] | a->s6_addr32[1]) |
#endif
		(__force unsigned long)(a->s6_addr32[2] ^
					cpu_to_be32(0x0000ffff))) == 0UL;
}

/*
 * Check for a RFC 4843 ORCHID address
 * (Overlay Routable Cryptographic Hash Identifiers)
 */
static inline bool ipv6_addr_orchid(const struct in6_addr *a)
{
	return (a->s6_addr32[0] & htonl(0xfffffff0)) == htonl(0x20010010);
}

static inline bool ipv6_addr_is_multicast(const struct in6_addr *addr)
{
	return (addr->s6_addr32[0] & htonl(0xFF000000)) == htonl(0xFF000000);
}

static inline void ipv6_addr_set_v4mapped(const __be32 addr,
					  struct in6_addr *v4mapped)
{
	ipv6_addr_set(v4mapped,
			0, 0,
			htonl(0x0000FFFF),
			addr);
}

/*
 * find the first different bit between two addresses
 * length of address must be a multiple of 32bits
 */
static inline int __ipv6_addr_diff32(const void *token1, const void *token2, int addrlen)
{
	const __be32 *a1 = token1, *a2 = token2;
	int i;

	addrlen >>= 2;

	for (i = 0; i < addrlen; i++) {
		__be32 xb = a1[i] ^ a2[i];
		if (xb)
			return i * 32 + 31 - __fls(ntohl(xb));
	}

	/*
 * we should *never* get to this point since that 
 * would mean the addrs are equal
 *
 * However, we do get to it 8) And exacly, when
 * addresses are equal 8)
 *
 * ip route add 1111::/128 via ...
 * ip route add 1111::/64 via ...
 * and we are here.
 *
 * Ideally, this function should stop comparison
 * at prefix length. It does not, but it is still OK,
 * if returned value is greater than prefix length.
 * --ANK (980803)
 */
	return addrlen << 5;
}

#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS) && BITS_PER_LONG == 64
static inline int __ipv6_addr_diff64(const void *token1, const void *token2, int addrlen)
{
	const __be64 *a1 = token1, *a2 = token2;
	int i;

	addrlen >>= 3;

	for (i = 0; i < addrlen; i++) {
		__be64 xb = a1[i] ^ a2[i];
		if (xb)
			return i * 64 + 63 - __fls(be64_to_cpu(xb));
	}

	return addrlen << 6;
}
#endif

static inline int __ipv6_addr_diff(const void *token1, const void *token2, int addrlen)
{
#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS) && BITS_PER_LONG == 64
	if (__builtin_constant_p(addrlen) && !(addrlen & 7))
		return __ipv6_addr_diff64(token1, token2, addrlen);
#endif
	return __ipv6_addr_diff32(token1, token2, addrlen);
}

static inline int ipv6_addr_diff(const struct in6_addr *a1, const struct in6_addr *a2)
{
	return __ipv6_addr_diff(a1, a2, sizeof(struct in6_addr));
}

__be32 ipv6_select_ident(struct net *net,
			 const struct in6_addr *daddr,
			 const struct in6_addr *saddr);
void ipv6_proxy_select_ident(struct net *net, struct sk_buff *skb);

int ip6_dst_hoplimit(struct dst_entry *dst);

static inline int ip6_sk_dst_hoplimit(struct ipv6_pinfo *np, struct flowi6 *fl6,
				      struct dst_entry *dst)
{
	int hlimit;

	if (ipv6_addr_is_multicast(&fl6->daddr))
		hlimit = np->mcast_hops;
	else
		hlimit = np->hop_limit;
	if (hlimit < 0)
		hlimit = ip6_dst_hoplimit(dst);
	return hlimit;
}

/* copy IPv6 saddr & daddr to flow_keys, possibly using 64bit load/store
 * Equivalent to : flow->v6addrs.src = iph->saddr;
 * flow->v6addrs.dst = iph->daddr;
 */
static inline void iph_to_flow_copy_v6addrs(struct flow_keys *flow,
					    const struct ipv6hdr *iph)
{
	BUILD_BUG_ON(offsetof(typeof(flow->addrs), v6addrs.dst) !=
		     offsetof(typeof(flow->addrs), v6addrs.src) +
		     sizeof(flow->addrs.v6addrs.src));
	memcpy(&flow->addrs.v6addrs, &iph->saddr, sizeof(flow->addrs.v6addrs));
	flow->control.addr_type = FLOW_DISSECTOR_KEY_IPV6_ADDRS;
}

#if IS_ENABLED(CONFIG_IPV6)

/* Sysctl settings for net ipv6.auto_flowlabels */
#define IP6_AUTO_FLOW_LABEL_OFF 0
#define IP6_AUTO_FLOW_LABEL_OPTOUT 1
#define IP6_AUTO_FLOW_LABEL_OPTIN 2
#define IP6_AUTO_FLOW_LABEL_FORCED 3

#define IP6_AUTO_FLOW_LABEL_MAX IP6_AUTO_FLOW_LABEL_FORCED

#define IP6_DEFAULT_AUTO_FLOW_LABELS IP6_AUTO_FLOW_LABEL_OPTOUT

static inline __be32 ip6_make_flowlabel(struct net *net, struct sk_buff *skb,
					__be32 flowlabel, bool autolabel,
					struct flowi6 *fl6)
{
	u32 hash;

	if (flowlabel ||
	    net->ipv6.sysctl.auto_flowlabels == IP6_AUTO_FLOW_LABEL_OFF ||
	    (!autolabel &&
	     net->ipv6.sysctl.auto_flowlabels != IP6_AUTO_FLOW_LABEL_FORCED))
		return flowlabel;

	hash = skb_get_hash_flowi6(skb, fl6);

	/* Since this is being sent on the wire obfuscate hash a bit
 * to minimize possbility that any useful information to an
 * attacker is leaked. Only lower 20 bits are relevant.
 */
	rol32(hash, 16);

	flowlabel = (__force __be32)hash & IPV6_FLOWLABEL_MASK;

	if (net->ipv6.sysctl.flowlabel_state_ranges)
		flowlabel |= IPV6_FLOWLABEL_STATELESS_FLAG;

	return flowlabel;
}

static inline int ip6_default_np_autolabel(struct net *net)
{
	switch (net->ipv6.sysctl.auto_flowlabels) {
	case IP6_AUTO_FLOW_LABEL_OFF:
	case IP6_AUTO_FLOW_LABEL_OPTIN:
	default:
		return 0;
	case IP6_AUTO_FLOW_LABEL_OPTOUT:
	case IP6_AUTO_FLOW_LABEL_FORCED:
		return 1;
	}
}
#else
static inline void ip6_set_txhash(struct sock *sk) { }
static inline __be32 ip6_make_flowlabel(struct net *net, struct sk_buff *skb,
					__be32 flowlabel, bool autolabel,
					struct flowi6 *fl6)
{
	return flowlabel;
}
static inline int ip6_default_np_autolabel(struct net *net)
{
	return 0;
}
#endif


/*
 * Header manipulation
 */
static inline void ip6_flow_hdr(struct ipv6hdr *hdr, unsigned int tclass,
				__be32 flowlabel)
{
	*(__be32 *)hdr = htonl(0x60000000 | (tclass << 20)) | flowlabel;
}

static inline __be32 ip6_flowinfo(const struct ipv6hdr *hdr)
{
	return *(__be32 *)hdr & IPV6_FLOWINFO_MASK;
}

static inline __be32 ip6_flowlabel(const struct ipv6hdr *hdr)
{
	return *(__be32 *)hdr & IPV6_FLOWLABEL_MASK;
}

static inline u8 ip6_tclass(__be32 flowinfo)
{
	return ntohl(flowinfo & IPV6_TCLASS_MASK) >> IPV6_TCLASS_SHIFT;
}
/*
 * Prototypes exported by ipv6
 */

/*
 * rcv function (called from netdevice level)
 */

int ipv6_rcv(struct sk_buff *skb, struct net_device *dev,
	     struct packet_type *pt, struct net_device *orig_dev);

int ip6_rcv_finish(struct net *net, struct sock *sk, struct sk_buff *skb);

/*
 * upper-layer output functions
 */
int ip6_xmit(const struct sock *sk, struct sk_buff *skb, struct flowi6 *fl6,
	     struct ipv6_txoptions *opt, int tclass);

int ip6_find_1stfragopt(struct sk_buff *skb, u8 **nexthdr);

int ip6_append_data(struct sock *sk,
		    int getfrag(void *from, char *to, int offset, int len,
				int odd, struct sk_buff *skb),
		    void *from, int length, int transhdrlen, int hlimit,
		    int tclass, struct ipv6_txoptions *opt, struct flowi6 *fl6,
		    struct rt6_info *rt, unsigned int flags, int dontfrag);

int ip6_push_pending_frames(struct sock *sk);

void ip6_flush_pending_frames(struct sock *sk);

int ip6_send_skb(struct sk_buff *skb);

struct sk_buff *__ip6_make_skb(struct sock *sk, struct sk_buff_head *queue,
			       struct inet_cork_full *cork,
			       struct inet6_cork *v6_cork);
struct sk_buff *ip6_make_skb(struct sock *sk,
			     int getfrag(void *from, char *to, int offset,
					 int len, int odd, struct sk_buff *skb),
			     void *from, int length, int transhdrlen,
			     int hlimit, int tclass, struct ipv6_txoptions *opt,
			     struct flowi6 *fl6, struct rt6_info *rt,
			     unsigned int flags, int dontfrag);

static inline struct sk_buff *ip6_finish_skb(struct sock *sk)
{
	return __ip6_make_skb(sk, &sk->sk_write_queue, &inet_sk(sk)->cork,
			      &inet6_sk(sk)->cork);
}

int ip6_dst_lookup(struct net *net, struct sock *sk, struct dst_entry **dst,
		   struct flowi6 *fl6);
struct dst_entry *ip6_dst_lookup_flow(const struct sock *sk, struct flowi6 *fl6,
				      const struct in6_addr *final_dst);
struct dst_entry *ip6_sk_dst_lookup_flow(struct sock *sk, struct flowi6 *fl6,
					 const struct in6_addr *final_dst);
struct dst_entry *ip6_blackhole_route(struct net *net,
				      struct dst_entry *orig_dst);

/*
 * skb processing functions
 */

int ip6_output(struct net *net, struct sock *sk, struct sk_buff *skb);
int ip6_forward(struct sk_buff *skb);
int ip6_input(struct sk_buff *skb);
int ip6_mc_input(struct sk_buff *skb);

int __ip6_local_out(struct net *net, struct sock *sk, struct sk_buff *skb);
int ip6_local_out(struct net *net, struct sock *sk, struct sk_buff *skb);

/*
 * Extension header (options) processing
 */

void ipv6_push_nfrag_opts(struct sk_buff *skb, struct ipv6_txoptions *opt,
			  u8 *proto, struct in6_addr **daddr_p);
void ipv6_push_frag_opts(struct sk_buff *skb, struct ipv6_txoptions *opt,
			 u8 *proto);

int ipv6_skip_exthdr(const struct sk_buff *, int start, u8 *nexthdrp,
		     __be16 *frag_offp);

bool ipv6_ext_hdr(u8 nexthdr);

enum {
	IP6_FH_F_FRAG		= (1 << 0),
	IP6_FH_F_AUTH		= (1 << 1),
	IP6_FH_F_SKIP_RH	= (1 << 2),
};

/* find specified header and get offset to it */
int ipv6_find_hdr(const struct sk_buff *skb, unsigned int *offset, int target,
		  unsigned short *fragoff, int *fragflg);

int ipv6_find_tlv(struct sk_buff *skb, int offset, int type);

struct in6_addr *fl6_update_dst(struct flowi6 *fl6,
				const struct ipv6_txoptions *opt,
				struct in6_addr *orig);

/*
 * socket options (ipv6_sockglue.c)
 */

int ipv6_setsockopt(struct sock *sk, int level, int optname,
		    char __user *optval, unsigned int optlen);
int ipv6_getsockopt(struct sock *sk, int level, int optname,
		    char __user *optval, int __user *optlen);
int compat_ipv6_setsockopt(struct sock *sk, int level, int optname,
			   char __user *optval, unsigned int optlen);
int compat_ipv6_getsockopt(struct sock *sk, int level, int optname,
			   char __user *optval, int __user *optlen);

int ip6_datagram_connect(struct sock *sk, struct sockaddr *addr, int addr_len);
int ip6_datagram_connect_v6_only(struct sock *sk, struct sockaddr *addr,
				 int addr_len);

int ipv6_recv_error(struct sock *sk, struct msghdr *msg, int len,
		    int *addr_len);
int ipv6_recv_rxpmtu(struct sock *sk, struct msghdr *msg, int len,
		     int *addr_len);
void ipv6_icmp_error(struct sock *sk, struct sk_buff *skb, int err, __be16 port,
		     u32 info, u8 *payload);
void ipv6_local_error(struct sock *sk, int err, struct flowi6 *fl6, u32 info);
void ipv6_local_rxpmtu(struct sock *sk, struct flowi6 *fl6, u32 mtu);

int inet6_release(struct socket *sock);
int inet6_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len);
int inet6_getname(struct socket *sock, struct sockaddr *uaddr, int *uaddr_len,
		  int peer);
int inet6_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg);

int inet6_hash_connect(struct inet_timewait_death_row *death_row,
			      struct sock *sk);

/*
 * reassembly.c
 */
extern const struct proto_ops inet6_stream_ops;
extern const struct proto_ops inet6_dgram_ops;

struct group_source_req;
struct group_filter;

int ip6_mc_source(int add, int omode, struct sock *sk,
		  struct group_source_req *pgsr);
int ip6_mc_msfilter(struct sock *sk, struct group_filter *gsf);
int ip6_mc_msfget(struct sock *sk, struct group_filter *gsf,
		  struct group_filter __user *optval, int __user *optlen);

#ifdef CONFIG_PROC_FS
int ac6_proc_init(struct net *net);
void ac6_proc_exit(struct net *net);
int raw6_proc_init(void);
void raw6_proc_exit(void);
int tcp6_proc_init(struct net *net);
void tcp6_proc_exit(struct net *net);
int udp6_proc_init(struct net *net);
void udp6_proc_exit(struct net *net);
int udplite6_proc_init(void);
void udplite6_proc_exit(void);
int ipv6_misc_proc_init(void);
void ipv6_misc_proc_exit(void);
int snmp6_register_dev(struct inet6_dev *idev);
int snmp6_unregister_dev(struct inet6_dev *idev);

#else
static inline int ac6_proc_init(struct net *net) { return 0; }
static inline void ac6_proc_exit(struct net *net) { }
static inline int snmp6_register_dev(struct inet6_dev *idev) { return 0; }
static inline int snmp6_unregister_dev(struct inet6_dev *idev) { return 0; }
#endif

#ifdef CONFIG_SYSCTL
extern struct ctl_table ipv6_route_table_template[];

struct ctl_table *ipv6_icmp_sysctl_init(struct net *net);
struct ctl_table *ipv6_route_sysctl_init(struct net *net);
int ipv6_sysctl_register(void);
void ipv6_sysctl_unregister(void);
#endif

int ipv6_sock_mc_join(struct sock *sk, int ifindex,
		      const struct in6_addr *addr);
int ipv6_sock_mc_drop(struct sock *sk, int ifindex,
		      const struct in6_addr *addr);
#endif /* _NET_IPV6_H */