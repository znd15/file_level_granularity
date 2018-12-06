

/*
 * INET An implementation of the TCP/IP protocol suite for the LINUX
 * operating system. INET is implemented using the BSD Socket
 * interface as the means of communication with the user level.
 *
 * The User Datagram Protocol (UDP).
 *
 * Authors: Ross Biro
 * Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 * Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 * Alan Cox, <alan@lxorguk.ukuu.org.uk>
 * Hirokazu Takahashi, <taka@valinux.co.jp>
 *
 * Fixes:
 * Alan Cox : verify_area() calls
 * Alan Cox : stopped close while in use off icmp
 * messages. Not a fix but a botch that
 * for udp at least is 'valid'.
 * Alan Cox : Fixed icmp handling properly
 * Alan Cox : Correct error for oversized datagrams
 * Alan Cox : Tidied select() semantics.
 * Alan Cox : udp_err() fixed properly, also now
 * select and read wake correctly on errors
 * Alan Cox : udp_send verify_area moved to avoid mem leak
 * Alan Cox : UDP can count its memory
 * Alan Cox : send to an unknown connection causes
 * an ECONNREFUSED off the icmp, but
 * does NOT close.
 * Alan Cox : Switched to new sk_buff handlers. No more backlog!
 * Alan Cox : Using generic datagram code. Even smaller and the PEEK
 * bug no longer crashes it.
 * Fred Van Kempen : Net2e support for sk->broadcast.
 * Alan Cox : Uses skb_free_datagram
 * Alan Cox : Added get/set sockopt support.
 * Alan Cox : Broadcasting without option set returns EACCES.
 * Alan Cox : No wakeup calls. Instead we now use the callbacks.
 * Alan Cox : Use ip_tos and ip_ttl
 * Alan Cox : SNMP Mibs
 * Alan Cox : MSG_DONTROUTE, and 0.0.0.0 support.
 * Matt Dillon : UDP length checks.
 * Alan Cox : Smarter af_inet used properly.
 * Alan Cox : Use new kernel side addressing.
 * Alan Cox : Incorrect return on truncated datagram receive.
 * Arnt Gulbrandsen : New udp_send and stuff
 * Alan Cox : Cache last socket
 * Alan Cox : Route cache
 * Jon Peatfield : Minor efficiency fix to sendto().
 * Mike Shaver : RFC1122 checks.
 * Alan Cox : Nonblocking error fix.
 * Willy Konynenberg : Transparent proxying support.
 * Mike McLagan : Routing by source
 * David S. Miller : New socket lookup architecture.
 * Last socket cache retained as it
 * does have a high hit rate.
 * Olaf Kirch : Don't linearise iovec on sendmsg.
 * Andi Kleen : Some cleanups, cache destination entry
 * for connect.
 * Vitaly E. Lavrov : Transparent proxy revived after year coma.
 * Melvin Smith : Check msg_name not msg_namelen in sendto(),
 * return ENOTCONN for unconnected sockets (POSIX)
 * Janos Farkas : don't deliver multi/broadcasts to a different
 * bound-to-device socket
 * Hirokazu Takahashi : HW checksumming for outgoing UDP
 * datagrams.
 * Hirokazu Takahashi : sendfile() on UDP works now.
 * Arnaldo C. Melo : convert /proc/net/udp to seq_file
 * YOSHIFUJI Hideaki @USAGI and: Support IPV6_V6ONLY socket option, which
 * Alexey Kuznetsov: allow both IPv4 and IPv6 sockets to bind
 * a single port at the same time.
 * Derek Atkins <derek@ihtfp.com>: Add Encapulation Support
 * James Chapman : Add L2TP encapsulation type.
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#define pr_fmt(fmt) "UDP: " fmt

#include <asm/uaccess.h>
#include <asm/ioctls.h>
#include <linux/bootmem.h>
#include <linux/highmem.h>
#include <linux/swap.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/module.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/igmp.h>
#include <linux/in.h>
#include <linux/errno.h>
#include <linux/timer.h>
#include <linux/mm.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/slab.h>
#include <net/tcp_states.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <net/net_namespace.h>
#include <net/icmp.h>
#include <net/inet_hashtables.h>
#include <net/route.h>
#include <net/checksum.h>
#include <net/xfrm.h>
#include <trace/events/udp.h>
#include <linux/static_key.h>
#include <trace/events/skb.h>
#include <net/busy_poll.h>
#include "udp_impl.h"

struct udp_table udp_table __read_mostly;
EXPORT_SYMBOL(udp_table);

long sysctl_udp_mem[3] __read_mostly;
EXPORT_SYMBOL(sysctl_udp_mem);

int sysctl_udp_rmem_min __read_mostly;
EXPORT_SYMBOL(sysctl_udp_rmem_min);

int sysctl_udp_wmem_min __read_mostly;
EXPORT_SYMBOL(sysctl_udp_wmem_min);

atomic_long_t udp_memory_allocated;
EXPORT_SYMBOL(udp_memory_allocated);

#define MAX_UDP_PORTS 65536
#define PORTS_PER_CHAIN (MAX_UDP_PORTS / UDP_HTABLE_SIZE_MIN)

static int udp_lib_lport_inuse(struct net *net, __u16 num,
			       const struct udp_hslot *hslot,
			       unsigned long *bitmap,
			       struct sock *sk,
			       int (*saddr_comp)(const struct sock *sk1,
						 const struct sock *sk2),
			       unsigned int log)
{
	struct sock *sk2;
	struct hlist_nulls_node *node;
	kuid_t uid = sock_i_uid(sk);

	sk_nulls_for_each(sk2, node, &hslot->head)
		if (net_eq(sock_net(sk2), net) &&
		    sk2 != sk &&
		    (bitmap || udp_sk(sk2)->udp_port_hash == num) &&
		    (!sk2->sk_reuse || !sk->sk_reuse) &&
		    (!sk2->sk_bound_dev_if || !sk->sk_bound_dev_if ||
		     sk2->sk_bound_dev_if == sk->sk_bound_dev_if) &&
		    (!sk2->sk_reuseport || !sk->sk_reuseport ||
		      !uid_eq(uid, sock_i_uid(sk2))) &&
		    (*saddr_comp)(sk, sk2)) {
			if (bitmap)
				__set_bit(udp_sk(sk2)->udp_port_hash >> log,
					  bitmap);
			else
				return 1;
		}
	return 0;
}

/*
 * Note: we still hold spinlock of primary hash chain, so no other writer
 * can insert/delete a socket with local_port == num
 */
static int udp_lib_lport_inuse2(struct net *net, __u16 num,
			       struct udp_hslot *hslot2,
			       struct sock *sk,
			       int (*saddr_comp)(const struct sock *sk1,
						 const struct sock *sk2))
{
	struct sock *sk2;
	struct hlist_nulls_node *node;
	kuid_t uid = sock_i_uid(sk);
	int res = 0;

	spin_lock(&hslot2->lock);
	udp_portaddr_for_each_entry(sk2, node, &hslot2->head)
		if (net_eq(sock_net(sk2), net) &&
		    sk2 != sk &&
		    (udp_sk(sk2)->udp_port_hash == num) &&
		    (!sk2->sk_reuse || !sk->sk_reuse) &&
		    (!sk2->sk_bound_dev_if || !sk->sk_bound_dev_if ||
		     sk2->sk_bound_dev_if == sk->sk_bound_dev_if) &&
		    (!sk2->sk_reuseport || !sk->sk_reuseport ||
		      !uid_eq(uid, sock_i_uid(sk2))) &&
		    (*saddr_comp)(sk, sk2)) {
			res = 1;
			break;
		}
	spin_unlock(&hslot2->lock);
	return res;
}

/**
 * udp_lib_get_port - UDP/-Lite port lookup for IPv4 and IPv6
 *
 * @sk: socket struct in question
 * @snum: port number to look up
 * @saddr_comp: AF-dependent comparison of bound local IP addresses
 * @hash2_nulladdr: AF-dependent hash value in secondary hash chains,
 * with NULL address
 */
int udp_lib_get_port(struct sock *sk, unsigned short snum,
		       int (*saddr_comp)(const struct sock *sk1,
					 const struct sock *sk2),
		     unsigned int hash2_nulladdr)
{
	struct udp_hslot *hslot, *hslot2;
	struct udp_table *udptable = sk->sk_prot->h.udp_table;
	int    error = 1;
	struct net *net = sock_net(sk);

	if (!snum) {
		int low, high, remaining;
		unsigned int rand;
		unsigned short first, last;
		DECLARE_BITMAP(bitmap, PORTS_PER_CHAIN);

		inet_get_local_port_range(net, &low, &high);
		remaining = (high - low) + 1;

		rand = net_random();
		first = (((u64)rand * remaining) >> 32) + low;
		/*
 * force rand to be an odd multiple of UDP_HTABLE_SIZE
 */
		rand = (rand | 1) * (udptable->mask + 1);
		last = first + udptable->mask + 1;
		do {
			hslot = udp_hashslot(udptable, net, first);
			bitmap_zero(bitmap, PORTS_PER_CHAIN);
			spin_lock_bh(&hslot->lock);
			udp_lib_lport_inuse(net, snum, hslot, bitmap, sk,
					    saddr_comp, udptable->log);

			snum = first;
			/*
 * Iterate on all possible values of snum for this hash.
 * Using steps of an odd multiple of UDP_HTABLE_SIZE
 * give us randomization and full range coverage.
 */
			do {
				if (low <= snum && snum <= high &&
				    !test_bit(snum >> udptable->log, bitmap) &&
				    !inet_is_reserved_local_port(snum))
					goto found;
				snum += rand;
			} while (snum != first);
			spin_unlock_bh(&hslot->lock);
		} while (++first != last);
		goto fail;
	} else {
		hslot = udp_hashslot(udptable, net, snum);
		spin_lock_bh(&hslot->lock);
		if (hslot->count > 10) {
			int exist;
			unsigned int slot2 = udp_sk(sk)->udp_portaddr_hash ^ snum;

			slot2          &= udptable->mask;
			hash2_nulladdr &= udptable->mask;

			hslot2 = udp_hashslot2(udptable, slot2);
			if (hslot->count < hslot2->count)
				goto scan_primary_hash;

			exist = udp_lib_lport_inuse2(net, snum, hslot2,
						     sk, saddr_comp);
			if (!exist && (hash2_nulladdr != slot2)) {
				hslot2 = udp_hashslot2(udptable, hash2_nulladdr);
				exist = udp_lib_lport_inuse2(net, snum, hslot2,
							     sk, saddr_comp);
			}
			if (exist)
				goto fail_unlock;
			else
				goto found;
		}
scan_primary_hash:
		if (udp_lib_lport_inuse(net, snum, hslot, NULL, sk,
					saddr_comp, 0))
			goto fail_unlock;
	}
found:
	inet_sk(sk)->inet_num = snum;
	udp_sk(sk)->udp_port_hash = snum;
	udp_sk(sk)->udp_portaddr_hash ^= snum;
	if (sk_unhashed(sk)) {
		sk_nulls_add_node_rcu(sk, &hslot->head);
		hslot->count++;
		sock_prot_inuse_add(sock_net(sk), sk->sk_prot, 1);

		hslot2 = udp_hashslot2(udptable, udp_sk(sk)->udp_portaddr_hash);
		spin_lock(&hslot2->lock);
		hlist_nulls_add_head_rcu(&udp_sk(sk)->udp_portaddr_node,
					 &hslot2->head);
		hslot2->count++;
		spin_unlock(&hslot2->lock);
	}
	error = 0;
fail_unlock:
	spin_unlock_bh(&hslot->lock);
fail:
	return error;
}
EXPORT_SYMBOL(udp_lib_get_port);

static int ipv4_rcv_saddr_equal(const struct sock *sk1, const struct sock *sk2)
{
	struct inet_sock *inet1 = inet_sk(sk1), *inet2 = inet_sk(sk2);

	return 	(!ipv6_only_sock(sk2) &&
		 (!inet1->inet_rcv_saddr || !inet2->inet_rcv_saddr ||
		   inet1->inet_rcv_saddr == inet2->inet_rcv_saddr));
}

static unsigned int udp4_portaddr_hash(struct net *net, __be32 saddr,
				       unsigned int port)
{
	return jhash_1word((__force u32)saddr, net_hash_mix(net)) ^ port;
}

int udp_v4_get_port(struct sock *sk, unsigned short snum)
{
	unsigned int hash2_nulladdr =
		udp4_portaddr_hash(sock_net(sk), htonl(INADDR_ANY), snum);
	unsigned int hash2_partial =
		udp4_portaddr_hash(sock_net(sk), inet_sk(sk)->inet_rcv_saddr, 0);

	/* precompute partial secondary hash */
	udp_sk(sk)->udp_portaddr_hash = hash2_partial;
	return udp_lib_get_port(sk, snum, ipv4_rcv_saddr_equal, hash2_nulladdr);
}

static inline int compute_score(struct sock *sk, struct net *net, __be32 saddr,
			 unsigned short hnum,
			 __be16 sport, __be32 daddr, __be16 dport, int dif)
{
	int score = -1;

	if (net_eq(sock_net(sk), net) && udp_sk(sk)->udp_port_hash == hnum &&
			!ipv6_only_sock(sk)) {
		struct inet_sock *inet = inet_sk(sk);

		score = (sk->sk_family == PF_INET ? 2 : 1);
		if (inet->inet_rcv_saddr) {
			if (inet->inet_rcv_saddr != daddr)
				return -1;
			score += 4;
		}
		if (inet->inet_daddr) {
			if (inet->inet_daddr != saddr)
				return -1;
			score += 4;
		}
		if (inet->inet_dport) {
			if (inet->inet_dport != sport)
				return -1;
			score += 4;
		}
		if (sk->sk_bound_dev_if) {
			if (sk->sk_bound_dev_if != dif)
				return -1;
			score += 4;
		}
	}
	return score;
}

/*
 * In this second variant, we check (daddr, dport) matches (inet_rcv_sadd, inet_num)
 */
static inline int compute_score2(struct sock *sk, struct net *net,
				 __be32 saddr, __be16 sport,
				 __be32 daddr, unsigned int hnum, int dif)
{
	int score = -1;

	if (net_eq(sock_net(sk), net) && !ipv6_only_sock(sk)) {
		struct inet_sock *inet = inet_sk(sk);

		if (inet->inet_rcv_saddr != daddr)
			return -1;
		if (inet->inet_num != hnum)
			return -1;

		score = (sk->sk_family == PF_INET ? 2 : 1);
		if (inet->inet_daddr) {
			if (inet->inet_daddr != saddr)
				return -1;
			score += 4;
		}
		if (inet->inet_dport) {
			if (inet->inet_dport != sport)
				return -1;
			score += 4;
		}
		if (sk->sk_bound_dev_if) {
			if (sk->sk_bound_dev_if != dif)
				return -1;
			score += 4;
		}
	}
	return score;
}

static unsigned int udp_ehashfn(struct net *net, const __be32 laddr,
				 const __u16 lport, const __be32 faddr,
				 const __be16 fport)
{
	static u32 udp_ehash_secret __read_mostly;

	net_get_random_once(&udp_ehash_secret, sizeof(udp_ehash_secret));

	return __inet_ehashfn(laddr, lport, faddr, fport,
			      udp_ehash_secret + net_hash_mix(net));
}


/* called with read_rcu_lock() */
static struct sock *udp4_lib_lookup2(struct net *net,
		__be32 saddr, __be16 sport,
		__be32 daddr, unsigned int hnum, int dif,
		struct udp_hslot *hslot2, unsigned int slot2)
{
	struct sock *sk, *result;
	struct hlist_nulls_node *node;
	int score, badness, matches = 0, reuseport = 0;
	u32 hash = 0;

begin:
	result = NULL;
	badness = 0;
	udp_portaddr_for_each_entry_rcu(sk, node, &hslot2->head) {
		score = compute_score2(sk, net, saddr, sport,
				      daddr, hnum, dif);
		if (score > badness) {
			result = sk;
			badness = score;
			reuseport = sk->sk_reuseport;
			if (reuseport) {
				hash = udp_ehashfn(net, daddr, hnum,
						   saddr, sport);
				matches = 1;
			}
		} else if (score == badness && reuseport) {
			matches++;
			if (((u64)hash * matches) >> 32 == 0)
				result = sk;
			hash = next_pseudo_random32(hash);
		}
	}
	/*
 * if the nulls value we got at the end of this lookup is
 * not the expected one, we must restart lookup.
 * We probably met an item that was moved to another chain.
 */
	if (get_nulls_value(node) != slot2)
		goto begin;
	if (result) {
		if (unlikely(!atomic_inc_not_zero_hint(&result->sk_refcnt, 2)))
			result = NULL;
		else if (unlikely(compute_score2(result, net, saddr, sport,
				  daddr, hnum, dif) < badness)) {
			sock_put(result);
			goto begin;
		}
	}
	return result;
}

/* UDP is nearly always wildcards out the wazoo, it makes no sense to try
 * harder than this. -DaveM
 */
struct sock *__udp4_lib_lookup(struct net *net, __be32 saddr,
		__be16 sport, __be32 daddr, __be16 dport,
		int dif, struct udp_table *udptable)
{
	struct sock *sk, *result;
	struct hlist_nulls_node *node;
	unsigned short hnum = ntohs(dport);
	unsigned int hash2, slot2, slot = udp_hashfn(net, hnum, udptable->mask);
	struct udp_hslot *hslot2, *hslot = &udptable->hash[slot];
	int score, badness, matches = 0, reuseport = 0;
	u32 hash = 0;

	rcu_read_lock();
	if (hslot->count > 10) {
		hash2 = udp4_portaddr_hash(net, daddr, hnum);
		slot2 = hash2 & udptable->mask;
		hslot2 = &udptable->hash2[slot2];
		if (hslot->count < hslot2->count)
			goto begin;

		result = udp4_lib_lookup2(net, saddr, sport,
					  daddr, hnum, dif,
					  hslot2, slot2);
		if (!result) {
			hash2 = udp4_portaddr_hash(net, htonl(INADDR_ANY), hnum);
			slot2 = hash2 & udptable->mask;
			hslot2 = &udptable->hash2[slot2];
			if (hslot->count < hslot2->count)
				goto begin;

			result = udp4_lib_lookup2(net, saddr, sport,
						  htonl(INADDR_ANY), hnum, dif,
						  hslot2, slot2);
		}
		rcu_read_unlock();
		return result;
	}
begin:
	result = NULL;
	badness = 0;
	sk_nulls_for_each_rcu(sk, node, &hslot->head) {
		score = compute_score(sk, net, saddr, hnum, sport,
				      daddr, dport, dif);
		if (score > badness) {
			result = sk;
			badness = score;
			reuseport = sk->sk_reuseport;
			if (reuseport) {
				hash = udp_ehashfn(net, daddr, hnum,
						   saddr, sport);
				matches = 1;
			}
		} else if (score == badness && reuseport) {
			matches++;
			if (((u64)hash * matches) >> 32 == 0)
				result = sk;
			hash = next_pseudo_random32(hash);
		}
	}
	/*
 * if the nulls value we got at the end of this lookup is
 * not the expected one, we must restart lookup.
 * We probably met an item that was moved to another chain.
 */
	if (get_nulls_value(node) != slot)
		goto begin;

	if (result) {
		if (unlikely(!atomic_inc_not_zero_hint(&result->sk_refcnt, 2)))
			result = NULL;
		else if (unlikely(compute_score(result, net, saddr, hnum, sport,
				  daddr, dport, dif) < badness)) {
			sock_put(result);
			goto begin;
		}
	}
	rcu_read_unlock();
	return result;
}
EXPORT_SYMBOL_GPL(__udp4_lib_lookup);

static inline struct sock *__udp4_lib_lookup_skb(struct sk_buff *skb,
						 __be16 sport, __be16 dport,
						 struct udp_table *udptable)
{
	struct sock *sk;
	const struct iphdr *iph = ip_hdr(skb);

	if (unlikely(sk = skb_steal_sock(skb)))
		return sk;
	else
		return __udp4_lib_lookup(dev_net(skb_dst(skb)->dev), iph->saddr, sport,
					 iph->daddr, dport, inet_iif(skb),
					 udptable);
}

struct sock *udp4_lib_lookup(struct net *net, __be32 saddr, __be16 sport,
			     __be32 daddr, __be16 dport, int dif)
{
	return __udp4_lib_lookup(net, saddr, sport, daddr, dport, dif, &udp_table);
}
EXPORT_SYMBOL_GPL(udp4_lib_lookup);

static inline bool __udp_is_mcast_sock(struct net *net, struct sock *sk,
				       __be16 loc_port, __be32 loc_addr,
				       __be16 rmt_port, __be32 rmt_addr,
				       int dif, unsigned short hnum)
{
	struct inet_sock *inet = inet_sk(sk);

	if (!net_eq(sock_net(sk), net) ||
	    udp_sk(sk)->udp_port_hash != hnum ||
	    (inet->inet_daddr && inet->inet_daddr != rmt_addr) ||
	    (inet->inet_dport != rmt_port && inet->inet_dport) ||
	    (inet->inet_rcv_saddr && inet->inet_rcv_saddr != loc_addr) ||
	    ipv6_only_sock(sk) ||
	    (sk->sk_bound_dev_if && sk->sk_bound_dev_if != dif))
		return false;
	if (!ip_mc_sf_allow(sk, loc_addr, rmt_addr, dif))
		return false;
	return true;
}

static inline struct sock *udp_v4_mcast_next(struct net *net, struct sock *sk,
					     __be16 loc_port, __be32 loc_addr,
					     __be16 rmt_port, __be32 rmt_addr,
					     int dif)
{
	struct hlist_nulls_node *node;
	struct sock *s = sk;
	unsigned short hnum = ntohs(loc_port);

	sk_nulls_for_each_from(s, node) {
		if (__udp_is_mcast_sock(net, s,
					loc_port, loc_addr,
					rmt_port, rmt_addr,
					dif, hnum))
			goto found;
	}
	s = NULL;
found:
	return s;
}

/*
 * This routine is called by the ICMP module when it gets some
 * sort of error condition. If err < 0 then the socket should
 * be closed and the error returned to the user. If err > 0
 * it's just the icmp type << 8 | icmp code.
 * Header points to the ip header of the error packet. We move
 * on past this. Then (as it used to claim before adjustment)
 * header points to the first 8 bytes of the udp header. We need
 * to find the appropriate port.
 */

void __udp4_lib_err(struct sk_buff *skb, u32 info, struct udp_table *udptable)
{
	struct inet_sock *inet;
	const struct iphdr *iph = (const struct iphdr *)skb->data;
	struct udphdr *uh = (struct udphdr *)(skb->data+(iph->ihl<<2));
	const int type = icmp_hdr(skb)->type;
	const int code = icmp_hdr(skb)->code;
	struct sock *sk;
	int harderr;
	int err;
	struct net *net = dev_net(skb->dev);

	sk = __udp4_lib_lookup(net, iph->daddr, uh->dest,
			iph->saddr, uh->source, skb->dev->ifindex, udptable);
	if (sk == NULL) {
		ICMP_INC_STATS_BH(net, ICMP_MIB_INERRORS);
		return;	/* No socket for error */
	}

	err = 0;
	harderr = 0;
	inet = inet_sk(sk);

	switch (type) {
	default:
	case ICMP_TIME_EXCEEDED:
		err = EHOSTUNREACH;
		break;
	case ICMP_SOURCE_QUENCH:
		goto out;
	case ICMP_PARAMETERPROB:
		err = EPROTO;
		harderr = 1;
		break;
	case ICMP_DEST_UNREACH:
		if (code == ICMP_FRAG_NEEDED) { /* Path MTU discovery */
			ipv4_sk_update_pmtu(skb, sk, info);
			if (inet->pmtudisc != IP_PMTUDISC_DONT) {
				err = EMSGSIZE;
				harderr = 1;
				break;
			}
			goto out;
		}
		err = EHOSTUNREACH;
		if (code <= NR_ICMP_UNREACH) {
			harderr = icmp_err_convert[code].fatal;
			err = icmp_err_convert[code].errno;
		}
		break;
	case ICMP_REDIRECT:
		ipv4_sk_redirect(skb, sk);
		goto out;
	}

	/*
 * RFC1122: OK. Passes ICMP errors back to application, as per
 * 4.1.3.3.
 */
	if (!inet->recverr) {
		if (!harderr || sk->sk_state != TCP_ESTABLISHED)
			goto out;
	} else
		ip_icmp_error(sk, skb, err, uh->dest, info, (u8 *)(uh+1));

	sk->sk_err = err;
	sk->sk_error_report(sk);
out:
	sock_put(sk);
}

void udp_err(struct sk_buff *skb, u32 info)
{
	__udp4_lib_err(skb, info, &udp_table);
}

/*
 * Throw away all pending data and cancel the corking. Socket is locked.
 */
void udp_flush_pending_frames(struct sock *sk)
{
	struct udp_sock *up = udp_sk(sk);

	if (up->pending) {
		up->len = 0;
		up->pending = 0;
		ip_flush_pending_frames(sk);
	}
}
EXPORT_SYMBOL(udp_flush_pending_frames);

/**
 * udp4_hwcsum - handle outgoing HW checksumming
 * @skb: sk_buff containing the filled-in UDP header
 * (checksum field must be zeroed out)
 * @src: source IP address
 * @dst: destination IP address
 */
void udp4_hwcsum(struct sk_buff *skb, __be32 src, __be32 dst)
{
	struct udphdr *uh = udp_hdr(skb);
	struct sk_buff *frags = skb_shinfo(skb)->frag_list;
	int offset = skb_transport_offset(skb);
	int len = skb->len - offset;
	int hlen = len;
	__wsum csum = 0;

	if (!frags) {
		/*
 * Only one fragment on the socket.
 */
		skb->csum_start = skb_transport_header(skb) - skb->head;
		skb->csum_offset = offsetof(struct udphdr, check);
		uh->check = ~csum_tcpudp_magic(src, dst, len,
					       IPPROTO_UDP, 0);
	} else {
		/*
 * HW-checksum won't work as there are two or more
 * fragments on the socket so that all csums of sk_buffs
 * should be together
 */
		do {
			csum = csum_add(csum, frags->csum);
			hlen -= frags->len;
		} while ((frags = frags->next));

		csum = skb_checksum(skb, offset, hlen, csum);
		skb->ip_summed = CHECKSUM_NONE;

		uh->check = csum_tcpudp_magic(src, dst, len, IPPROTO_UDP, csum);
		if (uh->check == 0)
			uh->check = CSUM_MANGLED_0;
	}
}
EXPORT_SYMBOL_GPL(udp4_hwcsum);

static int udp_send_skb(struct sk_buff *skb, struct flowi4 *fl4)
{
	struct sock *sk = skb->sk;
	struct inet_sock *inet = inet_sk(sk);
	struct udphdr *uh;
	int err = 0;
	int is_udplite = IS_UDPLITE(sk);
	int offset = skb_transport_offset(skb);
	int len = skb->len - offset;
	__wsum csum = 0;

	/*
 * Create a UDP header
 */
	uh = udp_hdr(skb);
	uh->source = inet->inet_sport;
	uh->dest = fl4->fl4_dport;
	uh->len = htons(len);
	uh->check = 0;

	if (is_udplite)  				 /* UDP-Lite */
		csum = udplite_csum(skb);

	else if (sk->sk_no_check == UDP_CSUM_NOXMIT) {   /* UDP csum disabled */

		skb->ip_summed = CHECKSUM_NONE;
		goto send;

	} else if (skb->ip_summed == CHECKSUM_PARTIAL) { /* UDP hardware csum */

		udp4_hwcsum(skb, fl4->saddr, fl4->daddr);
		goto send;

	} else
		csum = udp_csum(skb);

	/* add protocol-dependent pseudo-header */
	uh->check = csum_tcpudp_magic(fl4->saddr, fl4->daddr, len,
				      sk->sk_protocol, csum);
	if (uh->check == 0)
		uh->check = CSUM_MANGLED_0;

send:
	err = ip_send_skb(sock_net(sk), skb);
	if (err) {
		if (err == -ENOBUFS && !inet->recverr) {
			UDP_INC_STATS_USER(sock_net(sk),
					   UDP_MIB_SNDBUFERRORS, is_udplite);
			err = 0;
		}
	} else
		UDP_INC_STATS_USER(sock_net(sk),
				   UDP_MIB_OUTDATAGRAMS, is_udplite);
	return err;
}

/*
 * Push out all pending data as one UDP datagram. Socket is locked.
 */
int udp_push_pending_frames(struct sock *sk)
{
	struct udp_sock  *up = udp_sk(sk);
	struct inet_sock *inet = inet_sk(sk);
	struct flowi4 *fl4 = &inet->cork.fl.u.ip4;
	struct sk_buff *skb;
	int err = 0;

	skb = ip_finish_skb(sk, fl4);
	if (!skb)
		goto out;

	err = udp_send_skb(skb, fl4);

out:
	up->len = 0;
	up->pending = 0;
	return err;
}
EXPORT_SYMBOL(udp_push_pending_frames);

int udp_sendmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
		size_t len)
{
	struct inet_sock *inet = inet_sk(sk);
	struct udp_sock *up = udp_sk(sk);
	struct flowi4 fl4_stack;
	struct flowi4 *fl4;
	int ulen = len;
	struct ipcm_cookie ipc;
	struct rtable *rt = NULL;
	int free = 0;
	int connected = 0;
	__be32 daddr, faddr, saddr;
	__be16 dport;
	u8  tos;
	int err, is_udplite = IS_UDPLITE(sk);
	int corkreq = up->corkflag || msg->msg_flags&MSG_MORE;
	int (*getfrag)(void *, char *, int, int, int, struct sk_buff *);
	struct sk_buff *skb;
	struct ip_options_data opt_copy;

	if (len > 0xFFFF)
		return -EMSGSIZE;

	/*
 * Check the flags.
 */

	if (msg->msg_flags & MSG_OOB) /* Mirror BSD error message compatibility */
		return -EOPNOTSUPP;

	ipc.opt = NULL;
	ipc.tx_flags = 0;
	ipc.ttl = 0;
	ipc.tos = -1;

	getfrag = is_udplite ? udplite_getfrag : ip_generic_getfrag;

	fl4 = &inet->cork.fl.u.ip4;
	if (up->pending) {
		/*
 * There are pending frames.
 * The socket lock must be held while it's corked.
 */
		lock_sock(sk);
		if (likely(up->pending)) {
			if (unlikely(up->pending != AF_INET)) {
				release_sock(sk);
				return -EINVAL;
			}
			goto do_append_data;
		}
		release_sock(sk);
	}
	ulen += sizeof(struct udphdr);

	/*
 * Get and verify the address.
 */
	if (msg->msg_name) {
		struct sockaddr_in *usin = (struct sockaddr_in *)msg->msg_name;
		if (msg->msg_namelen < sizeof(*usin))
			return -EINVAL;
		if (usin->sin_family != AF_INET) {
			if (usin->sin_family != AF_UNSPEC)
				return -EAFNOSUPPORT;
		}

		daddr = usin->sin_addr.s_addr;
		dport = usin->sin_port;
		if (dport == 0)
			return -EINVAL;
	} else {
		if (sk->sk_state != TCP_ESTABLISHED)
			return -EDESTADDRREQ;
		daddr = inet->inet_daddr;
		dport = inet->inet_dport;
		/* Open fast path for connected socket.
 Route will not be used, if at least one option is set.
 */
		connected = 1;
	}
	ipc.addr = inet->inet_saddr;

	ipc.oif = sk->sk_bound_dev_if;

	sock_tx_timestamp(sk, &ipc.tx_flags);

	if (msg->msg_controllen) {
		err = ip_cmsg_send(sock_net(sk), msg, &ipc);
		if (err)
			return err;
		if (ipc.opt)
			free = 1;
		connected = 0;
	}
	if (!ipc.opt) {
		struct ip_options_rcu *inet_opt;

		rcu_read_lock();
		inet_opt = rcu_dereference(inet->inet_opt);
		if (inet_opt) {
			memcpy(&opt_copy, inet_opt,
			       sizeof(*inet_opt) + inet_opt->opt.optlen);
			ipc.opt = &opt_copy.opt;
		}
		rcu_read_unlock();
	}

	saddr = ipc.addr;
	ipc.addr = faddr = daddr;

	if (ipc.opt && ipc.opt->opt.srr) {
		if (!daddr)
			return -EINVAL;
		faddr = ipc.opt->opt.faddr;
		connected = 0;
	}
	tos = get_rttos(&ipc, inet);
	if (sock_flag(sk, SOCK_LOCALROUTE) ||
	    (msg->msg_flags & MSG_DONTROUTE) ||
	    (ipc.opt && ipc.opt->opt.is_strictroute)) {
		tos |= RTO_ONLINK;
		connected = 0;
	}

	if (ipv4_is_multicast(daddr)) {
		if (!ipc.oif)
			ipc.oif = inet->mc_index;
		if (!saddr)
			saddr = inet->mc_addr;
		connected = 0;
	} else if (!ipc.oif)
		ipc.oif = inet->uc_index;

	if (connected)
		rt = (struct rtable *)sk_dst_check(sk, 0);

	if (rt == NULL) {
		struct net *net = sock_net(sk);

		fl4 = &fl4_stack;
		flowi4_init_output(fl4, ipc.oif, sk->sk_mark, tos,
				   RT_SCOPE_UNIVERSE, sk->sk_protocol,
				   inet_sk_flowi_flags(sk)|FLOWI_FLAG_CAN_SLEEP,
				   faddr, saddr, dport, inet->inet_sport);

		security_sk_classify_flow(sk, flowi4_to_flowi(fl4));
		rt = ip_route_output_flow(net, fl4, sk);
		if (IS_ERR(rt)) {
			err = PTR_ERR(rt);
			rt = NULL;
			if (err == -ENETUNREACH)
				IP_INC_STATS_BH(net, IPSTATS_MIB_OUTNOROUTES);
			goto out;
		}

		err = -EACCES;
		if ((rt->rt_flags & RTCF_BROADCAST) &&
		    !sock_flag(sk, SOCK_BROADCAST))
			goto out;
		if (connected)
			sk_dst_set(sk, dst_clone(&rt->dst));
	}

	if (msg->msg_flags&MSG_CONFIRM)
		goto do_confirm;
back_from_confirm:

	saddr = fl4->saddr;
	if (!ipc.addr)
		daddr = ipc.addr = fl4->daddr;

	/* Lockless fast path for the non-corking case. */
	if (!corkreq) {
		skb = ip_make_skb(sk, fl4, getfrag, msg->msg_iov, ulen,
				  sizeof(struct udphdr), &ipc, &rt,
				  msg->msg_flags);
		err = PTR_ERR(skb);
		if (!IS_ERR_OR_NULL(skb))
			err = udp_send_skb(skb, fl4);
		goto out;
	}

	lock_sock(sk);
	if (unlikely(up->pending)) {
		/* The socket is already corked while preparing it. */
		/* ... which is an evident application bug. --ANK */
		release_sock(sk);

		LIMIT_NETDEBUG(KERN_DEBUG pr_fmt("cork app bug 2\n"));
		err = -EINVAL;
		goto out;
	}
	/*
 * Now cork the socket to pend data.
 */
	fl4 = &inet->cork.fl.u.ip4;
	fl4->daddr = daddr;
	fl4->saddr = saddr;
	fl4->fl4_dport = dport;
	fl4->fl4_sport = inet->inet_sport;
	up->pending = AF_INET;

do_append_data:
	up->len += ulen;
	err = ip_append_data(sk, fl4, getfrag, msg->msg_iov, ulen,
			     sizeof(struct udphdr), &ipc, &rt,
			     corkreq ? msg->msg_flags|MSG_MORE : msg->msg_flags);
	if (err)
		udp_flush_pending_frames(sk);
	else if (!corkreq)
		err = udp_push_pending_frames(sk);
	else if (unlikely(skb_queue_empty(&sk->sk_write_queue)))
		up->pending = 0;
	release_sock(sk);

out:
	ip_rt_put(rt);
	if (free)
		kfree(ipc.opt);
	if (!err)
		return len;
	/*
 * ENOBUFS = no kernel mem, SOCK_NOSPACE = no sndbuf space. Reporting
 * ENOBUFS might not be good (it's not tunable per se), but otherwise
 * we don't have a good statistic (IpOutDiscards but it can be too many
 * things). We could add another new stat but at least for now that
 * seems like overkill.
 */
	if (err == -ENOBUFS || test_bit(SOCK_NOSPACE, &sk->sk_socket->flags)) {
		UDP_INC_STATS_USER(sock_net(sk),
				UDP_MIB_SNDBUFERRORS, is_udplite);
	}
	return err;

do_confirm:
	dst_confirm(&rt->dst);
	if (!(msg->msg_flags&MSG_PROBE) || len)
		goto back_from_confirm;
	err = 0;
	goto out;
}
EXPORT_SYMBOL(udp_sendmsg);

int udp_sendpage(struct sock *sk, struct page *page, int offset,
		 size_t size, int flags)
{
	struct inet_sock *inet = inet_sk(sk);
	struct udp_sock *up = udp_sk(sk);
	int ret;

	if (!up->pending) {
		struct msghdr msg = { .msg_flags = flags|MSG_MORE };

		/* Call udp_sendmsg to specify destination address which
 * sendpage interface can't pass.
 * This will succeed only when the socket is connected.
 */
		ret = udp_sendmsg(NULL, sk, &msg, 0);
		if (ret < 0)
			return ret;
	}

	lock_sock(sk);

	if (unlikely(!up->pending)) {
		release_sock(sk);

		LIMIT_NETDEBUG(KERN_DEBUG pr_fmt("udp cork app bug 3\n"));
		return -EINVAL;
	}

	ret = ip_append_page(sk, &inet->cork.fl.u.ip4,
			     page, offset, size, flags);
	if (ret == -EOPNOTSUPP) {
		release_sock(sk);
		return sock_no_sendpage(sk->sk_socket, page, offset,
					size, flags);
	}
	if (ret < 0) {
		udp_flush_pending_frames(sk);
		goto out;
	}

	up->len += size;
	if (!(up->corkflag || (flags&MSG_MORE)))
		ret = udp_push_pending_frames(sk);
	if (!ret)
		ret = size;
out:
	release_sock(sk);
	return ret;
}


/**
 * first_packet_length - return length of first packet in receive queue
 * @sk: socket
 *
 * Drops all bad checksum frames, until a valid one is found.
 * Returns the length of found skb, or 0 if none is found.
 */
static unsigned int first_packet_length(struct sock *sk)
{
	struct sk_buff_head list_kill, *rcvq = &sk->sk_receive_queue;
	struct sk_buff *skb;
	unsigned int res;

	__skb_queue_head_init(&list_kill);

	spin_lock_bh(&rcvq->lock);
	while ((skb = skb_peek(rcvq)) != NULL &&
		udp_lib_checksum_complete(skb)) {
		UDP_INC_STATS_BH(sock_net(sk), UDP_MIB_CSUMERRORS,
				 IS_UDPLITE(sk));
		UDP_INC_STATS_BH(sock_net(sk), UDP_MIB_INERRORS,
				 IS_UDPLITE(sk));
		atomic_inc(&sk->sk_drops);
		__skb_unlink(skb, rcvq);
		__skb_queue_tail(&list_kill, skb);
	}
	res = skb ? skb->len : 0;
	spin_unlock_bh(&rcvq->lock);

	if (!skb_queue_empty(&list_kill)) {
		bool slow = lock_sock_fast(sk);

		__skb_queue_purge(&list_kill);
		sk_mem_reclaim_partial(sk);
		unlock_sock_fast(sk, slow);
	}
	return res;
}

/*
 * IOCTL requests applicable to the UDP protocol
 */

int udp_ioctl(struct sock *sk, int cmd, unsigned long arg)
{
	switch (cmd) {
	case SIOCOUTQ:
	{
		int amount = sk_wmem_alloc_get(sk);

		return put_user(amount, (int __user *)arg);
	}

	case SIOCINQ:
	{
		unsigned int amount = first_packet_length(sk);

		if (amount)
			/*
 * We will only return the amount
 * of this packet since that is all
 * that will be read.
 */
			amount -= sizeof(struct udphdr);

		return put_user(amount, (int __user *)arg);
	}

	default:
		return -ENOIOCTLCMD;
	}

	return 0;
}
EXPORT_SYMBOL(udp_ioctl);

/*
 * This should be easy, if there is something there we
 * return it, otherwise we block.
 */

int udp_recvmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
		size_t len, int noblock, int flags, int *addr_len)
{
	struct inet_sock *inet = inet_sk(sk);
	struct sockaddr_in *sin = (struct sockaddr_in *)msg->msg_name;
	struct sk_buff *skb;
	unsigned int ulen, copied;
	int peeked, off = 0;
	int err;
	int is_udplite = IS_UDPLITE(sk);
	bool slow;

	/*
 * Check any passed addresses
 */
	if (addr_len)
		*addr_len = sizeof(*sin);

	if (flags & MSG_ERRQUEUE)
		return ip_recv_error(sk, msg, len);

try_again:
	skb = __skb_recv_datagram(sk, flags | (noblock ? MSG_DONTWAIT : 0),
				  &peeked, &off, &err);
	if (!skb)
		goto out;

	ulen = skb->len - sizeof(struct udphdr);
	copied = len;
	if (copied > ulen)
		copied = ulen;
	else if (copied < ulen)
		msg->msg_flags |= MSG_TRUNC;

	/*
 * If checksum is needed at all, try to do it while copying the
 * data. If the data is truncated, or if we only want a partial
 * coverage checksum (UDP-Lite), do it before the copy.
 */

	if (copied < ulen || UDP_SKB_CB(skb)->partial_cov) {
		if (udp_lib_checksum_complete(skb))
			goto csum_copy_err;
	}

	if (skb_csum_unnecessary(skb))
		err = skb_copy_datagram_iovec(skb, sizeof(struct udphdr),
					      msg->msg_iov, copied);
	else {
		err = skb_copy_and_csum_datagram_iovec(skb,
						       sizeof(struct udphdr),
						       msg->msg_iov);

		if (err == -EINVAL)
			goto csum_copy_err;
	}

	if (unlikely(err)) {
		trace_kfree_skb(skb, udp_recvmsg);
		if (!peeked) {
			atomic_inc(&sk->sk_drops);
			UDP_INC_STATS_USER(sock_net(sk),
					   UDP_MIB_INERRORS, is_udplite);
		}
		goto out_free;
	}

	if (!peeked)
		UDP_INC_STATS_USER(sock_net(sk),
				UDP_MIB_INDATAGRAMS, is_udplite);

	sock_recv_ts_and_drops(msg, sk, skb);

	/* Copy the address. */
	if (sin) {
		sin->sin_family = AF_INET;
		sin->sin_port = udp_hdr(skb)->source;
		sin->sin_addr.s_addr = ip_hdr(skb)->saddr;
		memset(sin->sin_zero, 0, sizeof(sin->sin_zero));
	}
	if (inet->cmsg_flags)
		ip_cmsg_recv(msg, skb);

	err = copied;
	if (flags & MSG_TRUNC)
		err = ulen;

out_free:
	skb_free_datagram_locked(sk, skb);
out:
	return err;

csum_copy_err:
	slow = lock_sock_fast(sk);
	if (!skb_kill_datagram(sk, skb, flags)) {
		UDP_INC_STATS_USER(sock_net(sk), UDP_MIB_CSUMERRORS, is_udplite);
		UDP_INC_STATS_USER(sock_net(sk), UDP_MIB_INERRORS, is_udplite);
	}
	unlock_sock_fast(sk, slow);

	if (noblock)
		return -EAGAIN;

	/* starting over for a new packet */
	msg->msg_flags &= ~MSG_TRUNC;
	goto try_again;
}


int udp_disconnect(struct sock *sk, int flags)
{
	struct inet_sock *inet = inet_sk(sk);
	/*
 * 1003.1g - break association.
 */

	sk->sk_state = TCP_CLOSE;
	inet->inet_daddr = 0;
	inet->inet_dport = 0;
	sock_rps_reset_rxhash(sk);
	sk->sk_bound_dev_if = 0;
	if (!(sk->sk_userlocks & SOCK_BINDADDR_LOCK))
		inet_reset_saddr(sk);

	if (!(sk->sk_userlocks & SOCK_BINDPORT_LOCK)) {
		sk->sk_prot->unhash(sk);
		inet->inet_sport = 0;
	}
	sk_dst_reset(sk);
	return 0;
}
EXPORT_SYMBOL(udp_disconnect);

void udp_lib_unhash(struct sock *sk)
{
	if (sk_hashed(sk)) {
		struct udp_table *udptable = sk->sk_prot->h.udp_table;
		struct udp_hslot *hslot, *hslot2;

		hslot  = udp_hashslot(udptable, sock_net(sk),
				      udp_sk(sk)->udp_port_hash);
		hslot2 = udp_hashslot2(udptable, udp_sk(sk)->udp_portaddr_hash);

		spin_lock_bh(&hslot->lock);
		if (sk_nulls_del_node_init_rcu(sk)) {
			hslot->count--;
			inet_sk(sk)->inet_num = 0;
			sock_prot_inuse_add(sock_net(sk), sk->sk_prot, -1);

			spin_lock(&hslot2->lock);
			hlist_nulls_del_init_rcu(&udp_sk(sk)->udp_portaddr_node);
			hslot2->count--;
			spin_unlock(&hslot2->lock);
		}
		spin_unlock_bh(&hslot->lock);
	}
}
EXPORT_SYMBOL(udp_lib_unhash);

/*
 * inet_rcv_saddr was changed, we must rehash secondary hash
 */
void udp_lib_rehash(struct sock *sk, u16 newhash)
{
	if (sk_hashed(sk)) {
		struct udp_table *udptable = sk->sk_prot->h.udp_table;
		struct udp_hslot *hslot, *hslot2, *nhslot2;

		hslot2 = udp_hashslot2(udptable, udp_sk(sk)->udp_portaddr_hash);
		nhslot2 = udp_hashslot2(udptable, newhash);
		udp_sk(sk)->udp_portaddr_hash = newhash;
		if (hslot2 != nhslot2) {
			hslot = udp_hashslot(udptable, sock_net(sk),
					     udp_sk(sk)->udp_port_hash);
			/* we must lock primary chain too */
			spin_lock_bh(&hslot->lock);

			spin_lock(&hslot2->lock);
			hlist_nulls_del_init_rcu(&udp_sk(sk)->udp_portaddr_node);
			hslot2->count--;
			spin_unlock(&hslot2->lock);

			spin_lock(&nhslot2->lock);
			hlist_nulls_add_head_rcu(&udp_sk(sk)->udp_portaddr_node,
						 &nhslot2->head);
			nhslot2->count++;
			spin_unlock(&nhslot2->lock);

			spin_unlock_bh(&hslot->lock);
		}
	}
}
EXPORT_SYMBOL(udp_lib_rehash);

static void udp_v4_rehash(struct sock *sk)
{
	u16 new_hash = udp4_portaddr_hash(sock_net(sk),
					  inet_sk(sk)->inet_rcv_saddr,
					  inet_sk(sk)->inet_num);
	udp_lib_rehash(sk, new_hash);
}

static int __udp_queue_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	int rc;

	if (inet_sk(sk)->inet_daddr) {
		sock_rps_save_rxhash(sk, skb);
		sk_mark_napi_id(sk, skb);
	}

	rc = sock_queue_rcv_skb(sk, skb);
	if (rc < 0) {
		int is_udplite = IS_UDPLITE(sk);

		/* Note that an ENOMEM error is charged twice */
		if (rc == -ENOMEM)
			UDP_INC_STATS_BH(sock_net(sk), UDP_MIB_RCVBUFERRORS,
					 is_udplite);
		UDP_INC_STATS_BH(sock_net(sk), UDP_MIB_INERRORS, is_udplite);
		kfree_skb(skb);
		trace_udp_fail_queue_rcv_skb(rc, sk);
		return -1;
	}

	return 0;

}

static struct static_key udp_encap_needed __read_mostly;
void udp_encap_enable(void)
{
	if (!static_key_enabled(&udp_encap_needed))
		static_key_slow_inc(&udp_encap_needed);
}
EXPORT_SYMBOL(udp_encap_enable);

/* returns:
 * -1: error
 * 0: success
 * >0: "udp encap" protocol resubmission
 *
 * Note that in the success and error cases, the skb is assumed to
 * have either been requeued or freed.
 */
int udp_queue_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	struct udp_sock *up = udp_sk(sk);
	int rc;
	int is_udplite = IS_UDPLITE(sk);

	/*
 * Charge it to the socket, dropping if the queue is full.
 */
	if (!xfrm4_policy_check(sk, XFRM_POLICY_IN, skb))
		goto drop;
	nf_reset(skb);

	if (static_key_false(&udp_encap_needed) && up->encap_type) {
		int (*encap_rcv)(struct sock *sk, struct sk_buff *skb);

		/*
 * This is an encapsulation socket so pass the skb to
 * the socket's udp_encap_rcv() hook. Otherwise, just
 * fall through and pass this up the UDP socket.
 * up->encap_rcv() returns the following value:
 * =0 if skb was successfully passed to the encap
 * handler or was discarded by it.
 * >0 if skb should be passed on to UDP.
 * <0 if skb should be resubmitted as proto -N
 */

		/* if we're overly short, let UDP handle it */
		encap_rcv = ACCESS_ONCE(up->encap_rcv);
		if (skb->len > sizeof(struct udphdr) && encap_rcv != NULL) {
			int ret;

			ret = encap_rcv(sk, skb);
			if (ret <= 0) {
				UDP_INC_STATS_BH(sock_net(sk),
						 UDP_MIB_INDATAGRAMS,
						 is_udplite);
				return -ret;
			}
		}

		/* FALLTHROUGH -- it's a UDP Packet */
	}

	/*
 * UDP-Lite specific tests, ignored on UDP sockets
 */
	if ((is_udplite & UDPLITE_RECV_CC) &&  UDP_SKB_CB(skb)->partial_cov) {

		/*
 * MIB statistics other than incrementing the error count are
 * disabled for the following two types of errors: these depend
 * on the application settings, not on the functioning of the
 * protocol stack as such.
 *
 * RFC 3828 here recommends (sec 3.3): "There should also be a
 * way ... to ... at least let the receiving application block
 * delivery of packets with coverage values less than a value
 * provided by the application."
 */
		if (up->pcrlen == 0) {          /* full coverage was set */
			LIMIT_NETDEBUG(KERN_WARNING "UDPLite: partial coverage %d while full coverage %d requested\n",
				       UDP_SKB_CB(skb)->cscov, skb->len);
			goto drop;
		}
		/* The next case involves violating the min. coverage requested
 * by the receiver. This is subtle: if receiver wants x and x is
 * greater than the buffersize/MTU then receiver will complain
 * that it wants x while sender emits packets of smaller size y.
 * Therefore the above ...()->partial_cov statement is essential.
 */
		if (UDP_SKB_CB(skb)->cscov  <  up->pcrlen) {
			LIMIT_NETDEBUG(KERN_WARNING "UDPLite: coverage %d too small, need min %d\n",
				       UDP_SKB_CB(skb)->cscov, up->pcrlen);
			goto drop;
		}
	}

	if (rcu_access_pointer(sk->sk_filter) &&
	    udp_lib_checksum_complete(skb))
		goto csum_error;


	if (sk_rcvqueues_full(sk, skb, sk->sk_rcvbuf))
		goto drop;

	rc = 0;

	ipv4_pktinfo_prepare(sk, skb);
	bh_lock_sock(sk);
	if (!sock_owned_by_user(sk))
		rc = __udp_queue_rcv_skb(sk, skb);
	else if (sk_add_backlog(sk, skb, sk->sk_rcvbuf)) {
		bh_unlock_sock(sk);
		goto drop;
	}
	bh_unlock_sock(sk);

	return rc;

csum_error:
	UDP_INC_STATS_BH(sock_net(sk), UDP_MIB_CSUMERRORS, is_udplite);
drop:
	UDP_INC_STATS_BH(sock_net(sk), UDP_MIB_INERRORS, is_udplite);
	atomic_inc(&sk->sk_drops);
	kfree_skb(skb);
	return -1;
}


static void flush_stack(struct sock **stack, unsigned int count,
			struct sk_buff *skb, unsigned int final)
{
	unsigned int i;
	struct sk_buff *skb1 = NULL;
	struct sock *sk;

	for (i = 0; i < count; i++) {
		sk = stack[i];
		if (likely(skb1 == NULL))
			skb1 = (i == final) ? skb : skb_clone(skb, GFP_ATOMIC);

		if (!skb1) {
			atomic_inc(&sk->sk_drops);
			UDP_INC_STATS_BH(sock_net(sk), UDP_MIB_RCVBUFERRORS,
					 IS_UDPLITE(sk));
			UDP_INC_STATS_BH(sock_net(sk), UDP_MIB_INERRORS,
					 IS_UDPLITE(sk));
		}

		if (skb1 && udp_queue_rcv_skb(sk, skb1) <= 0)
			skb1 = NULL;
	}
	if (unlikely(skb1))
		kfree_skb(skb1);
}

static void udp_sk_rx_dst_set(struct sock *sk, const struct sk_buff *skb)
{
	struct dst_entry *dst = skb_dst(skb);

	dst_hold(dst);
	sk->sk_rx_dst = dst;
}

/*
 * Multicasts and broadcasts go to each listener.
 *
 * Note: called only from the BH handler context.
 */
static int __udp4_lib_mcast_deliver(struct net *net, struct sk_buff *skb,
				    struct udphdr  *uh,
				    __be32 saddr, __be32 daddr,
				    struct udp_table *udptable)
{
	struct sock *sk, *stack[256 / sizeof(struct sock *)];
	struct udp_hslot *hslot = udp_hashslot(udptable, net, ntohs(uh->dest));
	int dif;
	unsigned int i, count = 0;

	spin_lock(&hslot->lock);
	sk = sk_nulls_head(&hslot->head);
	dif = skb->dev->ifindex;
	sk = udp_v4_mcast_next(net, sk, uh->dest, daddr, uh->source, saddr, dif);
	while (sk) {
		stack[count++] = sk;
		sk = udp_v4_mcast_next(net, sk_nulls_next(sk), uh->dest,
				       daddr, uh->source, saddr, dif);
		if (unlikely(count == ARRAY_SIZE(stack))) {
			if (!sk)
				break;
			flush_stack(stack, count, skb, ~0);
			count = 0;
		}
	}
	/*
 * before releasing chain lock, we must take a reference on sockets
 */
	for (i = 0; i < count; i++)
		sock_hold(stack[i]);

	spin_unlock(&hslot->lock);

	/*
 * do the slow work with no lock held
 */
	if (count) {
		flush_stack(stack, count, skb, count - 1);

		for (i = 0; i < count; i++)
			sock_put(stack[i]);
	} else {
		kfree_skb(skb);
	}
	return 0;
}

/* Initialize UDP checksum. If exited with zero value (success),
 * CHECKSUM_UNNECESSARY means, that no more checks are required.
 * Otherwise, csum completion requires chacksumming packet body,
 * including udp header and folding it to skb->csum.
 */
static inline int udp4_csum_init(struct sk_buff *skb, struct udphdr *uh,
				 int proto)
{
	const struct iphdr *iph;
	int err;

	UDP_SKB_CB(skb)->partial_cov = 0;
	UDP_SKB_CB(skb)->cscov = skb->len;

	if (proto == IPPROTO_UDPLITE) {
		err = udplite_checksum_init(skb, uh);
		if (err)
			return err;
	}

	iph = ip_hdr(skb);
	if (uh->check == 0) {
		skb->ip_summed = CHECKSUM_UNNECESSARY;
	} else if (skb->ip_summed == CHECKSUM_COMPLETE) {
		if (!csum_tcpudp_magic(iph->saddr, iph->daddr, skb->len,
				      proto, skb->csum))
			skb->ip_summed = CHECKSUM_UNNECESSARY;
	}
	if (!skb_csum_unnecessary(skb))
		skb->csum = csum_tcpudp_nofold(iph->saddr, iph->daddr,
					       skb->len, proto, 0);
	/* Probably, we should checksum udp header (it should be in cache
 * in any case) and data in tiny packets (< rx copybreak).
 */

	return 0;
}

/*
 * All we need to do is get the socket, and then do a checksum.
 */

int __udp4_lib_rcv(struct sk_buff *skb, struct udp_table *udptable,
		   int proto)
{
	struct sock *sk;
	struct udphdr *uh;
	unsigned short ulen;
	struct rtable *rt = skb_rtable(skb);
	__be32 saddr, daddr;
	struct net *net = dev_net(skb->dev);

	/*
 * Validate the packet.
 */
	if (!pskb_may_pull(skb, sizeof(struct udphdr)))
		goto drop;		/* No space for header. */

	uh   = udp_hdr(skb);
	ulen = ntohs(uh->len);
	saddr = ip_hdr(skb)->saddr;
	daddr = ip_hdr(skb)->daddr;

	if (ulen > skb->len)
		goto short_packet;

	if (proto == IPPROTO_UDP) {
		/* UDP validates ulen. */
		if (ulen < sizeof(*uh) || pskb_trim_rcsum(skb, ulen))
			goto short_packet;
		uh = udp_hdr(skb);
	}

	if (udp4_csum_init(skb, uh, proto))
		goto csum_error;

	if (skb->sk) {
		int ret;
		sk = skb->sk;

		if (unlikely(sk->sk_rx_dst == NULL))
			udp_sk_rx_dst_set(sk, skb);

		ret = udp_queue_rcv_skb(sk, skb);

		/* a return value > 0 means to resubmit the input, but
 * it wants the return to be -protocol, or 0
 */
		if (ret > 0)
			return -ret;
		return 0;
	} else {
		if (rt->rt_flags & (RTCF_BROADCAST|RTCF_MULTICAST))
			return __udp4_lib_mcast_deliver(net, skb, uh,
					saddr, daddr, udptable);

		sk = __udp4_lib_lookup_skb(skb, uh->source, uh->dest, udptable);
	}

	if (sk != NULL) {
		int ret;

		ret = udp_queue_rcv_skb(sk, skb);
		sock_put(sk);

		/* a return value > 0 means to resubmit the input, but
 * it wants the return to be -protocol, or 0
 */
		if (ret > 0)
			return -ret;
		return 0;
	}

	if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb))
		goto drop;
	nf_reset(skb);

	/* No socket. Drop packet silently, if checksum is wrong */
	if (udp_lib_checksum_complete(skb))
		goto csum_error;

	UDP_INC_STATS_BH(net, UDP_MIB_NOPORTS, proto == IPPROTO_UDPLITE);
	icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, 0);

	/*
 * Hmm. We got an UDP packet to a port to which we
 * don't wanna listen. Ignore it.
 */
	kfree_skb(skb);
	return 0;

short_packet:
	LIMIT_NETDEBUG(KERN_DEBUG "UDP%s: short packet: From %pI4:%u %d/%d to %pI4:%u\n",
		       proto == IPPROTO_UDPLITE ? "Lite" : "",
		       &saddr, ntohs(uh->source),
		       ulen, skb->len,
		       &daddr, ntohs(uh->dest));
	goto drop;

csum_error:
	/*
 * RFC1122: OK. Discards the bad packet silently (as far as
 * the network is concerned, anyway) as per 4.1.3.4 (MUST).
 */
	LIMIT_NETDEBUG(KERN_DEBUG "UDP%s: bad checksum. From %pI4:%u to %pI4:%u ulen %d\n",
		       proto == IPPROTO_UDPLITE ? "Lite" : "",
		       &saddr, ntohs(uh->source), &daddr, ntohs(uh->dest),
		       ulen);
	UDP_INC_STATS_BH(net, UDP_MIB_CSUMERRORS, proto == IPPROTO_UDPLITE);
drop:
	UDP_INC_STATS_BH(net, UDP_MIB_INERRORS, proto == IPPROTO_UDPLITE);
	kfree_skb(skb);
	return 0;
}

/* We can only early demux multicast if there is a single matching socket.
 * If more than one socket found returns NULL
 */
static struct sock *__udp4_lib_mcast_demux_lookup(struct net *net,
						  __be16 loc_port, __be32 loc_addr,
						  __be16 rmt_port, __be32 rmt_addr,
						  int dif)
{
	struct sock *sk, *result;
	struct hlist_nulls_node *node;
	unsigned short hnum = ntohs(loc_port);
	unsigned int count, slot = udp_hashfn(net, hnum, udp_table.mask);
	struct udp_hslot *hslot = &udp_table.hash[slot];

	rcu_read_lock();
begin:
	count = 0;
	result = NULL;
	sk_nulls_for_each_rcu(sk, node, &hslot->head) {
		if (__udp_is_mcast_sock(net, sk,
					loc_port, loc_addr,
					rmt_port, rmt_addr,
					dif, hnum)) {
			result = sk;
			++count;
		}
	}
	/*
 * if the nulls value we got at the end of this lookup is
 * not the expected one, we must restart lookup.
 * We probably met an item that was moved to another chain.
 */
	if (get_nulls_value(node) != slot)
		goto begin;

	if (result) {
		if (count != 1 ||
		    unlikely(!atomic_inc_not_zero_hint(&result->sk_refcnt, 2)))
			result = NULL;
		else if (unlikely(!__udp_is_mcast_sock(net, result,
						       loc_port, loc_addr,
						       rmt_port, rmt_addr,
						       dif, hnum))) {
			sock_put(result);
			result = NULL;
		}
	}
	rcu_read_unlock();
	return result;
}

/* For unicast we should only early demux connected sockets or we can
 * break forwarding setups. The chains here can be long so only check
 * if the first socket is an exact match and if not move on.
 */
static struct sock *__udp4_lib_demux_lookup(struct net *net,
					    __be16 loc_port, __be32 loc_addr,
					    __be16 rmt_port, __be32 rmt_addr,
					    int dif)
{
	struct sock *sk, *result;
	struct hlist_nulls_node *node;
	unsigned short hnum = ntohs(loc_port);
	unsigned int hash2 = udp4_portaddr_hash(net, loc_addr, hnum);
	unsigned int slot2 = hash2 & udp_table.mask;
	struct udp_hslot *hslot2 = &udp_table.hash2[slot2];
	INET_ADDR_COOKIE(acookie, rmt_addr, loc_addr)
	const __portpair ports = INET_COMBINED_PORTS(rmt_port, hnum);

	rcu_read_lock();
	result = NULL;
	udp_portaddr_for_each_entry_rcu(sk, node, &hslot2->head) {
		if (INET_MATCH(sk, net, acookie,
			       rmt_addr, loc_addr, ports, dif))
			result = sk;
		/* Only check first socket in chain */
		break;
	}

	if (result) {
		if (unlikely(!atomic_inc_not_zero_hint(&result->sk_refcnt, 2)))
			result = NULL;
		else if (unlikely(!INET_MATCH(sk, net, acookie,
					      rmt_addr, loc_addr,
					      ports, dif))) {
			sock_put(result);
			result = NULL;
		}
	}
	rcu_read_unlock();
	return result;
}

void udp_v4_early_demux(struct sk_buff *skb)
{
	const struct iphdr *iph = ip_hdr(skb);
	const struct udphdr *uh = udp_hdr(skb);
	struct sock *sk;
	struct dst_entry *dst;
	struct net *net = dev_net(skb->dev);
	int dif = skb->dev->ifindex;

	/* validate the packet */
	if (!pskb_may_pull(skb, skb_transport_offset(skb) + sizeof(struct udphdr)))
		return;

	if (skb->pkt_type == PACKET_BROADCAST ||
	    skb->pkt_type == PACKET_MULTICAST)
		sk = __udp4_lib_mcast_demux_lookup(net, uh->dest, iph->daddr,
						   uh->source, iph->saddr, dif);
	else if (skb->pkt_type == PACKET_HOST)
		sk = __udp4_lib_demux_lookup(net, uh->dest, iph->daddr,
					     uh->source, iph->saddr, dif);
	else
		return;

	if (!sk)
		return;

	skb->sk = sk;
	skb->destructor = sock_edemux;
	dst = sk->sk_rx_dst;

	if (dst)
		dst = dst_check(dst, 0);
	if (dst)
		skb_dst_set_noref(skb, dst);
}

int udp_rcv(struct sk_buff *skb)
{
	return __udp4_lib_rcv(skb, &udp_table, IPPROTO_UDP);
}

void udp_destroy_sock(struct sock *sk)
{
	struct udp_sock *up = udp_sk(sk);
	bool slow = lock_sock_fast(sk);
	udp_flush_pending_frames(sk);
	unlock_sock_fast(sk, slow);
	if (static_key_false(&udp_encap_needed) && up->encap_type) {
		void (*encap_destroy)(struct sock *sk);
		encap_destroy = ACCESS_ONCE(up->encap_destroy);
		if (encap_destroy)
			encap_destroy(sk);
	}
}

/*
 * Socket option code for UDP
 */
int udp_lib_setsockopt(struct sock *sk, int level, int optname,
		       char __user *optval, unsigned int optlen,
		       int (*push_pending_frames)(struct sock *))
{
	struct udp_sock *up = udp_sk(sk);
	int val;
	int err = 0;
	int is_udplite = IS_UDPLITE(sk);

	if (optlen < sizeof(int))
		return -EINVAL;

	if (get_user(val, (int __user *)optval))
		return -EFAULT;

	switch (optname) {
	case UDP_CORK:
		if (val != 0) {
			up->corkflag = 1;
		} else {
			up->corkflag = 0;
			lock_sock(sk);
			(*push_pending_frames)(sk);
			release_sock(sk);
		}
		break;

	case UDP_ENCAP:
		switch (val) {
		case 0:
		case UDP_ENCAP_ESPINUDP:
		case UDP_ENCAP_ESPINUDP_NON_IKE:
			up->encap_rcv = xfrm4_udp_encap_rcv;
			/* FALLTHROUGH */
		case UDP_ENCAP_L2TPINUDP:
			up->encap_type = val;
			udp_encap_enable();
			break;
		default:
			err = -ENOPROTOOPT;
			break;
		}
		break;

	/*
 * UDP-Lite's partial checksum coverage (RFC 3828).
 */
	/* The sender sets actual checksum coverage length via this option.
 * The case coverage > packet length is handled by send module. */
	case UDPLITE_SEND_CSCOV:
		if (!is_udplite)         /* Disable the option on UDP sockets */
			return -ENOPROTOOPT;
		if (val != 0 && val < 8) /* Illegal coverage: use default (8) */
			val = 8;
		else if (val > USHRT_MAX)
			val = USHRT_MAX;
		up->pcslen = val;
		up->pcflag |= UDPLITE_SEND_CC;
		break;

	/* The receiver specifies a minimum checksum coverage value. To make
 * sense, this should be set to at least 8 (as done below). If zero is
 * used, this again means full checksum coverage. */
	case UDPLITE_RECV_CSCOV:
		if (!is_udplite)         /* Disable the option on UDP sockets */
			return -ENOPROTOOPT;
		if (val != 0 && val < 8) /* Avoid silly minimal values. */
			val = 8;
		else if (val > USHRT_MAX)
			val = USHRT_MAX;
		up->pcrlen = val;
		up->pcflag |= UDPLITE_RECV_CC;
		break;

	default:
		err = -ENOPROTOOPT;
		break;
	}

	return err;
}
EXPORT_SYMBOL(udp_lib_setsockopt);

int udp_setsockopt(struct sock *sk, int level, int optname,
		   char __user *optval, unsigned int optlen)
{
	if (level == SOL_UDP  ||  level == SOL_UDPLITE)
		return udp_lib_setsockopt(sk, level, optname, optval, optlen,
					  udp_push_pending_frames);
	return ip_setsockopt(sk, level, optname, optval, optlen);
}

#ifdef CONFIG_COMPAT
int compat_udp_setsockopt(struct sock *sk, int level, int optname,
			  char __user *optval, unsigned int optlen)
{
	if (level == SOL_UDP  ||  level == SOL_UDPLITE)
		return udp_lib_setsockopt(sk, level, optname, optval, optlen,
					  udp_push_pending_frames);
	return compat_ip_setsockopt(sk, level, optname, optval, optlen);
}
#endif

int udp_lib_getsockopt(struct sock *sk, int level, int optname,
		       char __user *optval, int __user *optlen)
{
	struct udp_sock *up = udp_sk(sk);
	int val, len;

	if (get_user(len, optlen))
		return -EFAULT;

	len = min_t(unsigned int, len, sizeof(int));

	if (len < 0)
		return -EINVAL;

	switch (optname) {
	case UDP_CORK:
		val = up->corkflag;
		break;

	case UDP_ENCAP:
		val = up->encap_type;
		break;

	/* The following two cannot be changed on UDP sockets, the return is
 * always 0 (which corresponds to the full checksum coverage of UDP). */
	case UDPLITE_SEND_CSCOV:
		val = up->pcslen;
		break;

	case UDPLITE_RECV_CSCOV:
		val = up->pcrlen;
		break;

	default:
		return -ENOPROTOOPT;
	}

	if (put_user(len, optlen))
		return -EFAULT;
	if (copy_to_user(optval, &val, len))
		return -EFAULT;
	return 0;
}
EXPORT_SYMBOL(udp_lib_getsockopt);

int udp_getsockopt(struct sock *sk, int level, int optname,
		   char __user *optval, int __user *optlen)
{
	if (level == SOL_UDP  ||  level == SOL_UDPLITE)
		return udp_lib_getsockopt(sk, level, optname, optval, optlen);
	return ip_getsockopt(sk, level, optname, optval, optlen);
}

#ifdef CONFIG_COMPAT
int compat_udp_getsockopt(struct sock *sk, int level, int optname,
				 char __user *optval, int __user *optlen)
{
	if (level == SOL_UDP  ||  level == SOL_UDPLITE)
		return udp_lib_getsockopt(sk, level, optname, optval, optlen);
	return compat_ip_getsockopt(sk, level, optname, optval, optlen);
}
#endif
/**
 * udp_poll - wait for a UDP event.
 * @file - file struct
 * @sock - socket
 * @wait - poll table
 *
 * This is same as datagram poll, except for the special case of
 * blocking sockets. If application is using a blocking fd
 * and a packet with checksum error is in the queue;
 * then it could get return from select indicating data available
 * but then block when reading it. Add special case code
 * to work around these arguably broken applications.
 */
unsigned int udp_poll(struct file *file, struct socket *sock, poll_table *wait)
{
	unsigned int mask = datagram_poll(file, sock, wait);
	struct sock *sk = sock->sk;

	sock_rps_record_flow(sk);

	/* Check for false positives due to checksum errors */
	if ((mask & POLLRDNORM) && !(file->f_flags & O_NONBLOCK) &&
	    !(sk->sk_shutdown & RCV_SHUTDOWN) && !first_packet_length(sk))
		mask &= ~(POLLIN | POLLRDNORM);

	return mask;

}
EXPORT_SYMBOL(udp_poll);

struct proto udp_prot = {
	.name		   = "UDP",
	.owner		   = THIS_MODULE,
	.close		   = udp_lib_close,
	.connect	   = ip4_datagram_connect,
	.disconnect	   = udp_disconnect,
	.ioctl		   = udp_ioctl,
	.destroy	   = udp_destroy_sock,
	.setsockopt	   = udp_setsockopt,
	.getsockopt	   = udp_getsockopt,
	.sendmsg	   = udp_sendmsg,
	.recvmsg	   = udp_recvmsg,
	.sendpage	   = udp_sendpage,
	.backlog_rcv	   = __udp_queue_rcv_skb,
	.release_cb	   = ip4_datagram_release_cb,
	.hash		   = udp_lib_hash,
	.unhash		   = udp_lib_unhash,
	.rehash		   = udp_v4_rehash,
	.get_port	   = udp_v4_get_port,
	.memory_allocated  = &udp_memory_allocated,
	.sysctl_mem	   = sysctl_udp_mem,
	.sysctl_wmem	   = &sysctl_udp_wmem_min,
	.sysctl_rmem	   = &sysctl_udp_rmem_min,
	.obj_size	   = sizeof(struct udp_sock),
	.slab_flags	   = SLAB_DESTROY_BY_RCU,
	.h.udp_table	   = &udp_table,
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_udp_setsockopt,
	.compat_getsockopt = compat_udp_getsockopt,
#endif
	.clear_sk	   = sk_prot_clear_portaddr_nulls,
};
EXPORT_SYMBOL(udp_prot);

/* ------------------------------------------------------------------------ */
#ifdef CONFIG_PROC_FS

static struct sock *udp_get_first(struct seq_file *seq, int start)
{
	struct sock *sk;
	struct udp_iter_state *state = seq->private;
	struct net *net = seq_file_net(seq);

	for (state->bucket = start; state->bucket <= state->udp_table->mask;
	     ++state->bucket) {
		struct hlist_nulls_node *node;
		struct udp_hslot *hslot = &state->udp_table->hash[state->bucket];

		if (hlist_nulls_empty(&hslot->head))
			continue;

		spin_lock_bh(&hslot->lock);
		sk_nulls_for_each(sk, node, &hslot->head) {
			if (!net_eq(sock_net(sk), net))
				continue;
			if (sk->sk_family == state->family)
				goto found;
		}
		spin_unlock_bh(&hslot->lock);
	}
	sk = NULL;
found:
	return sk;
}

static struct sock *udp_get_next(struct seq_file *seq, struct sock *sk)
{
	struct udp_iter_state *state = seq->private;
	struct net *net = seq_file_net(seq);

	do {
		sk = sk_nulls_next(sk);
	} while (sk && (!net_eq(sock_net(sk), net) || sk->sk_family != state->family));

	if (!sk) {
		if (state->bucket <= state->udp_table->mask)
			spin_unlock_bh(&state->udp_table->hash[state->bucket].lock);
		return udp_get_first(seq, state->bucket + 1);
	}
	return sk;
}

static struct sock *udp_get_idx(struct seq_file *seq, loff_t pos)
{
	struct sock *sk = udp_get_first(seq, 0);

	if (sk)
		while (pos && (sk = udp_get_next(seq, sk)) != NULL)
			--pos;
	return pos ? NULL : sk;
}

static void *udp_seq_start(struct seq_file *seq, loff_t *pos)
{
	struct udp_iter_state *state = seq->private;
	state->bucket = MAX_UDP_PORTS;

	return *pos ? udp_get_idx(seq, *pos-1) : SEQ_START_TOKEN;
}

static void *udp_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct sock *sk;

	if (v == SEQ_START_TOKEN)
		sk = udp_get_idx(seq, 0);
	else
		sk = udp_get_next(seq, v);

	++*pos;
	return sk;
}

static void udp_seq_stop(struct seq_file *seq, void *v)
{
	struct udp_iter_state *state = seq->private;

	if (state->bucket <= state->udp_table->mask)
		spin_unlock_bh(&state->udp_table->hash[state->bucket].lock);
}

int udp_seq_open(struct inode *inode, struct file *file)
{
	struct udp_seq_afinfo *afinfo = PDE_DATA(inode);
	struct udp_iter_state *s;
	int err;

	err = seq_open_net(inode, file, &afinfo->seq_ops,
			   sizeof(struct udp_iter_state));
	if (err < 0)
		return err;

	s = ((struct seq_file *)file->private_data)->private;
	s->family		= afinfo->family;
	s->udp_table		= afinfo->udp_table;
	return err;
}
EXPORT_SYMBOL(udp_seq_open);

/* ------------------------------------------------------------------------ */
int udp_proc_register(struct net *net, struct udp_seq_afinfo *afinfo)
{
	struct proc_dir_entry *p;
	int rc = 0;

	afinfo->seq_ops.start		= udp_seq_start;
	afinfo->seq_ops.next		= udp_seq_next;
	afinfo->seq_ops.stop		= udp_seq_stop;

	p = proc_create_data(afinfo->name, S_IRUGO, net->proc_net,
			     afinfo->seq_fops, afinfo);
	if (!p)
		rc = -ENOMEM;
	return rc;
}
EXPORT_SYMBOL(udp_proc_register);

void udp_proc_unregister(struct net *net, struct udp_seq_afinfo *afinfo)
{
	remove_proc_entry(afinfo->name, net->proc_net);
}
EXPORT_SYMBOL(udp_proc_unregister);

/* ------------------------------------------------------------------------ */
static void udp4_format_sock(struct sock *sp, struct seq_file *f,
		int bucket, int *len)
{
	struct inet_sock *inet = inet_sk(sp);
	__be32 dest = inet->inet_daddr;
	__be32 src  = inet->inet_rcv_saddr;
	__u16 destp	  = ntohs(inet->inet_dport);
	__u16 srcp	  = ntohs(inet->inet_sport);

	seq_printf(f, "%5d: %08X:%04X %08X:%04X"
		" %02X %08X:%08X %02X:%08lX %08X %5u %8d %lu %d %pK %d%n",
		bucket, src, srcp, dest, destp, sp->sk_state,
		sk_wmem_alloc_get(sp),
		sk_rmem_alloc_get(sp),
		0, 0L, 0,
		from_kuid_munged(seq_user_ns(f), sock_i_uid(sp)),
		0, sock_i_ino(sp),
		atomic_read(&sp->sk_refcnt), sp,
		atomic_read(&sp->sk_drops), len);
}

int udp4_seq_show(struct seq_file *seq, void *v)
{
	if (v == SEQ_START_TOKEN)
		seq_printf(seq, "%-127s\n",
			   " sl local_address rem_address st tx_queue "
			   "rx_queue tr tm->when retrnsmt uid timeout "
			   "inode ref pointer drops");
	else {
		struct udp_iter_state *state = seq->private;
		int len;

		udp4_format_sock(v, seq, state->bucket, &len);
		seq_printf(seq, "%*s\n", 127 - len, "");
	}
	return 0;
}

static const struct file_operations udp_afinfo_seq_fops = {
	.owner    = THIS_MODULE,
	.open     = udp_seq_open,
	.read     = seq_read,
	.llseek   = seq_lseek,
	.release  = seq_release_net
};

/* ------------------------------------------------------------------------ */
static struct udp_seq_afinfo udp4_seq_afinfo = {
	.name		= "udp",
	.family		= AF_INET,
	.udp_table	= &udp_table,
	.seq_fops	= &udp_afinfo_seq_fops,
	.seq_ops	= {
		.show		= udp4_seq_show,
	},
};

static int __net_init udp4_proc_init_net(struct net *net)
{
	return udp_proc_register(net, &udp4_seq_afinfo);
}

static void __net_exit udp4_proc_exit_net(struct net *net)
{
	udp_proc_unregister(net, &udp4_seq_afinfo);
}

static struct pernet_operations udp4_net_ops = {
	.init = udp4_proc_init_net,
	.exit = udp4_proc_exit_net,
};

int __init udp4_proc_init(void)
{
	return register_pernet_subsys(&udp4_net_ops);
}

void udp4_proc_exit(void)
{
	unregister_pernet_subsys(&udp4_net_ops);
}
#endif /* CONFIG_PROC_FS */

static __initdata unsigned long uhash_entries;
static int __init set_uhash_entries(char *str)
{
	ssize_t ret;

	if (!str)
		return 0;

	ret = kstrtoul(str, 0, &uhash_entries);
	if (ret)
		return 0;

	if (uhash_entries && uhash_entries < UDP_HTABLE_SIZE_MIN)
		uhash_entries = UDP_HTABLE_SIZE_MIN;
	return 1;
}
__setup("uhash_entries=", set_uhash_entries);

void __init udp_table_init(struct udp_table *table, const char *name)
{
	unsigned int i;

	table->hash = alloc_large_system_hash(name,
					      2 * sizeof(struct udp_hslot),
					      uhash_entries,
					      21, /* one slot per 2 MB */
					      0,
					      &table->log,
					      &table->mask,
					      UDP_HTABLE_SIZE_MIN,
					      64 * 1024);

	table->hash2 = table->hash + (table->mask + 1);
	for (i = 0; i <= table->mask; i++) {
		INIT_HLIST_NULLS_HEAD(&table->hash[i].head, i);
		table->hash[i].count = 0;
		spin_lock_init(&table->hash[i].lock);
	}
	for (i = 0; i <= table->mask; i++) {
		INIT_HLIST_NULLS_HEAD(&table->hash2[i].head, i);
		table->hash2[i].count = 0;
		spin_lock_init(&table->hash2[i].lock);
	}
}

void __init udp_init(void)
{
	unsigned long limit;

	udp_table_init(&udp_table, "UDP");
	limit = nr_free_buffer_pages() / 8;
	limit = max(limit, 128UL);
	sysctl_udp_mem[0] = limit / 4 * 3;
	sysctl_udp_mem[1] = limit;
	sysctl_udp_mem[2] = sysctl_udp_mem[0] * 2;

	sysctl_udp_rmem_min = SK_MEM_QUANTUM;
	sysctl_udp_wmem_min = SK_MEM_QUANTUM;
}

struct sk_buff *skb_udp_tunnel_segment(struct sk_buff *skb,
				       netdev_features_t features)
{
	struct sk_buff *segs = ERR_PTR(-EINVAL);
	int mac_len = skb->mac_len;
	int tnl_hlen = skb_inner_mac_header(skb) - skb_transport_header(skb);
	__be16 protocol = skb->protocol;
	netdev_features_t enc_features;
	int outer_hlen;

	if (unlikely(!pskb_may_pull(skb, tnl_hlen)))
		goto out;

	skb->encapsulation = 0;
	__skb_pull(skb, tnl_hlen);
	skb_reset_mac_header(skb);
	skb_set_network_header(skb, skb_inner_network_offset(skb));
	skb->mac_len = skb_inner_network_offset(skb);
	skb->protocol = htons(ETH_P_TEB);

	/* segment inner packet. */
	enc_features = skb->dev->hw_enc_features & netif_skb_features(skb);
	segs = skb_mac_gso_segment(skb, enc_features);
	if (!segs || IS_ERR(segs))
		goto out;

	outer_hlen = skb_tnl_header_len(skb);
	skb = segs;
	do {
		struct udphdr *uh;
		int udp_offset = outer_hlen - tnl_hlen;

		skb_reset_inner_headers(skb);
		skb->encapsulation = 1;

		skb->mac_len = mac_len;

		skb_push(skb, outer_hlen);
		skb_reset_mac_header(skb);
		skb_set_network_header(skb, mac_len);
		skb_set_transport_header(skb, udp_offset);
		uh = udp_hdr(skb);
		uh->len = htons(skb->len - udp_offset);

		/* csum segment if tunnel sets skb with csum. */
		if (protocol == htons(ETH_P_IP) && unlikely(uh->check)) {
			struct iphdr *iph = ip_hdr(skb);

			uh->check = ~csum_tcpudp_magic(iph->saddr, iph->daddr,
						       skb->len - udp_offset,
						       IPPROTO_UDP, 0);
			uh->check = csum_fold(skb_checksum(skb, udp_offset,
							   skb->len - udp_offset, 0));
			if (uh->check == 0)
				uh->check = CSUM_MANGLED_0;

		} else if (protocol == htons(ETH_P_IPV6)) {
			struct ipv6hdr *ipv6h = ipv6_hdr(skb);
			u32 len = skb->len - udp_offset;

			uh->check = ~csum_ipv6_magic(&ipv6h->saddr, &ipv6h->daddr,
						     len, IPPROTO_UDP, 0);
			uh->check = csum_fold(skb_checksum(skb, udp_offset, len, 0));
			if (uh->check == 0)
				uh->check = CSUM_MANGLED_0;
			skb->ip_summed = CHECKSUM_NONE;
		}

		skb->protocol = protocol;
	} while ((skb = skb->next));
out:
	return segs;
}

/*
 * UDP over IPv6
 * Linux INET6 implementation
 *
 * Authors:
 * Pedro Roque <roque@di.fc.ul.pt>
 *
 * Based on linux/ipv4/udp.c
 *
 * Fixes:
 * Hideaki YOSHIFUJI : sin6_scope_id support
 * YOSHIFUJI Hideaki @USAGI and: Support IPV6_V6ONLY socket option, which
 * Alexey Kuznetsov allow both IPv4 and IPv6 sockets to bind
 * a single port at the same time.
 * Kazunori MIYAZAWA @USAGI: change process style to use ip6_append_data
 * YOSHIFUJI Hideaki @USAGI: convert /proc/net/udp6 to seq_file.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/net.h>
#include <linux/in6.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <asm/uaccess.h>

#include <net/ndisc.h>
#include <net/protocol.h>
#include <net/transp_v6.h>
#include <net/ip6_route.h>
#include <net/raw.h>
#include <net/tcp_states.h>
#include <net/ip6_checksum.h>
#include <net/xfrm.h>
#include <net/inet6_hashtables.h>
#include <net/busy_poll.h>

#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <trace/events/skb.h>
#include "udp_impl.h"

static unsigned int udp6_ehashfn(struct net *net,
				  const struct in6_addr *laddr,
				  const u16 lport,
				  const struct in6_addr *faddr,
				  const __be16 fport)
{
	static u32 udp6_ehash_secret __read_mostly;
	static u32 udp_ipv6_hash_secret __read_mostly;

	u32 lhash, fhash;

	net_get_random_once(&udp6_ehash_secret,
			    sizeof(udp6_ehash_secret));
	net_get_random_once(&udp_ipv6_hash_secret,
			    sizeof(udp_ipv6_hash_secret));

	lhash = (__force u32)laddr->s6_addr32[3];
	fhash = __ipv6_addr_jhash(faddr, udp_ipv6_hash_secret);

	return __inet6_ehashfn(lhash, lport, fhash, fport,
			       udp_ipv6_hash_secret + net_hash_mix(net));
}

int ipv6_rcv_saddr_equal(const struct sock *sk, const struct sock *sk2)
{
	const struct in6_addr *sk2_rcv_saddr6 = inet6_rcv_saddr(sk2);
	int sk_ipv6only = ipv6_only_sock(sk);
	int sk2_ipv6only = inet_v6_ipv6only(sk2);
	int addr_type = ipv6_addr_type(&sk->sk_v6_rcv_saddr);
	int addr_type2 = sk2_rcv_saddr6 ? ipv6_addr_type(sk2_rcv_saddr6) : IPV6_ADDR_MAPPED;

	/* if both are mapped, treat as IPv4 */
	if (addr_type == IPV6_ADDR_MAPPED && addr_type2 == IPV6_ADDR_MAPPED)
		return (!sk2_ipv6only &&
			(!sk->sk_rcv_saddr || !sk2->sk_rcv_saddr ||
			  sk->sk_rcv_saddr == sk2->sk_rcv_saddr));

	if (addr_type2 == IPV6_ADDR_ANY &&
	    !(sk2_ipv6only && addr_type == IPV6_ADDR_MAPPED))
		return 1;

	if (addr_type == IPV6_ADDR_ANY &&
	    !(sk_ipv6only && addr_type2 == IPV6_ADDR_MAPPED))
		return 1;

	if (sk2_rcv_saddr6 &&
	    ipv6_addr_equal(&sk->sk_v6_rcv_saddr, sk2_rcv_saddr6))
		return 1;

	return 0;
}

static unsigned int udp6_portaddr_hash(struct net *net,
				       const struct in6_addr *addr6,
				       unsigned int port)
{
	unsigned int hash, mix = net_hash_mix(net);

	if (ipv6_addr_any(addr6))
		hash = jhash_1word(0, mix);
	else if (ipv6_addr_v4mapped(addr6))
		hash = jhash_1word((__force u32)addr6->s6_addr32[3], mix);
	else
		hash = jhash2((__force u32 *)addr6->s6_addr32, 4, mix);

	return hash ^ port;
}


int udp_v6_get_port(struct sock *sk, unsigned short snum)
{
	unsigned int hash2_nulladdr =
		udp6_portaddr_hash(sock_net(sk), &in6addr_any, snum);
	unsigned int hash2_partial =
		udp6_portaddr_hash(sock_net(sk), &sk->sk_v6_rcv_saddr, 0);

	/* precompute partial secondary hash */
	udp_sk(sk)->udp_portaddr_hash = hash2_partial;
	return udp_lib_get_port(sk, snum, ipv6_rcv_saddr_equal, hash2_nulladdr);
}

static void udp_v6_rehash(struct sock *sk)
{
	u16 new_hash = udp6_portaddr_hash(sock_net(sk),
					  &sk->sk_v6_rcv_saddr,
					  inet_sk(sk)->inet_num);

	udp_lib_rehash(sk, new_hash);
}

static inline int compute_score(struct sock *sk, struct net *net,
				unsigned short hnum,
				const struct in6_addr *saddr, __be16 sport,
				const struct in6_addr *daddr, __be16 dport,
				int dif)
{
	int score = -1;

	if (net_eq(sock_net(sk), net) && udp_sk(sk)->udp_port_hash == hnum &&
			sk->sk_family == PF_INET6) {
		struct inet_sock *inet = inet_sk(sk);

		score = 0;
		if (inet->inet_dport) {
			if (inet->inet_dport != sport)
				return -1;
			score++;
		}
		if (!ipv6_addr_any(&sk->sk_v6_rcv_saddr)) {
			if (!ipv6_addr_equal(&sk->sk_v6_rcv_saddr, daddr))
				return -1;
			score++;
		}
		if (!ipv6_addr_any(&sk->sk_v6_daddr)) {
			if (!ipv6_addr_equal(&sk->sk_v6_daddr, saddr))
				return -1;
			score++;
		}
		if (sk->sk_bound_dev_if) {
			if (sk->sk_bound_dev_if != dif)
				return -1;
			score++;
		}
	}
	return score;
}

#define SCORE2_MAX (1 + 1 + 1)
static inline int compute_score2(struct sock *sk, struct net *net,
				const struct in6_addr *saddr, __be16 sport,
				const struct in6_addr *daddr, unsigned short hnum,
				int dif)
{
	int score = -1;

	if (net_eq(sock_net(sk), net) && udp_sk(sk)->udp_port_hash == hnum &&
			sk->sk_family == PF_INET6) {
		struct inet_sock *inet = inet_sk(sk);

		if (!ipv6_addr_equal(&sk->sk_v6_rcv_saddr, daddr))
			return -1;
		score = 0;
		if (inet->inet_dport) {
			if (inet->inet_dport != sport)
				return -1;
			score++;
		}
		if (!ipv6_addr_any(&sk->sk_v6_daddr)) {
			if (!ipv6_addr_equal(&sk->sk_v6_daddr, saddr))
				return -1;
			score++;
		}
		if (sk->sk_bound_dev_if) {
			if (sk->sk_bound_dev_if != dif)
				return -1;
			score++;
		}
	}
	return score;
}


/* called with read_rcu_lock() */
static struct sock *udp6_lib_lookup2(struct net *net,
		const struct in6_addr *saddr, __be16 sport,
		const struct in6_addr *daddr, unsigned int hnum, int dif,
		struct udp_hslot *hslot2, unsigned int slot2)
{
	struct sock *sk, *result;
	struct hlist_nulls_node *node;
	int score, badness, matches = 0, reuseport = 0;
	u32 hash = 0;

begin:
	result = NULL;
	badness = -1;
	udp_portaddr_for_each_entry_rcu(sk, node, &hslot2->head) {
		score = compute_score2(sk, net, saddr, sport,
				      daddr, hnum, dif);
		if (score > badness) {
			result = sk;
			badness = score;
			reuseport = sk->sk_reuseport;
			if (reuseport) {
				hash = udp6_ehashfn(net, daddr, hnum,
						    saddr, sport);
				matches = 1;
			} else if (score == SCORE2_MAX)
				goto exact_match;
		} else if (score == badness && reuseport) {
			matches++;
			if (((u64)hash * matches) >> 32 == 0)
				result = sk;
			hash = next_pseudo_random32(hash);
		}
	}
	/*
 * if the nulls value we got at the end of this lookup is
 * not the expected one, we must restart lookup.
 * We probably met an item that was moved to another chain.
 */
	if (get_nulls_value(node) != slot2)
		goto begin;

	if (result) {
exact_match:
		if (unlikely(!atomic_inc_not_zero_hint(&result->sk_refcnt, 2)))
			result = NULL;
		else if (unlikely(compute_score2(result, net, saddr, sport,
				  daddr, hnum, dif) < badness)) {
			sock_put(result);
			goto begin;
		}
	}
	return result;
}

struct sock *__udp6_lib_lookup(struct net *net,
				      const struct in6_addr *saddr, __be16 sport,
				      const struct in6_addr *daddr, __be16 dport,
				      int dif, struct udp_table *udptable)
{
	struct sock *sk, *result;
	struct hlist_nulls_node *node;
	unsigned short hnum = ntohs(dport);
	unsigned int hash2, slot2, slot = udp_hashfn(net, hnum, udptable->mask);
	struct udp_hslot *hslot2, *hslot = &udptable->hash[slot];
	int score, badness, matches = 0, reuseport = 0;
	u32 hash = 0;

	rcu_read_lock();
	if (hslot->count > 10) {
		hash2 = udp6_portaddr_hash(net, daddr, hnum);
		slot2 = hash2 & udptable->mask;
		hslot2 = &udptable->hash2[slot2];
		if (hslot->count < hslot2->count)
			goto begin;

		result = udp6_lib_lookup2(net, saddr, sport,
					  daddr, hnum, dif,
					  hslot2, slot2);
		if (!result) {
			hash2 = udp6_portaddr_hash(net, &in6addr_any, hnum);
			slot2 = hash2 & udptable->mask;
			hslot2 = &udptable->hash2[slot2];
			if (hslot->count < hslot2->count)
				goto begin;

			result = udp6_lib_lookup2(net, saddr, sport,
						  &in6addr_any, hnum, dif,
						  hslot2, slot2);
		}
		rcu_read_unlock();
		return result;
	}
begin:
	result = NULL;
	badness = -1;
	sk_nulls_for_each_rcu(sk, node, &hslot->head) {
		score = compute_score(sk, net, hnum, saddr, sport, daddr, dport, dif);
		if (score > badness) {
			result = sk;
			badness = score;
			reuseport = sk->sk_reuseport;
			if (reuseport) {
				hash = udp6_ehashfn(net, daddr, hnum,
						    saddr, sport);
				matches = 1;
			}
		} else if (score == badness && reuseport) {
			matches++;
			if (((u64)hash * matches) >> 32 == 0)
				result = sk;
			hash = next_pseudo_random32(hash);
		}
	}
	/*
 * if the nulls value we got at the end of this lookup is
 * not the expected one, we must restart lookup.
 * We probably met an item that was moved to another chain.
 */
	if (get_nulls_value(node) != slot)
		goto begin;

	if (result) {
		if (unlikely(!atomic_inc_not_zero_hint(&result->sk_refcnt, 2)))
			result = NULL;
		else if (unlikely(compute_score(result, net, hnum, saddr, sport,
					daddr, dport, dif) < badness)) {
			sock_put(result);
			goto begin;
		}
	}
	rcu_read_unlock();
	return result;
}
EXPORT_SYMBOL_GPL(__udp6_lib_lookup);

static struct sock *__udp6_lib_lookup_skb(struct sk_buff *skb,
					  __be16 sport, __be16 dport,
					  struct udp_table *udptable)
{
	struct sock *sk;
	const struct ipv6hdr *iph = ipv6_hdr(skb);

	if (unlikely(sk = skb_steal_sock(skb)))
		return sk;
	return __udp6_lib_lookup(dev_net(skb_dst(skb)->dev), &iph->saddr, sport,
				 &iph->daddr, dport, inet6_iif(skb),
				 udptable);
}

struct sock *udp6_lib_lookup(struct net *net, const struct in6_addr *saddr, __be16 sport,
			     const struct in6_addr *daddr, __be16 dport, int dif)
{
	return __udp6_lib_lookup(net, saddr, sport, daddr, dport, dif, &udp_table);
}
EXPORT_SYMBOL_GPL(udp6_lib_lookup);


/*
 * This should be easy, if there is something there we
 * return it, otherwise we block.
 */

int udpv6_recvmsg(struct kiocb *iocb, struct sock *sk,
		  struct msghdr *msg, size_t len,
		  int noblock, int flags, int *addr_len)
{
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct inet_sock *inet = inet_sk(sk);
	struct sk_buff *skb;
	unsigned int ulen, copied;
	int peeked, off = 0;
	int err;
	int is_udplite = IS_UDPLITE(sk);
	int is_udp4;
	bool slow;

	if (addr_len)
		*addr_len = sizeof(struct sockaddr_in6);

	if (flags & MSG_ERRQUEUE)
		return ipv6_recv_error(sk, msg, len);

	if (np->rxpmtu && np->rxopt.bits.rxpmtu)
		return ipv6_recv_rxpmtu(sk, msg, len);

try_again:
	skb = __skb_recv_datagram(sk, flags | (noblock ? MSG_DONTWAIT : 0),
				  &peeked, &off, &err);
	if (!skb)
		goto out;

	ulen = skb->len - sizeof(struct udphdr);
	copied = len;
	if (copied > ulen)
		copied = ulen;
	else if (copied < ulen)
		msg->msg_flags |= MSG_TRUNC;

	is_udp4 = (skb->protocol == htons(ETH_P_IP));

	/*
 * If checksum is needed at all, try to do it while copying the
 * data. If the data is truncated, or if we only want a partial
 * coverage checksum (UDP-Lite), do it before the copy.
 */

	if (copied < ulen || UDP_SKB_CB(skb)->partial_cov) {
		if (udp_lib_checksum_complete(skb))
			goto csum_copy_err;
	}

	if (skb_csum_unnecessary(skb))
		err = skb_copy_datagram_iovec(skb, sizeof(struct udphdr),
					      msg->msg_iov, copied);
	else {
		err = skb_copy_and_csum_datagram_iovec(skb, sizeof(struct udphdr), msg->msg_iov);
		if (err == -EINVAL)
			goto csum_copy_err;
	}
	if (unlikely(err)) {
		trace_kfree_skb(skb, udpv6_recvmsg);
		if (!peeked) {
			atomic_inc(&sk->sk_drops);
			if (is_udp4)
				UDP_INC_STATS_USER(sock_net(sk),
						   UDP_MIB_INERRORS,
						   is_udplite);
			else
				UDP6_INC_STATS_USER(sock_net(sk),
						    UDP_MIB_INERRORS,
						    is_udplite);
		}
		goto out_free;
	}
	if (!peeked) {
		if (is_udp4)
			UDP_INC_STATS_USER(sock_net(sk),
					UDP_MIB_INDATAGRAMS, is_udplite);
		else
			UDP6_INC_STATS_USER(sock_net(sk),
					UDP_MIB_INDATAGRAMS, is_udplite);
	}

	sock_recv_ts_and_drops(msg, sk, skb);

	/* Copy the address. */
	if (msg->msg_name) {
		struct sockaddr_in6 *sin6;

		sin6 = (struct sockaddr_in6 *) msg->msg_name;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = udp_hdr(skb)->source;
		sin6->sin6_flowinfo = 0;

		if (is_udp4) {
			ipv6_addr_set_v4mapped(ip_hdr(skb)->saddr,
					       &sin6->sin6_addr);
			sin6->sin6_scope_id = 0;
		} else {
			sin6->sin6_addr = ipv6_hdr(skb)->saddr;
			sin6->sin6_scope_id =
				ipv6_iface_scope_id(&sin6->sin6_addr,
						    IP6CB(skb)->iif);
		}

	}
	if (is_udp4) {
		if (inet->cmsg_flags)
			ip_cmsg_recv(msg, skb);
	} else {
		if (np->rxopt.all)
			ip6_datagram_recv_ctl(sk, msg, skb);
	}

	err = copied;
	if (flags & MSG_TRUNC)
		err = ulen;

out_free:
	skb_free_datagram_locked(sk, skb);
out:
	return err;

csum_copy_err:
	slow = lock_sock_fast(sk);
	if (!skb_kill_datagram(sk, skb, flags)) {
		if (is_udp4) {
			UDP_INC_STATS_USER(sock_net(sk),
					UDP_MIB_CSUMERRORS, is_udplite);
			UDP_INC_STATS_USER(sock_net(sk),
					UDP_MIB_INERRORS, is_udplite);
		} else {
			UDP6_INC_STATS_USER(sock_net(sk),
					UDP_MIB_CSUMERRORS, is_udplite);
			UDP6_INC_STATS_USER(sock_net(sk),
					UDP_MIB_INERRORS, is_udplite);
		}
	}
	unlock_sock_fast(sk, slow);

	if (noblock)
		return -EAGAIN;

	/* starting over for a new packet */
	msg->msg_flags &= ~MSG_TRUNC;
	goto try_again;
}

void __udp6_lib_err(struct sk_buff *skb, struct inet6_skb_parm *opt,
		    u8 type, u8 code, int offset, __be32 info,
		    struct udp_table *udptable)
{
	struct ipv6_pinfo *np;
	const struct ipv6hdr *hdr = (const struct ipv6hdr *)skb->data;
	const struct in6_addr *saddr = &hdr->saddr;
	const struct in6_addr *daddr = &hdr->daddr;
	struct udphdr *uh = (struct udphdr*)(skb->data+offset);
	struct sock *sk;
	int err;

	sk = __udp6_lib_lookup(dev_net(skb->dev), daddr, uh->dest,
			       saddr, uh->source, inet6_iif(skb), udptable);
	if (sk == NULL)
		return;

	if (type == ICMPV6_PKT_TOOBIG)
		ip6_sk_update_pmtu(skb, sk, info);
	if (type == NDISC_REDIRECT) {
		ip6_sk_redirect(skb, sk);
		goto out;
	}

	np = inet6_sk(sk);

	if (!icmpv6_err_convert(type, code, &err) && !np->recverr)
		goto out;

	if (sk->sk_state != TCP_ESTABLISHED && !np->recverr)
		goto out;

	if (np->recverr)
		ipv6_icmp_error(sk, skb, err, uh->dest, ntohl(info), (u8 *)(uh+1));

	sk->sk_err = err;
	sk->sk_error_report(sk);
out:
	sock_put(sk);
}

static int __udpv6_queue_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	int rc;

	if (!ipv6_addr_any(&sk->sk_v6_daddr)) {
		sock_rps_save_rxhash(sk, skb);
		sk_mark_napi_id(sk, skb);
	}

	rc = sock_queue_rcv_skb(sk, skb);
	if (rc < 0) {
		int is_udplite = IS_UDPLITE(sk);

		/* Note that an ENOMEM error is charged twice */
		if (rc == -ENOMEM)
			UDP6_INC_STATS_BH(sock_net(sk),
					UDP_MIB_RCVBUFERRORS, is_udplite);
		UDP6_INC_STATS_BH(sock_net(sk), UDP_MIB_INERRORS, is_udplite);
		kfree_skb(skb);
		return -1;
	}
	return 0;
}

static __inline__ void udpv6_err(struct sk_buff *skb,
				 struct inet6_skb_parm *opt, u8 type,
				 u8 code, int offset, __be32 info     )
{
	__udp6_lib_err(skb, opt, type, code, offset, info, &udp_table);
}

static struct static_key udpv6_encap_needed __read_mostly;
void udpv6_encap_enable(void)
{
	if (!static_key_enabled(&udpv6_encap_needed))
		static_key_slow_inc(&udpv6_encap_needed);
}
EXPORT_SYMBOL(udpv6_encap_enable);

int udpv6_queue_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	struct udp_sock *up = udp_sk(sk);
	int rc;
	int is_udplite = IS_UDPLITE(sk);

	if (!xfrm6_policy_check(sk, XFRM_POLICY_IN, skb))
		goto drop;

	if (static_key_false(&udpv6_encap_needed) && up->encap_type) {
		int (*encap_rcv)(struct sock *sk, struct sk_buff *skb);

		/*
 * This is an encapsulation socket so pass the skb to
 * the socket's udp_encap_rcv() hook. Otherwise, just
 * fall through and pass this up the UDP socket.
 * up->encap_rcv() returns the following value:
 * =0 if skb was successfully passed to the encap
 * handler or was discarded by it.
 * >0 if skb should be passed on to UDP.
 * <0 if skb should be resubmitted as proto -N
 */

		/* if we're overly short, let UDP handle it */
		encap_rcv = ACCESS_ONCE(up->encap_rcv);
		if (skb->len > sizeof(struct udphdr) && encap_rcv != NULL) {
			int ret;

			ret = encap_rcv(sk, skb);
			if (ret <= 0) {
				UDP_INC_STATS_BH(sock_net(sk),
						 UDP_MIB_INDATAGRAMS,
						 is_udplite);
				return -ret;
			}
		}

		/* FALLTHROUGH -- it's a UDP Packet */
	}

	/*
 * UDP-Lite specific tests, ignored on UDP sockets (see net/ipv4/udp.c).
 */
	if ((is_udplite & UDPLITE_RECV_CC) &&  UDP_SKB_CB(skb)->partial_cov) {

		if (up->pcrlen == 0) {          /* full coverage was set */
			LIMIT_NETDEBUG(KERN_WARNING "UDPLITE6: partial coverage"
				" %d while full coverage %d requested\n",
				UDP_SKB_CB(skb)->cscov, skb->len);
			goto drop;
		}
		if (UDP_SKB_CB(skb)->cscov  <  up->pcrlen) {
			LIMIT_NETDEBUG(KERN_WARNING "UDPLITE6: coverage %d "
						    "too small, need min %d\n",
				       UDP_SKB_CB(skb)->cscov, up->pcrlen);
			goto drop;
		}
	}

	if (rcu_access_pointer(sk->sk_filter)) {
		if (udp_lib_checksum_complete(skb))
			goto csum_error;
	}

	if (sk_rcvqueues_full(sk, skb, sk->sk_rcvbuf))
		goto drop;

	skb_dst_drop(skb);

	bh_lock_sock(sk);
	rc = 0;
	if (!sock_owned_by_user(sk))
		rc = __udpv6_queue_rcv_skb(sk, skb);
	else if (sk_add_backlog(sk, skb, sk->sk_rcvbuf)) {
		bh_unlock_sock(sk);
		goto drop;
	}
	bh_unlock_sock(sk);

	return rc;
csum_error:
	UDP6_INC_STATS_BH(sock_net(sk), UDP_MIB_CSUMERRORS, is_udplite);
drop:
	UDP6_INC_STATS_BH(sock_net(sk), UDP_MIB_INERRORS, is_udplite);
	atomic_inc(&sk->sk_drops);
	kfree_skb(skb);
	return -1;
}

static struct sock *udp_v6_mcast_next(struct net *net, struct sock *sk,
				      __be16 loc_port, const struct in6_addr *loc_addr,
				      __be16 rmt_port, const struct in6_addr *rmt_addr,
				      int dif)
{
	struct hlist_nulls_node *node;
	struct sock *s = sk;
	unsigned short num = ntohs(loc_port);

	sk_nulls_for_each_from(s, node) {
		struct inet_sock *inet = inet_sk(s);

		if (!net_eq(sock_net(s), net))
			continue;

		if (udp_sk(s)->udp_port_hash == num &&
		    s->sk_family == PF_INET6) {
			if (inet->inet_dport) {
				if (inet->inet_dport != rmt_port)
					continue;
			}
			if (!ipv6_addr_any(&sk->sk_v6_daddr) &&
			    !ipv6_addr_equal(&sk->sk_v6_daddr, rmt_addr))
				continue;

			if (s->sk_bound_dev_if && s->sk_bound_dev_if != dif)
				continue;

			if (!ipv6_addr_any(&sk->sk_v6_rcv_saddr)) {
				if (!ipv6_addr_equal(&sk->sk_v6_rcv_saddr, loc_addr))
					continue;
			}
			if (!inet6_mc_check(s, loc_addr, rmt_addr))
				continue;
			return s;
		}
	}
	return NULL;
}

static void flush_stack(struct sock **stack, unsigned int count,
			struct sk_buff *skb, unsigned int final)
{
	struct sk_buff *skb1 = NULL;
	struct sock *sk;
	unsigned int i;

	for (i = 0; i < count; i++) {
		sk = stack[i];
		if (likely(skb1 == NULL))
			skb1 = (i == final) ? skb : skb_clone(skb, GFP_ATOMIC);
		if (!skb1) {
			atomic_inc(&sk->sk_drops);
			UDP6_INC_STATS_BH(sock_net(sk), UDP_MIB_RCVBUFERRORS,
					  IS_UDPLITE(sk));
			UDP6_INC_STATS_BH(sock_net(sk), UDP_MIB_INERRORS,
					  IS_UDPLITE(sk));
		}

		if (skb1 && udpv6_queue_rcv_skb(sk, skb1) <= 0)
			skb1 = NULL;
	}
	if (unlikely(skb1))
		kfree_skb(skb1);
}
/*
 * Note: called only from the BH handler context,
 * so we don't need to lock the hashes.
 */
static int __udp6_lib_mcast_deliver(struct net *net, struct sk_buff *skb,
		const struct in6_addr *saddr, const struct in6_addr *daddr,
		struct udp_table *udptable)
{
	struct sock *sk, *stack[256 / sizeof(struct sock *)];
	const struct udphdr *uh = udp_hdr(skb);
	struct udp_hslot *hslot = udp_hashslot(udptable, net, ntohs(uh->dest));
	int dif;
	unsigned int i, count = 0;

	spin_lock(&hslot->lock);
	sk = sk_nulls_head(&hslot->head);
	dif = inet6_iif(skb);
	sk = udp_v6_mcast_next(net, sk, uh->dest, daddr, uh->source, saddr, dif);
	while (sk) {
		stack[count++] = sk;
		sk = udp_v6_mcast_next(net, sk_nulls_next(sk), uh->dest, daddr,
				       uh->source, saddr, dif);
		if (unlikely(count == ARRAY_SIZE(stack))) {
			if (!sk)
				break;
			flush_stack(stack, count, skb, ~0);
			count = 0;
		}
	}
	/*
 * before releasing the lock, we must take reference on sockets
 */
	for (i = 0; i < count; i++)
		sock_hold(stack[i]);

	spin_unlock(&hslot->lock);

	if (count) {
		flush_stack(stack, count, skb, count - 1);

		for (i = 0; i < count; i++)
			sock_put(stack[i]);
	} else {
		kfree_skb(skb);
	}
	return 0;
}

int __udp6_lib_rcv(struct sk_buff *skb, struct udp_table *udptable,
		   int proto)
{
	struct net *net = dev_net(skb->dev);
	struct sock *sk;
	struct udphdr *uh;
	const struct in6_addr *saddr, *daddr;
	u32 ulen = 0;

	if (!pskb_may_pull(skb, sizeof(struct udphdr)))
		goto discard;

	saddr = &ipv6_hdr(skb)->saddr;
	daddr = &ipv6_hdr(skb)->daddr;
	uh = udp_hdr(skb);

	ulen = ntohs(uh->len);
	if (ulen > skb->len)
		goto short_packet;

	if (proto == IPPROTO_UDP) {
		/* UDP validates ulen. */

		/* Check for jumbo payload */
		if (ulen == 0)
			ulen = skb->len;

		if (ulen < sizeof(*uh))
			goto short_packet;

		if (ulen < skb->len) {
			if (pskb_trim_rcsum(skb, ulen))
				goto short_packet;
			saddr = &ipv6_hdr(skb)->saddr;
			daddr = &ipv6_hdr(skb)->daddr;
			uh = udp_hdr(skb);
		}
	}

	if (udp6_csum_init(skb, uh, proto))
		goto csum_error;

	/*
 * Multicast receive code
 */
	if (ipv6_addr_is_multicast(daddr))
		return __udp6_lib_mcast_deliver(net, skb,
				saddr, daddr, udptable);

	/* Unicast */

	/*
 * check socket cache ... must talk to Alan about his plans
 * for sock caches... i'll skip this for now.
 */
	sk = __udp6_lib_lookup_skb(skb, uh->source, uh->dest, udptable);
	if (sk != NULL) {
		int ret;

		ret = udpv6_queue_rcv_skb(sk, skb);
		sock_put(sk);

		/* a return value > 0 means to resubmit the input, but
 * it wants the return to be -protocol, or 0
 */
		if (ret > 0)
			return -ret;

		return 0;
	}

	if (!xfrm6_policy_check(NULL, XFRM_POLICY_IN, skb))
		goto discard;

	if (udp_lib_checksum_complete(skb))
		goto csum_error;

	UDP6_INC_STATS_BH(net, UDP_MIB_NOPORTS, proto == IPPROTO_UDPLITE);
	icmpv6_send(skb, ICMPV6_DEST_UNREACH, ICMPV6_PORT_UNREACH, 0);

	kfree_skb(skb);
	return 0;

short_packet:
	LIMIT_NETDEBUG(KERN_DEBUG "UDP%sv6: short packet: From [%pI6c]:%u %d/%d to [%pI6c]:%u\n",
		       proto == IPPROTO_UDPLITE ? "-Lite" : "",
		       saddr,
		       ntohs(uh->source),
		       ulen,
		       skb->len,
		       daddr,
		       ntohs(uh->dest));
	goto discard;
csum_error:
	UDP6_INC_STATS_BH(net, UDP_MIB_CSUMERRORS, proto == IPPROTO_UDPLITE);
discard:
	UDP6_INC_STATS_BH(net, UDP_MIB_INERRORS, proto == IPPROTO_UDPLITE);
	kfree_skb(skb);
	return 0;
}

static __inline__ int udpv6_rcv(struct sk_buff *skb)
{
	return __udp6_lib_rcv(skb, &udp_table, IPPROTO_UDP);
}

/*
 * Throw away all pending data and cancel the corking. Socket is locked.
 */
static void udp_v6_flush_pending_frames(struct sock *sk)
{
	struct udp_sock *up = udp_sk(sk);

	if (up->pending == AF_INET)
		udp_flush_pending_frames(sk);
	else if (up->pending) {
		up->len = 0;
		up->pending = 0;
		ip6_flush_pending_frames(sk);
	}
}

/**
 * udp6_hwcsum_outgoing - handle outgoing HW checksumming
 * @sk: socket we are sending on
 * @skb: sk_buff containing the filled-in UDP header
 * (checksum field must be zeroed out)
 */
static void udp6_hwcsum_outgoing(struct sock *sk, struct sk_buff *skb,
				 const struct in6_addr *saddr,
				 const struct in6_addr *daddr, int len)
{
	unsigned int offset;
	struct udphdr *uh = udp_hdr(skb);
	__wsum csum = 0;

	if (skb_queue_len(&sk->sk_write_queue) == 1) {
		/* Only one fragment on the socket. */
		skb->csum_start = skb_transport_header(skb) - skb->head;
		skb->csum_offset = offsetof(struct udphdr, check);
		uh->check = ~csum_ipv6_magic(saddr, daddr, len, IPPROTO_UDP, 0);
	} else {
		/*
 * HW-checksum won't work as there are two or more
 * fragments on the socket so that all csums of sk_buffs
 * should be together
 */
		offset = skb_transport_offset(skb);
		skb->csum = skb_checksum(skb, offset, skb->len - offset, 0);

		skb->ip_summed = CHECKSUM_NONE;

		skb_queue_walk(&sk->sk_write_queue, skb) {
			csum = csum_add(csum, skb->csum);
		}

		uh->check = csum_ipv6_magic(saddr, daddr, len, IPPROTO_UDP,
					    csum);
		if (uh->check == 0)
			uh->check = CSUM_MANGLED_0;
	}
}

/*
 * Sending
 */

static int udp_v6_push_pending_frames(struct sock *sk)
{
	struct sk_buff *skb;
	struct udphdr *uh;
	struct udp_sock  *up = udp_sk(sk);
	struct inet_sock *inet = inet_sk(sk);
	struct flowi6 *fl6;
	int err = 0;
	int is_udplite = IS_UDPLITE(sk);
	__wsum csum = 0;

	if (up->pending == AF_INET)
		return udp_push_pending_frames(sk);

	fl6 = &inet->cork.fl.u.ip6;

	/* Grab the skbuff where UDP header space exists. */
	if ((skb = skb_peek(&sk->sk_write_queue)) == NULL)
		goto out;

	/*
 * Create a UDP header
 */
	uh = udp_hdr(skb);
	uh->source = fl6->fl6_sport;
	uh->dest = fl6->fl6_dport;
	uh->len = htons(up->len);
	uh->check = 0;

	if (is_udplite)
		csum = udplite_csum_outgoing(sk, skb);
	else if (skb->ip_summed == CHECKSUM_PARTIAL) { /* UDP hardware csum */
		udp6_hwcsum_outgoing(sk, skb, &fl6->saddr, &fl6->daddr,
				     up->len);
		goto send;
	} else
		csum = udp_csum_outgoing(sk, skb);

	/* add protocol-dependent pseudo-header */
	uh->check = csum_ipv6_magic(&fl6->saddr, &fl6->daddr,
				    up->len, fl6->flowi6_proto, csum);
	if (uh->check == 0)
		uh->check = CSUM_MANGLED_0;

send:
	err = ip6_push_pending_frames(sk);
	if (err) {
		if (err == -ENOBUFS && !inet6_sk(sk)->recverr) {
			UDP6_INC_STATS_USER(sock_net(sk),
					    UDP_MIB_SNDBUFERRORS, is_udplite);
			err = 0;
		}
	} else
		UDP6_INC_STATS_USER(sock_net(sk),
				    UDP_MIB_OUTDATAGRAMS, is_udplite);
out:
	up->len = 0;
	up->pending = 0;
	return err;
}

int udpv6_sendmsg(struct kiocb *iocb, struct sock *sk,
		  struct msghdr *msg, size_t len)
{
	struct ipv6_txoptions opt_space;
	struct udp_sock *up = udp_sk(sk);
	struct inet_sock *inet = inet_sk(sk);
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) msg->msg_name;
	struct in6_addr *daddr, *final_p, final;
	struct ipv6_txoptions *opt = NULL;
	struct ip6_flowlabel *flowlabel = NULL;
	struct flowi6 fl6;
	struct dst_entry *dst;
	int addr_len = msg->msg_namelen;
	int ulen = len;
	int hlimit = -1;
	int tclass = -1;
	int dontfrag = -1;
	int corkreq = up->corkflag || msg->msg_flags&MSG_MORE;
	int err;
	int connected = 0;
	int is_udplite = IS_UDPLITE(sk);
	int (*getfrag)(void *, char *, int, int, int, struct sk_buff *);

	/* destination address check */
	if (sin6) {
		if (addr_len < offsetof(struct sockaddr, sa_data))
			return -EINVAL;

		switch (sin6->sin6_family) {
		case AF_INET6:
			if (addr_len < SIN6_LEN_RFC2133)
				return -EINVAL;
			daddr = &sin6->sin6_addr;
			break;
		case AF_INET:
			goto do_udp_sendmsg;
		case AF_UNSPEC:
			msg->msg_name = sin6 = NULL;
			msg->msg_namelen = addr_len = 0;
			daddr = NULL;
			break;
		default:
			return -EINVAL;
		}
	} else if (!up->pending) {
		if (sk->sk_state != TCP_ESTABLISHED)
			return -EDESTADDRREQ;
		daddr = &sk->sk_v6_daddr;
	} else
		daddr = NULL;

	if (daddr) {
		if (ipv6_addr_v4mapped(daddr)) {
			struct sockaddr_in sin;
			sin.sin_family = AF_INET;
			sin.sin_port = sin6 ? sin6->sin6_port : inet->inet_dport;
			sin.sin_addr.s_addr = daddr->s6_addr32[3];
			msg->msg_name = &sin;
			msg->msg_namelen = sizeof(sin);
do_udp_sendmsg:
			if (__ipv6_only_sock(sk))
				return -ENETUNREACH;
			return udp_sendmsg(iocb, sk, msg, len);
		}
	}

	if (up->pending == AF_INET)
		return udp_sendmsg(iocb, sk, msg, len);

	/* Rough check on arithmetic overflow,
 better check is made in ip6_append_data().
 */
	if (len > INT_MAX - sizeof(struct udphdr))
		return -EMSGSIZE;

	if (up->pending) {
		/*
 * There are pending frames.
 * The socket lock must be held while it's corked.
 */
		lock_sock(sk);
		if (likely(up->pending)) {
			if (unlikely(up->pending != AF_INET6)) {
				release_sock(sk);
				return -EAFNOSUPPORT;
			}
			dst = NULL;
			goto do_append_data;
		}
		release_sock(sk);
	}
	ulen += sizeof(struct udphdr);

	memset(&fl6, 0, sizeof(fl6));

	if (sin6) {
		if (sin6->sin6_port == 0)
			return -EINVAL;

		fl6.fl6_dport = sin6->sin6_port;
		daddr = &sin6->sin6_addr;

		if (np->sndflow) {
			fl6.flowlabel = sin6->sin6_flowinfo&IPV6_FLOWINFO_MASK;
			if (fl6.flowlabel&IPV6_FLOWLABEL_MASK) {
				flowlabel = fl6_sock_lookup(sk, fl6.flowlabel);
				if (flowlabel == NULL)
					return -EINVAL;
				daddr = &flowlabel->dst;
			}
		}

		/*
 * Otherwise it will be difficult to maintain
 * sk->sk_dst_cache.
 */
		if (sk->sk_state == TCP_ESTABLISHED &&
		    ipv6_addr_equal(daddr, &sk->sk_v6_daddr))
			daddr = &sk->sk_v6_daddr;

		if (addr_len >= sizeof(struct sockaddr_in6) &&
		    sin6->sin6_scope_id &&
		    __ipv6_addr_needs_scope_id(__ipv6_addr_type(daddr)))
			fl6.flowi6_oif = sin6->sin6_scope_id;
	} else {
		if (sk->sk_state != TCP_ESTABLISHED)
			return -EDESTADDRREQ;

		fl6.fl6_dport = inet->inet_dport;
		daddr = &sk->sk_v6_daddr;
		fl6.flowlabel = np->flow_label;
		connected = 1;
	}

	if (!fl6.flowi6_oif)
		fl6.flowi6_oif = sk->sk_bound_dev_if;

	if (!fl6.flowi6_oif)
		fl6.flowi6_oif = np->sticky_pktinfo.ipi6_ifindex;

	fl6.flowi6_mark = sk->sk_mark;

	if (msg->msg_controllen) {
		opt = &opt_space;
		memset(opt, 0, sizeof(struct ipv6_txoptions));
		opt->tot_len = sizeof(*opt);

		err = ip6_datagram_send_ctl(sock_net(sk), sk, msg, &fl6, opt,
					    &hlimit, &tclass, &dontfrag);
		if (err < 0) {
			fl6_sock_release(flowlabel);
			return err;
		}
		if ((fl6.flowlabel&IPV6_FLOWLABEL_MASK) && !flowlabel) {
			flowlabel = fl6_sock_lookup(sk, fl6.flowlabel);
			if (flowlabel == NULL)
				return -EINVAL;
		}
		if (!(opt->opt_nflen|opt->opt_flen))
			opt = NULL;
		connected = 0;
	}
	if (opt == NULL)
		opt = np->opt;
	if (flowlabel)
		opt = fl6_merge_options(&opt_space, flowlabel, opt);
	opt = ipv6_fixup_options(&opt_space, opt);

	fl6.flowi6_proto = sk->sk_protocol;
	if (!ipv6_addr_any(daddr))
		fl6.daddr = *daddr;
	else
		fl6.daddr.s6_addr[15] = 0x1; /* :: means loopback (BSD'ism) */
	if (ipv6_addr_any(&fl6.saddr) && !ipv6_addr_any(&np->saddr))
		fl6.saddr = np->saddr;
	fl6.fl6_sport = inet->inet_sport;

	final_p = fl6_update_dst(&fl6, opt, &final);
	if (final_p)
		connected = 0;

	if (!fl6.flowi6_oif && ipv6_addr_is_multicast(&fl6.daddr)) {
		fl6.flowi6_oif = np->mcast_oif;
		connected = 0;
	} else if (!fl6.flowi6_oif)
		fl6.flowi6_oif = np->ucast_oif;

	security_sk_classify_flow(sk, flowi6_to_flowi(&fl6));

	dst = ip6_sk_dst_lookup_flow(sk, &fl6, final_p, true);
	if (IS_ERR(dst)) {
		err = PTR_ERR(dst);
		dst = NULL;
		goto out;
	}

	if (hlimit < 0) {
		if (ipv6_addr_is_multicast(&fl6.daddr))
			hlimit = np->mcast_hops;
		else
			hlimit = np->hop_limit;
		if (hlimit < 0)
			hlimit = ip6_dst_hoplimit(dst);
	}

	if (tclass < 0)
		tclass = np->tclass;

	if (msg->msg_flags&MSG_CONFIRM)
		goto do_confirm;
back_from_confirm:

	lock_sock(sk);
	if (unlikely(up->pending)) {
		/* The socket is already corked while preparing it. */
		/* ... which is an evident application bug. --ANK */
		release_sock(sk);

		LIMIT_NETDEBUG(KERN_DEBUG "udp cork app bug 2\n");
		err = -EINVAL;
		goto out;
	}

	up->pending = AF_INET6;

do_append_data:
	if (dontfrag < 0)
		dontfrag = np->dontfrag;
	up->len += ulen;
	getfrag  =  is_udplite ?  udplite_getfrag : ip_generic_getfrag;
	err = ip6_append_data(sk, getfrag, msg->msg_iov, ulen,
		sizeof(struct udphdr), hlimit, tclass, opt, &fl6,
		(struct rt6_info*)dst,
		corkreq ? msg->msg_flags|MSG_MORE : msg->msg_flags, dontfrag);
	if (err)
		udp_v6_flush_pending_frames(sk);
	else if (!corkreq)
		err = udp_v6_push_pending_frames(sk);
	else if (unlikely(skb_queue_empty(&sk->sk_write_queue)))
		up->pending = 0;

	if (dst) {
		if (connected) {
			ip6_dst_store(sk, dst,
				      ipv6_addr_equal(&fl6.daddr, &sk->sk_v6_daddr) ?
				      &sk->sk_v6_daddr : NULL,
#ifdef CONFIG_IPV6_SUBTREES
				      ipv6_addr_equal(&fl6.saddr, &np->saddr) ?
				      &np->saddr :
#endif
				      NULL);
		} else {
			dst_release(dst);
		}
		dst = NULL;
	}

	if (err > 0)
		err = np->recverr ? net_xmit_errno(err) : 0;
	release_sock(sk);
out:
	dst_release(dst);
	fl6_sock_release(flowlabel);
	if (!err)
		return len;
	/*
 * ENOBUFS = no kernel mem, SOCK_NOSPACE = no sndbuf space. Reporting
 * ENOBUFS might not be good (it's not tunable per se), but otherwise
 * we don't have a good statistic (IpOutDiscards but it can be too many
 * things). We could add another new stat but at least for now that
 * seems like overkill.
 */
	if (err == -ENOBUFS || test_bit(SOCK_NOSPACE, &sk->sk_socket->flags)) {
		UDP6_INC_STATS_USER(sock_net(sk),
				UDP_MIB_SNDBUFERRORS, is_udplite);
	}
	return err;

do_confirm:
	dst_confirm(dst);
	if (!(msg->msg_flags&MSG_PROBE) || len)
		goto back_from_confirm;
	err = 0;
	goto out;
}

void udpv6_destroy_sock(struct sock *sk)
{
	struct udp_sock *up = udp_sk(sk);
	lock_sock(sk);
	udp_v6_flush_pending_frames(sk);
	release_sock(sk);

	if (static_key_false(&udpv6_encap_needed) && up->encap_type) {
		void (*encap_destroy)(struct sock *sk);
		encap_destroy = ACCESS_ONCE(up->encap_destroy);
		if (encap_destroy)
			encap_destroy(sk);
	}

	inet6_destroy_sock(sk);
}

/*
 * Socket option code for UDP
 */
int udpv6_setsockopt(struct sock *sk, int level, int optname,
		     char __user *optval, unsigned int optlen)
{
	if (level == SOL_UDP  ||  level == SOL_UDPLITE)
		return udp_lib_setsockopt(sk, level, optname, optval, optlen,
					  udp_v6_push_pending_frames);
	return ipv6_setsockopt(sk, level, optname, optval, optlen);
}

#ifdef CONFIG_COMPAT
int compat_udpv6_setsockopt(struct sock *sk, int level, int optname,
			    char __user *optval, unsigned int optlen)
{
	if (level == SOL_UDP  ||  level == SOL_UDPLITE)
		return udp_lib_setsockopt(sk, level, optname, optval, optlen,
					  udp_v6_push_pending_frames);
	return compat_ipv6_setsockopt(sk, level, optname, optval, optlen);
}
#endif

int udpv6_getsockopt(struct sock *sk, int level, int optname,
		     char __user *optval, int __user *optlen)
{
	if (level == SOL_UDP  ||  level == SOL_UDPLITE)
		return udp_lib_getsockopt(sk, level, optname, optval, optlen);
	return ipv6_getsockopt(sk, level, optname, optval, optlen);
}

#ifdef CONFIG_COMPAT
int compat_udpv6_getsockopt(struct sock *sk, int level, int optname,
			    char __user *optval, int __user *optlen)
{
	if (level == SOL_UDP  ||  level == SOL_UDPLITE)
		return udp_lib_getsockopt(sk, level, optname, optval, optlen);
	return compat_ipv6_getsockopt(sk, level, optname, optval, optlen);
}
#endif

static const struct inet6_protocol udpv6_protocol = {
	.handler	=	udpv6_rcv,
	.err_handler	=	udpv6_err,
	.flags		=	INET6_PROTO_NOPOLICY|INET6_PROTO_FINAL,
};

/* ------------------------------------------------------------------------ */
#ifdef CONFIG_PROC_FS
int udp6_seq_show(struct seq_file *seq, void *v)
{
	if (v == SEQ_START_TOKEN) {
		seq_puts(seq, IPV6_SEQ_DGRAM_HEADER);
	} else {
		int bucket = ((struct udp_iter_state *)seq->private)->bucket;
		struct inet_sock *inet = inet_sk(v);
		__u16 srcp = ntohs(inet->inet_sport);
		__u16 destp = ntohs(inet->inet_dport);
		ip6_dgram_sock_seq_show(seq, v, srcp, destp, bucket);
	}
	return 0;
}

static const struct file_operations udp6_afinfo_seq_fops = {
	.owner    = THIS_MODULE,
	.open     = udp_seq_open,
	.read     = seq_read,
	.llseek   = seq_lseek,
	.release  = seq_release_net
};

static struct udp_seq_afinfo udp6_seq_afinfo = {
	.name		= "udp6",
	.family		= AF_INET6,
	.udp_table	= &udp_table,
	.seq_fops	= &udp6_afinfo_seq_fops,
	.seq_ops	= {
		.show		= udp6_seq_show,
	},
};

int __net_init udp6_proc_init(struct net *net)
{
	return udp_proc_register(net, &udp6_seq_afinfo);
}

void udp6_proc_exit(struct net *net) {
	udp_proc_unregister(net, &udp6_seq_afinfo);
}
#endif /* CONFIG_PROC_FS */

void udp_v6_clear_sk(struct sock *sk, int size)
{
	struct inet_sock *inet = inet_sk(sk);

	/* we do not want to clear pinet6 field, because of RCU lookups */
	sk_prot_clear_portaddr_nulls(sk, offsetof(struct inet_sock, pinet6));

	size -= offsetof(struct inet_sock, pinet6) + sizeof(inet->pinet6);
	memset(&inet->pinet6 + 1, 0, size);
}

/* ------------------------------------------------------------------------ */

struct proto udpv6_prot = {
	.name		   = "UDPv6",
	.owner		   = THIS_MODULE,
	.close		   = udp_lib_close,
	.connect	   = ip6_datagram_connect,
	.disconnect	   = udp_disconnect,
	.ioctl		   = udp_ioctl,
	.destroy	   = udpv6_destroy_sock,
	.setsockopt	   = udpv6_setsockopt,
	.getsockopt	   = udpv6_getsockopt,
	.sendmsg	   = udpv6_sendmsg,
	.recvmsg	   = udpv6_recvmsg,
	.backlog_rcv	   = __udpv6_queue_rcv_skb,
	.hash		   = udp_lib_hash,
	.unhash		   = udp_lib_unhash,
	.rehash		   = udp_v6_rehash,
	.get_port	   = udp_v6_get_port,
	.memory_allocated  = &udp_memory_allocated,
	.sysctl_mem	   = sysctl_udp_mem,
	.sysctl_wmem	   = &sysctl_udp_wmem_min,
	.sysctl_rmem	   = &sysctl_udp_rmem_min,
	.obj_size	   = sizeof(struct udp6_sock),
	.slab_flags	   = SLAB_DESTROY_BY_RCU,
	.h.udp_table	   = &udp_table,
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_udpv6_setsockopt,
	.compat_getsockopt = compat_udpv6_getsockopt,
#endif
	.clear_sk	   = udp_v6_clear_sk,
};

static struct inet_protosw udpv6_protosw = {
	.type =      SOCK_DGRAM,
	.protocol =  IPPROTO_UDP,
	.prot = &udpv6_prot,
	.ops = &inet6_dgram_ops,
	.no_check =  UDP_CSUM_DEFAULT,
	.flags =     INET_PROTOSW_PERMANENT,
};


int __init udpv6_init(void)
{
	int ret;

	ret = inet6_add_protocol(&udpv6_protocol, IPPROTO_UDP);
	if (ret)
		goto out;

	ret = inet6_register_protosw(&udpv6_protosw);
	if (ret)
		goto out_udpv6_protocol;
out:
	return ret;

out_udpv6_protocol:
	inet6_del_protocol(&udpv6_protocol, IPPROTO_UDP);
	goto out;
}

void udpv6_exit(void)
{
	inet6_unregister_protosw(&udpv6_protosw);
	inet6_del_protocol(&udpv6_protocol, IPPROTO_UDP);
}