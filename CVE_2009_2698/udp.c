

/*
 * INET An implementation of the TCP/IP protocol suite for the LINUX
 * operating system. INET is implemented using the BSD Socket
 * interface as the means of communication with the user level.
 *
 * The User Datagram Protocol (UDP).
 *
 * Version: $Id: udp.c,v 1.102 2002/02/01 22:01:04 davem Exp $
 *
 * Authors: Ross Biro
 * Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 * Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 * Alan Cox, <Alan.Cox@linux.org>
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
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */
 
#include <asm/system.h>
#include <asm/uaccess.h>
#include <asm/ioctls.h>
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
#include <linux/ipv6.h>
#include <linux/netdevice.h>
#include <net/snmp.h>
#include <net/ip.h>
#include <net/tcp_states.h>
#include <net/protocol.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <net/sock.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <net/route.h>
#include <net/inet_common.h>
#include <net/checksum.h>
#include <net/xfrm.h>

/*
 * Snmp MIB for the UDP layer
 */

DEFINE_SNMP_STAT(struct udp_mib, udp_statistics) __read_mostly;

struct hlist_head udp_hash[UDP_HTABLE_SIZE];
DEFINE_RWLOCK(udp_hash_lock);

static int udp_port_rover;

static inline int udp_lport_inuse(u16 num)
{
	struct sock *sk;
	struct hlist_node *node;

	sk_for_each(sk, node, &udp_hash[num & (UDP_HTABLE_SIZE - 1)])
		if (inet_sk(sk)->num == num)
			return 1;
	return 0;
}

/**
 * udp_get_port - common port lookup for IPv4 and IPv6
 *
 * @sk: socket struct in question
 * @snum: port number to look up
 * @saddr_comp: AF-dependent comparison of bound local IP addresses
 */
int udp_get_port(struct sock *sk, unsigned short snum,
		 int (*saddr_cmp)(const struct sock *sk1, const struct sock *sk2))
{
	struct hlist_node *node;
	struct hlist_head *head;
	struct sock *sk2;
	int    error = 1;

	write_lock_bh(&udp_hash_lock);
	if (snum == 0) {
		int best_size_so_far, best, result, i;

		if (udp_port_rover > sysctl_local_port_range[1] ||
		    udp_port_rover < sysctl_local_port_range[0])
			udp_port_rover = sysctl_local_port_range[0];
		best_size_so_far = 32767;
		best = result = udp_port_rover;
		for (i = 0; i < UDP_HTABLE_SIZE; i++, result++) {
			int size;

			head = &udp_hash[result & (UDP_HTABLE_SIZE - 1)];
			if (hlist_empty(head)) {
				if (result > sysctl_local_port_range[1])
					result = sysctl_local_port_range[0] +
						((result - sysctl_local_port_range[0]) &
						 (UDP_HTABLE_SIZE - 1));
				goto gotit;
			}
			size = 0;
			sk_for_each(sk2, node, head)
				if (++size < best_size_so_far) {
					best_size_so_far = size;
					best = result;
				}
		}
		result = best;
		for(i = 0; i < (1 << 16) / UDP_HTABLE_SIZE; i++, result += UDP_HTABLE_SIZE) {
			if (result > sysctl_local_port_range[1])
				result = sysctl_local_port_range[0]
					+ ((result - sysctl_local_port_range[0]) &
					   (UDP_HTABLE_SIZE - 1));
			if (!udp_lport_inuse(result))
				break;
		}
		if (i >= (1 << 16) / UDP_HTABLE_SIZE)
			goto fail;
gotit:
		udp_port_rover = snum = result;
	} else {
		head = &udp_hash[snum & (UDP_HTABLE_SIZE - 1)];

		sk_for_each(sk2, node, head)
			if (inet_sk(sk2)->num == snum                        &&
			    sk2 != sk                                        &&
			    (!sk2->sk_reuse        || !sk->sk_reuse) &&
			    (!sk2->sk_bound_dev_if || !sk->sk_bound_dev_if
			     || sk2->sk_bound_dev_if == sk->sk_bound_dev_if) &&
			    (*saddr_cmp)(sk, sk2) )
				goto fail;
	}
	inet_sk(sk)->num = snum;
	if (sk_unhashed(sk)) {
		head = &udp_hash[snum & (UDP_HTABLE_SIZE - 1)];
		sk_add_node(sk, head);
		sock_prot_inc_use(sk->sk_prot);
	}
	error = 0;
fail:
	write_unlock_bh(&udp_hash_lock);
	return error;
}

static inline int ipv4_rcv_saddr_equal(const struct sock *sk1, const struct sock *sk2)
{
	struct inet_sock *inet1 = inet_sk(sk1), *inet2 = inet_sk(sk2);

	return 	( !ipv6_only_sock(sk2) &&
		  (!inet1->rcv_saddr || !inet2->rcv_saddr ||
		   inet1->rcv_saddr == inet2->rcv_saddr      ));
}

static inline int udp_v4_get_port(struct sock *sk, unsigned short snum)
{
	return udp_get_port(sk, snum, ipv4_rcv_saddr_equal);
}


static void udp_v4_hash(struct sock *sk)
{
	BUG();
}

static void udp_v4_unhash(struct sock *sk)
{
	write_lock_bh(&udp_hash_lock);
	if (sk_del_node_init(sk)) {
		inet_sk(sk)->num = 0;
		sock_prot_dec_use(sk->sk_prot);
	}
	write_unlock_bh(&udp_hash_lock);
}

/* UDP is nearly always wildcards out the wazoo, it makes no sense to try
 * harder than this. -DaveM
 */
static struct sock *udp_v4_lookup_longway(__be32 saddr, __be16 sport,
					  __be32 daddr, __be16 dport, int dif)
{
	struct sock *sk, *result = NULL;
	struct hlist_node *node;
	unsigned short hnum = ntohs(dport);
	int badness = -1;

	sk_for_each(sk, node, &udp_hash[hnum & (UDP_HTABLE_SIZE - 1)]) {
		struct inet_sock *inet = inet_sk(sk);

		if (inet->num == hnum && !ipv6_only_sock(sk)) {
			int score = (sk->sk_family == PF_INET ? 1 : 0);
			if (inet->rcv_saddr) {
				if (inet->rcv_saddr != daddr)
					continue;
				score+=2;
			}
			if (inet->daddr) {
				if (inet->daddr != saddr)
					continue;
				score+=2;
			}
			if (inet->dport) {
				if (inet->dport != sport)
					continue;
				score+=2;
			}
			if (sk->sk_bound_dev_if) {
				if (sk->sk_bound_dev_if != dif)
					continue;
				score+=2;
			}
			if(score == 9) {
				result = sk;
				break;
			} else if(score > badness) {
				result = sk;
				badness = score;
			}
		}
	}
	return result;
}

static __inline__ struct sock *udp_v4_lookup(__be32 saddr, __be16 sport,
					     __be32 daddr, __be16 dport, int dif)
{
	struct sock *sk;

	read_lock(&udp_hash_lock);
	sk = udp_v4_lookup_longway(saddr, sport, daddr, dport, dif);
	if (sk)
		sock_hold(sk);
	read_unlock(&udp_hash_lock);
	return sk;
}

static inline struct sock *udp_v4_mcast_next(struct sock *sk,
					     __be16 loc_port, __be32 loc_addr,
					     __be16 rmt_port, __be32 rmt_addr,
					     int dif)
{
	struct hlist_node *node;
	struct sock *s = sk;
	unsigned short hnum = ntohs(loc_port);

	sk_for_each_from(s, node) {
		struct inet_sock *inet = inet_sk(s);

		if (inet->num != hnum					||
		    (inet->daddr && inet->daddr != rmt_addr) ||
		    (inet->dport != rmt_port && inet->dport) ||
		    (inet->rcv_saddr && inet->rcv_saddr != loc_addr) ||
		    ipv6_only_sock(s) ||
		    (s->sk_bound_dev_if && s->sk_bound_dev_if != dif))
			continue;
		if (!ip_mc_sf_allow(s, loc_addr, rmt_addr, dif))
			continue;
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

void udp_err(struct sk_buff *skb, u32 info)
{
	struct inet_sock *inet;
	struct iphdr *iph = (struct iphdr*)skb->data;
	struct udphdr *uh = (struct udphdr*)(skb->data+(iph->ihl<<2));
	int type = skb->h.icmph->type;
	int code = skb->h.icmph->code;
	struct sock *sk;
	int harderr;
	int err;

	sk = udp_v4_lookup(iph->daddr, uh->dest, iph->saddr, uh->source, skb->dev->ifindex);
	if (sk == NULL) {
		ICMP_INC_STATS_BH(ICMP_MIB_INERRORS);
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
	}

	/*
 * RFC1122: OK. Passes ICMP errors back to application, as per 
 * 4.1.3.3.
 */
	if (!inet->recverr) {
		if (!harderr || sk->sk_state != TCP_ESTABLISHED)
			goto out;
	} else {
		ip_icmp_error(sk, skb, err, uh->dest, info, (u8*)(uh+1));
	}
	sk->sk_err = err;
	sk->sk_error_report(sk);
out:
	sock_put(sk);
}

/*
 * Throw away all pending data and cancel the corking. Socket is locked.
 */
static void udp_flush_pending_frames(struct sock *sk)
{
	struct udp_sock *up = udp_sk(sk);

	if (up->pending) {
		up->len = 0;
		up->pending = 0;
		ip_flush_pending_frames(sk);
	}
}

/*
 * Push out all pending data as one UDP datagram. Socket is locked.
 */
static int udp_push_pending_frames(struct sock *sk, struct udp_sock *up)
{
	struct inet_sock *inet = inet_sk(sk);
	struct flowi *fl = &inet->cork.fl;
	struct sk_buff *skb;
	struct udphdr *uh;
	int err = 0;

	/* Grab the skbuff where UDP header space exists. */
	if ((skb = skb_peek(&sk->sk_write_queue)) == NULL)
		goto out;

	/*
 * Create a UDP header
 */
	uh = skb->h.uh;
	uh->source = fl->fl_ip_sport;
	uh->dest = fl->fl_ip_dport;
	uh->len = htons(up->len);
	uh->check = 0;

	if (sk->sk_no_check == UDP_CSUM_NOXMIT) {
		skb->ip_summed = CHECKSUM_NONE;
		goto send;
	}

	if (skb_queue_len(&sk->sk_write_queue) == 1) {
		/*
 * Only one fragment on the socket.
 */
		if (skb->ip_summed == CHECKSUM_PARTIAL) {
			skb->csum = offsetof(struct udphdr, check);
			uh->check = ~csum_tcpudp_magic(fl->fl4_src, fl->fl4_dst,
					up->len, IPPROTO_UDP, 0);
		} else {
			skb->csum = csum_partial((char *)uh,
					sizeof(struct udphdr), skb->csum);
			uh->check = csum_tcpudp_magic(fl->fl4_src, fl->fl4_dst,
					up->len, IPPROTO_UDP, skb->csum);
			if (uh->check == 0)
				uh->check = -1;
		}
	} else {
		unsigned int csum = 0;
		/*
 * HW-checksum won't work as there are two or more 
 * fragments on the socket so that all csums of sk_buffs
 * should be together.
 */
		if (skb->ip_summed == CHECKSUM_PARTIAL) {
			int offset = (unsigned char *)uh - skb->data;
			skb->csum = skb_checksum(skb, offset, skb->len - offset, 0);

			skb->ip_summed = CHECKSUM_NONE;
		} else {
			skb->csum = csum_partial((char *)uh,
					sizeof(struct udphdr), skb->csum);
		}

		skb_queue_walk(&sk->sk_write_queue, skb) {
			csum = csum_add(csum, skb->csum);
		}
		uh->check = csum_tcpudp_magic(fl->fl4_src, fl->fl4_dst,
				up->len, IPPROTO_UDP, csum);
		if (uh->check == 0)
			uh->check = -1;
	}
send:
	err = ip_push_pending_frames(sk);
out:
	up->len = 0;
	up->pending = 0;
	return err;
}


static unsigned short udp_check(struct udphdr *uh, int len, __be32 saddr, __be32 daddr, unsigned long base)
{
	return(csum_tcpudp_magic(saddr, daddr, len, IPPROTO_UDP, base));
}

int udp_sendmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
		size_t len)
{
	struct inet_sock *inet = inet_sk(sk);
	struct udp_sock *up = udp_sk(sk);
	int ulen = len;
	struct ipcm_cookie ipc;
	struct rtable *rt = NULL;
	int free = 0;
	int connected = 0;
	__be32 daddr, faddr, saddr;
	__be16 dport;
	u8  tos;
	int err;
	int corkreq = up->corkflag || msg->msg_flags&MSG_MORE;

	if (len > 0xFFFF)
		return -EMSGSIZE;

	/* 
 * Check the flags.
 */

	if (msg->msg_flags&MSG_OOB)	/* Mirror BSD error message compatibility */
		return -EOPNOTSUPP;

	ipc.opt = NULL;

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
		struct sockaddr_in * usin = (struct sockaddr_in*)msg->msg_name;
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
		daddr = inet->daddr;
		dport = inet->dport;
		/* Open fast path for connected socket.
 Route will not be used, if at least one option is set.
 */
		connected = 1;
  	}
	ipc.addr = inet->saddr;

	ipc.oif = sk->sk_bound_dev_if;
	if (msg->msg_controllen) {
		err = ip_cmsg_send(msg, &ipc);
		if (err)
			return err;
		if (ipc.opt)
			free = 1;
		connected = 0;
	}
	if (!ipc.opt)
		ipc.opt = inet->opt;

	saddr = ipc.addr;
	ipc.addr = faddr = daddr;

	if (ipc.opt && ipc.opt->srr) {
		if (!daddr)
			return -EINVAL;
		faddr = ipc.opt->faddr;
		connected = 0;
	}
	tos = RT_TOS(inet->tos);
	if (sock_flag(sk, SOCK_LOCALROUTE) ||
	    (msg->msg_flags & MSG_DONTROUTE) || 
	    (ipc.opt && ipc.opt->is_strictroute)) {
		tos |= RTO_ONLINK;
		connected = 0;
	}

	if (MULTICAST(daddr)) {
		if (!ipc.oif)
			ipc.oif = inet->mc_index;
		if (!saddr)
			saddr = inet->mc_addr;
		connected = 0;
	}

	if (connected)
		rt = (struct rtable*)sk_dst_check(sk, 0);

	if (rt == NULL) {
		struct flowi fl = { .oif = ipc.oif,
				    .nl_u = { .ip4_u =
					      { .daddr = faddr,
						.saddr = saddr,
						.tos = tos } },
				    .proto = IPPROTO_UDP,
				    .uli_u = { .ports =
					       { .sport = inet->sport,
						 .dport = dport } } };
		security_sk_classify_flow(sk, &fl);
		err = ip_route_output_flow(&rt, &fl, sk, !(msg->msg_flags&MSG_DONTWAIT));
		if (err)
			goto out;

		err = -EACCES;
		if ((rt->rt_flags & RTCF_BROADCAST) &&
		    !sock_flag(sk, SOCK_BROADCAST))
			goto out;
		if (connected)
			sk_dst_set(sk, dst_clone(&rt->u.dst));
	}

	if (msg->msg_flags&MSG_CONFIRM)
		goto do_confirm;
back_from_confirm:

	saddr = rt->rt_src;
	if (!ipc.addr)
		daddr = ipc.addr = rt->rt_dst;

	lock_sock(sk);
	if (unlikely(up->pending)) {
		/* The socket is already corked while preparing it. */
		/* ... which is an evident application bug. --ANK */
		release_sock(sk);

		LIMIT_NETDEBUG(KERN_DEBUG "udp cork app bug 2\n");
		err = -EINVAL;
		goto out;
	}
	/*
 * Now cork the socket to pend data.
 */
	inet->cork.fl.fl4_dst = daddr;
	inet->cork.fl.fl_ip_dport = dport;
	inet->cork.fl.fl4_src = saddr;
	inet->cork.fl.fl_ip_sport = inet->sport;
	up->pending = AF_INET;

do_append_data:
	up->len += ulen;
	err = ip_append_data(sk, ip_generic_getfrag, msg->msg_iov, ulen, 
			sizeof(struct udphdr), &ipc, rt, 
			corkreq ? msg->msg_flags|MSG_MORE : msg->msg_flags);
	if (err)
		udp_flush_pending_frames(sk);
	else if (!corkreq)
		err = udp_push_pending_frames(sk, up);
	release_sock(sk);

out:
	ip_rt_put(rt);
	if (free)
		kfree(ipc.opt);
	if (!err) {
		UDP_INC_STATS_USER(UDP_MIB_OUTDATAGRAMS);
		return len;
	}
	/*
 * ENOBUFS = no kernel mem, SOCK_NOSPACE = no sndbuf space. Reporting
 * ENOBUFS might not be good (it's not tunable per se), but otherwise
 * we don't have a good statistic (IpOutDiscards but it can be too many
 * things). We could add another new stat but at least for now that
 * seems like overkill.
 */
	if (err == -ENOBUFS || test_bit(SOCK_NOSPACE, &sk->sk_socket->flags)) {
		UDP_INC_STATS_USER(UDP_MIB_SNDBUFERRORS);
	}
	return err;

do_confirm:
	dst_confirm(&rt->u.dst);
	if (!(msg->msg_flags&MSG_PROBE) || len)
		goto back_from_confirm;
	err = 0;
	goto out;
}

static int udp_sendpage(struct sock *sk, struct page *page, int offset,
			size_t size, int flags)
{
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

		LIMIT_NETDEBUG(KERN_DEBUG "udp cork app bug 3\n");
		return -EINVAL;
	}

	ret = ip_append_page(sk, page, offset, size, flags);
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
		ret = udp_push_pending_frames(sk, up);
	if (!ret)
		ret = size;
out:
	release_sock(sk);
	return ret;
}

/*
 * IOCTL requests applicable to the UDP protocol
 */
 
int udp_ioctl(struct sock *sk, int cmd, unsigned long arg)
{
	switch(cmd) 
	{
		case SIOCOUTQ:
		{
			int amount = atomic_read(&sk->sk_wmem_alloc);
			return put_user(amount, (int __user *)arg);
		}

		case SIOCINQ:
		{
			struct sk_buff *skb;
			unsigned long amount;

			amount = 0;
			spin_lock_bh(&sk->sk_receive_queue.lock);
			skb = skb_peek(&sk->sk_receive_queue);
			if (skb != NULL) {
				/*
 * We will only return the amount
 * of this packet since that is all
 * that will be read.
 */
				amount = skb->len - sizeof(struct udphdr);
			}
			spin_unlock_bh(&sk->sk_receive_queue.lock);
			return put_user(amount, (int __user *)arg);
		}

		default:
			return -ENOIOCTLCMD;
	}
	return(0);
}

static __inline__ int __udp_checksum_complete(struct sk_buff *skb)
{
	return __skb_checksum_complete(skb);
}

static __inline__ int udp_checksum_complete(struct sk_buff *skb)
{
	return skb->ip_summed != CHECKSUM_UNNECESSARY &&
		__udp_checksum_complete(skb);
}

/*
 * This should be easy, if there is something there we
 * return it, otherwise we block.
 */

static int udp_recvmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
		       size_t len, int noblock, int flags, int *addr_len)
{
	struct inet_sock *inet = inet_sk(sk);
  	struct sockaddr_in *sin = (struct sockaddr_in *)msg->msg_name;
  	struct sk_buff *skb;
  	int copied, err;

	/*
 * Check any passed addresses
 */
	if (addr_len)
		*addr_len=sizeof(*sin);

	if (flags & MSG_ERRQUEUE)
		return ip_recv_error(sk, msg, len);

try_again:
	skb = skb_recv_datagram(sk, flags, noblock, &err);
	if (!skb)
		goto out;
  
  	copied = skb->len - sizeof(struct udphdr);
	if (copied > len) {
		copied = len;
		msg->msg_flags |= MSG_TRUNC;
	}

	if (skb->ip_summed==CHECKSUM_UNNECESSARY) {
		err = skb_copy_datagram_iovec(skb, sizeof(struct udphdr), msg->msg_iov,
					      copied);
	} else if (msg->msg_flags&MSG_TRUNC) {
		if (__udp_checksum_complete(skb))
			goto csum_copy_err;
		err = skb_copy_datagram_iovec(skb, sizeof(struct udphdr), msg->msg_iov,
					      copied);
	} else {
		err = skb_copy_and_csum_datagram_iovec(skb, sizeof(struct udphdr), msg->msg_iov);

		if (err == -EINVAL)
			goto csum_copy_err;
	}

	if (err)
		goto out_free;

	sock_recv_timestamp(msg, sk, skb);

	/* Copy the address. */
	if (sin)
	{
		sin->sin_family = AF_INET;
		sin->sin_port = skb->h.uh->source;
		sin->sin_addr.s_addr = skb->nh.iph->saddr;
		memset(sin->sin_zero, 0, sizeof(sin->sin_zero));
  	}
	if (inet->cmsg_flags)
		ip_cmsg_recv(msg, skb);

	err = copied;
	if (flags & MSG_TRUNC)
		err = skb->len - sizeof(struct udphdr);
  
out_free:
  	skb_free_datagram(sk, skb);
out:
  	return err;

csum_copy_err:
	UDP_INC_STATS_BH(UDP_MIB_INERRORS);

	skb_kill_datagram(sk, skb, flags);

	if (noblock)
		return -EAGAIN;	
	goto try_again;
}


int udp_disconnect(struct sock *sk, int flags)
{
	struct inet_sock *inet = inet_sk(sk);
	/*
 * 1003.1g - break association.
 */
	 
	sk->sk_state = TCP_CLOSE;
	inet->daddr = 0;
	inet->dport = 0;
	sk->sk_bound_dev_if = 0;
	if (!(sk->sk_userlocks & SOCK_BINDADDR_LOCK))
		inet_reset_saddr(sk);

	if (!(sk->sk_userlocks & SOCK_BINDPORT_LOCK)) {
		sk->sk_prot->unhash(sk);
		inet->sport = 0;
	}
	sk_dst_reset(sk);
	return 0;
}

static void udp_close(struct sock *sk, long timeout)
{
	sk_common_release(sk);
}

/* return:
 * 1 if the the UDP system should process it
 * 0 if we should drop this packet
 * -1 if it should get processed by xfrm4_rcv_encap
 */
static int udp_encap_rcv(struct sock * sk, struct sk_buff *skb)
{
#ifndef CONFIG_XFRM
	return 1; 
#else
	struct udp_sock *up = udp_sk(sk);
  	struct udphdr *uh = skb->h.uh;
	struct iphdr *iph;
	int iphlen, len;
  
	__u8 *udpdata = (__u8 *)uh + sizeof(struct udphdr);
	__be32 *udpdata32 = (__be32 *)udpdata;
	__u16 encap_type = up->encap_type;

	/* if we're overly short, let UDP handle it */
	if (udpdata > skb->tail)
		return 1;

	/* if this is not encapsulated socket, then just return now */
	if (!encap_type)
		return 1;

	len = skb->tail - udpdata;

	switch (encap_type) {
	default:
	case UDP_ENCAP_ESPINUDP:
		/* Check if this is a keepalive packet. If so, eat it. */
		if (len == 1 && udpdata[0] == 0xff) {
			return 0;
		} else if (len > sizeof(struct ip_esp_hdr) && udpdata32[0] != 0 ) {
			/* ESP Packet without Non-ESP header */
			len = sizeof(struct udphdr);
		} else
			/* Must be an IKE packet.. pass it through */
			return 1;
		break;
	case UDP_ENCAP_ESPINUDP_NON_IKE:
		/* Check if this is a keepalive packet. If so, eat it. */
		if (len == 1 && udpdata[0] == 0xff) {
			return 0;
		} else if (len > 2 * sizeof(u32) + sizeof(struct ip_esp_hdr) &&
			   udpdata32[0] == 0 && udpdata32[1] == 0) {
			
			/* ESP Packet with Non-IKE marker */
			len = sizeof(struct udphdr) + 2 * sizeof(u32);
		} else
			/* Must be an IKE packet.. pass it through */
			return 1;
		break;
	}

	/* At this point we are sure that this is an ESPinUDP packet,
 * so we need to remove 'len' bytes from the packet (the UDP
 * header and optional ESP marker bytes) and then modify the
 * protocol to ESP, and then call into the transform receiver.
 */
	if (skb_cloned(skb) && pskb_expand_head(skb, 0, 0, GFP_ATOMIC))
		return 0;

	/* Now we can update and verify the packet length... */
	iph = skb->nh.iph;
	iphlen = iph->ihl << 2;
	iph->tot_len = htons(ntohs(iph->tot_len) - len);
	if (skb->len < iphlen + len) {
		/* packet is too small!?! */
		return 0;
	}

	/* pull the data buffer up to the ESP header and set the
 * transport header to point to ESP. Keep UDP on the stack
 * for later.
 */
	skb->h.raw = skb_pull(skb, len);

	/* modify the protocol (it's ESP!) */
	iph->protocol = IPPROTO_ESP;

	/* and let the caller know to send this into the ESP processor... */
	return -1;
#endif
}

/* returns:
 * -1: error
 * 0: success
 * >0: "udp encap" protocol resubmission
 *
 * Note that in the success and error cases, the skb is assumed to
 * have either been requeued or freed.
 */
static int udp_queue_rcv_skb(struct sock * sk, struct sk_buff *skb)
{
	struct udp_sock *up = udp_sk(sk);
	int rc;

	/*
 * Charge it to the socket, dropping if the queue is full.
 */
	if (!xfrm4_policy_check(sk, XFRM_POLICY_IN, skb)) {
		kfree_skb(skb);
		return -1;
	}
	nf_reset(skb);

	if (up->encap_type) {
		/*
 * This is an encapsulation socket, so let's see if this is
 * an encapsulated packet.
 * If it's a keepalive packet, then just eat it.
 * If it's an encapsulateed packet, then pass it to the
 * IPsec xfrm input and return the response
 * appropriately. Otherwise, just fall through and
 * pass this up the UDP socket.
 */
		int ret;

		ret = udp_encap_rcv(sk, skb);
		if (ret == 0) {
			/* Eat the packet .. */
			kfree_skb(skb);
			return 0;
		}
		if (ret < 0) {
			/* process the ESP packet */
			ret = xfrm4_rcv_encap(skb, up->encap_type);
			UDP_INC_STATS_BH(UDP_MIB_INDATAGRAMS);
			return -ret;
		}
		/* FALLTHROUGH -- it's a UDP Packet */
	}

	if (sk->sk_filter && skb->ip_summed != CHECKSUM_UNNECESSARY) {
		if (__udp_checksum_complete(skb)) {
			UDP_INC_STATS_BH(UDP_MIB_INERRORS);
			kfree_skb(skb);
			return -1;
		}
		skb->ip_summed = CHECKSUM_UNNECESSARY;
	}

	if ((rc = sock_queue_rcv_skb(sk,skb)) < 0) {
		/* Note that an ENOMEM error is charged twice */
		if (rc == -ENOMEM)
			UDP_INC_STATS_BH(UDP_MIB_RCVBUFERRORS);
		UDP_INC_STATS_BH(UDP_MIB_INERRORS);
		kfree_skb(skb);
		return -1;
	}
	UDP_INC_STATS_BH(UDP_MIB_INDATAGRAMS);
	return 0;
}

/*
 * Multicasts and broadcasts go to each listener.
 *
 * Note: called only from the BH handler context,
 * so we don't need to lock the hashes.
 */
static int udp_v4_mcast_deliver(struct sk_buff *skb, struct udphdr *uh,
				 __be32 saddr, __be32 daddr)
{
	struct sock *sk;
	int dif;

	read_lock(&udp_hash_lock);
	sk = sk_head(&udp_hash[ntohs(uh->dest) & (UDP_HTABLE_SIZE - 1)]);
	dif = skb->dev->ifindex;
	sk = udp_v4_mcast_next(sk, uh->dest, daddr, uh->source, saddr, dif);
	if (sk) {
		struct sock *sknext = NULL;

		do {
			struct sk_buff *skb1 = skb;

			sknext = udp_v4_mcast_next(sk_next(sk), uh->dest, daddr,
						   uh->source, saddr, dif);
			if(sknext)
				skb1 = skb_clone(skb, GFP_ATOMIC);

			if(skb1) {
				int ret = udp_queue_rcv_skb(sk, skb1);
				if (ret > 0)
					/* we should probably re-process instead
 * of dropping packets here. */
					kfree_skb(skb1);
			}
			sk = sknext;
		} while(sknext);
	} else
		kfree_skb(skb);
	read_unlock(&udp_hash_lock);
	return 0;
}

/* Initialize UDP checksum. If exited with zero value (success),
 * CHECKSUM_UNNECESSARY means, that no more checks are required.
 * Otherwise, csum completion requires chacksumming packet body,
 * including udp header and folding it to skb->csum.
 */
static void udp_checksum_init(struct sk_buff *skb, struct udphdr *uh,
			     unsigned short ulen, __be32 saddr, __be32 daddr)
{
	if (uh->check == 0) {
		skb->ip_summed = CHECKSUM_UNNECESSARY;
	} else if (skb->ip_summed == CHECKSUM_COMPLETE) {
		if (!udp_check(uh, ulen, saddr, daddr, skb->csum))
			skb->ip_summed = CHECKSUM_UNNECESSARY;
	}
	if (skb->ip_summed != CHECKSUM_UNNECESSARY)
		skb->csum = csum_tcpudp_nofold(saddr, daddr, ulen, IPPROTO_UDP, 0);
	/* Probably, we should checksum udp header (it should be in cache
 * in any case) and data in tiny packets (< rx copybreak).
 */
}

/*
 * All we need to do is get the socket, and then do a checksum. 
 */
 
int udp_rcv(struct sk_buff *skb)
{
  	struct sock *sk;
  	struct udphdr *uh;
	unsigned short ulen;
	struct rtable *rt = (struct rtable*)skb->dst;
	__be32 saddr = skb->nh.iph->saddr;
	__be32 daddr = skb->nh.iph->daddr;
	int len = skb->len;

	/*
 * Validate the packet and the UDP length.
 */
	if (!pskb_may_pull(skb, sizeof(struct udphdr)))
		goto no_header;

	uh = skb->h.uh;

	ulen = ntohs(uh->len);

	if (ulen > len || ulen < sizeof(*uh))
		goto short_packet;

	if (pskb_trim_rcsum(skb, ulen))
		goto short_packet;

	udp_checksum_init(skb, uh, ulen, saddr, daddr);

	if(rt->rt_flags & (RTCF_BROADCAST|RTCF_MULTICAST))
		return udp_v4_mcast_deliver(skb, uh, saddr, daddr);

	sk = udp_v4_lookup(saddr, uh->source, daddr, uh->dest, skb->dev->ifindex);

	if (sk != NULL) {
		int ret = udp_queue_rcv_skb(sk, skb);
		sock_put(sk);

		/* a return value > 0 means to resubmit the input, but
 * it it wants the return to be -protocol, or 0
 */
		if (ret > 0)
			return -ret;
		return 0;
	}

	if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb))
		goto drop;
	nf_reset(skb);

	/* No socket. Drop packet silently, if checksum is wrong */
	if (udp_checksum_complete(skb))
		goto csum_error;

	UDP_INC_STATS_BH(UDP_MIB_NOPORTS);
	icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, 0);

	/*
 * Hmm. We got an UDP packet to a port to which we
 * don't wanna listen. Ignore it.
 */
	kfree_skb(skb);
	return(0);

short_packet:
	LIMIT_NETDEBUG(KERN_DEBUG "UDP: short packet: From %u.%u.%u.%u:%u %d/%d to %u.%u.%u.%u:%u\n",
		       NIPQUAD(saddr),
		       ntohs(uh->source),
		       ulen,
		       len,
		       NIPQUAD(daddr),
		       ntohs(uh->dest));
no_header:
	UDP_INC_STATS_BH(UDP_MIB_INERRORS);
	kfree_skb(skb);
	return(0);

csum_error:
	/* 
 * RFC1122: OK. Discards the bad packet silently (as far as 
 * the network is concerned, anyway) as per 4.1.3.4 (MUST). 
 */
	LIMIT_NETDEBUG(KERN_DEBUG "UDP: bad checksum. From %d.%d.%d.%d:%d to %d.%d.%d.%d:%d ulen %d\n",
		       NIPQUAD(saddr),
		       ntohs(uh->source),
		       NIPQUAD(daddr),
		       ntohs(uh->dest),
		       ulen);
drop:
	UDP_INC_STATS_BH(UDP_MIB_INERRORS);
	kfree_skb(skb);
	return(0);
}

static int udp_destroy_sock(struct sock *sk)
{
	lock_sock(sk);
	udp_flush_pending_frames(sk);
	release_sock(sk);
	return 0;
}

/*
 * Socket option code for UDP
 */
static int do_udp_setsockopt(struct sock *sk, int level, int optname,
			  char __user *optval, int optlen)
{
	struct udp_sock *up = udp_sk(sk);
	int val;
	int err = 0;

	if(optlen<sizeof(int))
		return -EINVAL;

	if (get_user(val, (int __user *)optval))
		return -EFAULT;

	switch(optname) {
	case UDP_CORK:
		if (val != 0) {
			up->corkflag = 1;
		} else {
			up->corkflag = 0;
			lock_sock(sk);
			udp_push_pending_frames(sk, up);
			release_sock(sk);
		}
		break;
		
	case UDP_ENCAP:
		switch (val) {
		case 0:
		case UDP_ENCAP_ESPINUDP:
		case UDP_ENCAP_ESPINUDP_NON_IKE:
			up->encap_type = val;
			break;
		default:
			err = -ENOPROTOOPT;
			break;
		}
		break;

	default:
		err = -ENOPROTOOPT;
		break;
	};

	return err;
}

static int udp_setsockopt(struct sock *sk, int level, int optname,
			  char __user *optval, int optlen)
{
	if (level != SOL_UDP)
		return ip_setsockopt(sk, level, optname, optval, optlen);
	return do_udp_setsockopt(sk, level, optname, optval, optlen);
}

#ifdef CONFIG_COMPAT
static int compat_udp_setsockopt(struct sock *sk, int level, int optname,
				 char __user *optval, int optlen)
{
	if (level != SOL_UDP)
		return compat_ip_setsockopt(sk, level, optname, optval, optlen);
	return do_udp_setsockopt(sk, level, optname, optval, optlen);
}
#endif

static int do_udp_getsockopt(struct sock *sk, int level, int optname,
			  char __user *optval, int __user *optlen)
{
	struct udp_sock *up = udp_sk(sk);
	int val, len;

	if(get_user(len,optlen))
		return -EFAULT;

	len = min_t(unsigned int, len, sizeof(int));
	
	if(len < 0)
		return -EINVAL;

	switch(optname) {
	case UDP_CORK:
		val = up->corkflag;
		break;

	case UDP_ENCAP:
		val = up->encap_type;
		break;

	default:
		return -ENOPROTOOPT;
	};

  	if(put_user(len, optlen))
  		return -EFAULT;
	if(copy_to_user(optval, &val,len))
		return -EFAULT;
  	return 0;
}

static int udp_getsockopt(struct sock *sk, int level, int optname,
			  char __user *optval, int __user *optlen)
{
	if (level != SOL_UDP)
		return ip_getsockopt(sk, level, optname, optval, optlen);
	return do_udp_getsockopt(sk, level, optname, optval, optlen);
}

#ifdef CONFIG_COMPAT
static int compat_udp_getsockopt(struct sock *sk, int level, int optname,
				 char __user *optval, int __user *optlen)
{
	if (level != SOL_UDP)
		return compat_ip_getsockopt(sk, level, optname, optval, optlen);
	return do_udp_getsockopt(sk, level, optname, optval, optlen);
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
	
	/* Check for false positives due to checksum errors */
	if ( (mask & POLLRDNORM) &&
	     !(file->f_flags & O_NONBLOCK) &&
	     !(sk->sk_shutdown & RCV_SHUTDOWN)){
		struct sk_buff_head *rcvq = &sk->sk_receive_queue;
		struct sk_buff *skb;

		spin_lock_bh(&rcvq->lock);
		while ((skb = skb_peek(rcvq)) != NULL) {
			if (udp_checksum_complete(skb)) {
				UDP_INC_STATS_BH(UDP_MIB_INERRORS);
				__skb_unlink(skb, rcvq);
				kfree_skb(skb);
			} else {
				skb->ip_summed = CHECKSUM_UNNECESSARY;
				break;
			}
		}
		spin_unlock_bh(&rcvq->lock);

		/* nothing to see, move along */
		if (skb == NULL)
			mask &= ~(POLLIN | POLLRDNORM);
	}

	return mask;
	
}

struct proto udp_prot = {
 	.name		   = "UDP",
	.owner		   = THIS_MODULE,
	.close		   = udp_close,
	.connect	   = ip4_datagram_connect,
	.disconnect	   = udp_disconnect,
	.ioctl		   = udp_ioctl,
	.destroy	   = udp_destroy_sock,
	.setsockopt	   = udp_setsockopt,
	.getsockopt	   = udp_getsockopt,
	.sendmsg	   = udp_sendmsg,
	.recvmsg	   = udp_recvmsg,
	.sendpage	   = udp_sendpage,
	.backlog_rcv	   = udp_queue_rcv_skb,
	.hash		   = udp_v4_hash,
	.unhash		   = udp_v4_unhash,
	.get_port	   = udp_v4_get_port,
	.obj_size	   = sizeof(struct udp_sock),
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_udp_setsockopt,
	.compat_getsockopt = compat_udp_getsockopt,
#endif
};

/* ------------------------------------------------------------------------ */
#ifdef CONFIG_PROC_FS

static struct sock *udp_get_first(struct seq_file *seq)
{
	struct sock *sk;
	struct udp_iter_state *state = seq->private;

	for (state->bucket = 0; state->bucket < UDP_HTABLE_SIZE; ++state->bucket) {
		struct hlist_node *node;
		sk_for_each(sk, node, &udp_hash[state->bucket]) {
			if (sk->sk_family == state->family)
				goto found;
		}
	}
	sk = NULL;
found:
	return sk;
}

static struct sock *udp_get_next(struct seq_file *seq, struct sock *sk)
{
	struct udp_iter_state *state = seq->private;

	do {
		sk = sk_next(sk);
try_again:
		;
	} while (sk && sk->sk_family != state->family);

	if (!sk && ++state->bucket < UDP_HTABLE_SIZE) {
		sk = sk_head(&udp_hash[state->bucket]);
		goto try_again;
	}
	return sk;
}

static struct sock *udp_get_idx(struct seq_file *seq, loff_t pos)
{
	struct sock *sk = udp_get_first(seq);

	if (sk)
		while(pos && (sk = udp_get_next(seq, sk)) != NULL)
			--pos;
	return pos ? NULL : sk;
}

static void *udp_seq_start(struct seq_file *seq, loff_t *pos)
{
	read_lock(&udp_hash_lock);
	return *pos ? udp_get_idx(seq, *pos-1) : (void *)1;
}

static void *udp_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct sock *sk;

	if (v == (void *)1)
		sk = udp_get_idx(seq, 0);
	else
		sk = udp_get_next(seq, v);

	++*pos;
	return sk;
}

static void udp_seq_stop(struct seq_file *seq, void *v)
{
	read_unlock(&udp_hash_lock);
}

static int udp_seq_open(struct inode *inode, struct file *file)
{
	struct udp_seq_afinfo *afinfo = PDE(inode)->data;
	struct seq_file *seq;
	int rc = -ENOMEM;
	struct udp_iter_state *s = kzalloc(sizeof(*s), GFP_KERNEL);

	if (!s)
		goto out;
	s->family		= afinfo->family;
	s->seq_ops.start	= udp_seq_start;
	s->seq_ops.next		= udp_seq_next;
	s->seq_ops.show		= afinfo->seq_show;
	s->seq_ops.stop		= udp_seq_stop;

	rc = seq_open(file, &s->seq_ops);
	if (rc)
		goto out_kfree;

	seq	     = file->private_data;
	seq->private = s;
out:
	return rc;
out_kfree:
	kfree(s);
	goto out;
}

/* ------------------------------------------------------------------------ */
int udp_proc_register(struct udp_seq_afinfo *afinfo)
{
	struct proc_dir_entry *p;
	int rc = 0;

	if (!afinfo)
		return -EINVAL;
	afinfo->seq_fops->owner		= afinfo->owner;
	afinfo->seq_fops->open		= udp_seq_open;
	afinfo->seq_fops->read		= seq_read;
	afinfo->seq_fops->llseek	= seq_lseek;
	afinfo->seq_fops->release	= seq_release_private;

	p = proc_net_fops_create(afinfo->name, S_IRUGO, afinfo->seq_fops);
	if (p)
		p->data = afinfo;
	else
		rc = -ENOMEM;
	return rc;
}

void udp_proc_unregister(struct udp_seq_afinfo *afinfo)
{
	if (!afinfo)
		return;
	proc_net_remove(afinfo->name);
	memset(afinfo->seq_fops, 0, sizeof(*afinfo->seq_fops));
}

/* ------------------------------------------------------------------------ */
static void udp4_format_sock(struct sock *sp, char *tmpbuf, int bucket)
{
	struct inet_sock *inet = inet_sk(sp);
	__be32 dest = inet->daddr;
	__be32 src  = inet->rcv_saddr;
	__u16 destp	  = ntohs(inet->dport);
	__u16 srcp	  = ntohs(inet->sport);

	sprintf(tmpbuf, "%4d: %08X:%04X %08X:%04X"
		" %02X %08X:%08X %02X:%08lX %08X %5d %8d %lu %d %p",
		bucket, src, srcp, dest, destp, sp->sk_state, 
		atomic_read(&sp->sk_wmem_alloc),
		atomic_read(&sp->sk_rmem_alloc),
		0, 0L, 0, sock_i_uid(sp), 0, sock_i_ino(sp),
		atomic_read(&sp->sk_refcnt), sp);
}

static int udp4_seq_show(struct seq_file *seq, void *v)
{
	if (v == SEQ_START_TOKEN)
		seq_printf(seq, "%-127s\n",
			   " sl local_address rem_address st tx_queue "
			   "rx_queue tr tm->when retrnsmt uid timeout "
			   "inode");
	else {
		char tmpbuf[129];
		struct udp_iter_state *state = seq->private;

		udp4_format_sock(v, tmpbuf, state->bucket);
		seq_printf(seq, "%-127s\n", tmpbuf);
	}
	return 0;
}

/* ------------------------------------------------------------------------ */
static struct file_operations udp4_seq_fops;
static struct udp_seq_afinfo udp4_seq_afinfo = {
	.owner		= THIS_MODULE,
	.name		= "udp",
	.family		= AF_INET,
	.seq_show	= udp4_seq_show,
	.seq_fops	= &udp4_seq_fops,
};

int __init udp4_proc_init(void)
{
	return udp_proc_register(&udp4_seq_afinfo);
}

void udp4_proc_exit(void)
{
	udp_proc_unregister(&udp4_seq_afinfo);
}
#endif /* CONFIG_PROC_FS */

EXPORT_SYMBOL(udp_disconnect);
EXPORT_SYMBOL(udp_hash);
EXPORT_SYMBOL(udp_hash_lock);
EXPORT_SYMBOL(udp_ioctl);
EXPORT_SYMBOL(udp_get_port);
EXPORT_SYMBOL(udp_prot);
EXPORT_SYMBOL(udp_sendmsg);
EXPORT_SYMBOL(udp_poll);

#ifdef CONFIG_PROC_FS
EXPORT_SYMBOL(udp_proc_register);
EXPORT_SYMBOL(udp_proc_unregister);
#endif

/*
 * UDP over IPv6
 * Linux INET6 implementation 
 *
 * Authors:
 * Pedro Roque <roque@di.fc.ul.pt> 
 *
 * Based on linux/ipv4/udp.c
 *
 * $Id: udp.c,v 1.65 2002/02/01 22:01:04 davem Exp $
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
#include <linux/sched.h>
#include <linux/net.h>
#include <linux/in6.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <asm/uaccess.h>

#include <net/sock.h>
#include <net/snmp.h>

#include <net/ipv6.h>
#include <net/ndisc.h>
#include <net/protocol.h>
#include <net/transp_v6.h>
#include <net/ip6_route.h>
#include <net/addrconf.h>
#include <net/ip.h>
#include <net/udp.h>
#include <net/raw.h>
#include <net/inet_common.h>
#include <net/tcp_states.h>

#include <net/ip6_checksum.h>
#include <net/xfrm.h>

#include <linux/proc_fs.h>
#include <linux/seq_file.h>

DEFINE_SNMP_STAT(struct udp_mib, udp_stats_in6) __read_mostly;

static inline int udp_v6_get_port(struct sock *sk, unsigned short snum)
{
	return udp_get_port(sk, snum, ipv6_rcv_saddr_equal);
}

static void udp_v6_hash(struct sock *sk)
{
	BUG();
}

static void udp_v6_unhash(struct sock *sk)
{
 	write_lock_bh(&udp_hash_lock);
	if (sk_del_node_init(sk)) {
		inet_sk(sk)->num = 0;
		sock_prot_dec_use(sk->sk_prot);
	}
	write_unlock_bh(&udp_hash_lock);
}

static struct sock *udp_v6_lookup(struct in6_addr *saddr, u16 sport,
				  struct in6_addr *daddr, u16 dport, int dif)
{
	struct sock *sk, *result = NULL;
	struct hlist_node *node;
	unsigned short hnum = ntohs(dport);
	int badness = -1;

 	read_lock(&udp_hash_lock);
	sk_for_each(sk, node, &udp_hash[hnum & (UDP_HTABLE_SIZE - 1)]) {
		struct inet_sock *inet = inet_sk(sk);

		if (inet->num == hnum && sk->sk_family == PF_INET6) {
			struct ipv6_pinfo *np = inet6_sk(sk);
			int score = 0;
			if (inet->dport) {
				if (inet->dport != sport)
					continue;
				score++;
			}
			if (!ipv6_addr_any(&np->rcv_saddr)) {
				if (!ipv6_addr_equal(&np->rcv_saddr, daddr))
					continue;
				score++;
			}
			if (!ipv6_addr_any(&np->daddr)) {
				if (!ipv6_addr_equal(&np->daddr, saddr))
					continue;
				score++;
			}
			if (sk->sk_bound_dev_if) {
				if (sk->sk_bound_dev_if != dif)
					continue;
				score++;
			}
			if(score == 4) {
				result = sk;
				break;
			} else if(score > badness) {
				result = sk;
				badness = score;
			}
		}
	}
	if (result)
		sock_hold(result);
 	read_unlock(&udp_hash_lock);
	return result;
}

/*
 *
 */

static void udpv6_close(struct sock *sk, long timeout)
{
	sk_common_release(sk);
}

/*
 * This should be easy, if there is something there we
 * return it, otherwise we block.
 */

static int udpv6_recvmsg(struct kiocb *iocb, struct sock *sk, 
		  struct msghdr *msg, size_t len,
		  int noblock, int flags, int *addr_len)
{
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct inet_sock *inet = inet_sk(sk);
  	struct sk_buff *skb;
	size_t copied;
  	int err;

  	if (addr_len)
  		*addr_len=sizeof(struct sockaddr_in6);
  
	if (flags & MSG_ERRQUEUE)
		return ipv6_recv_error(sk, msg, len);

try_again:
	skb = skb_recv_datagram(sk, flags, noblock, &err);
	if (!skb)
		goto out;

 	copied = skb->len - sizeof(struct udphdr);
  	if (copied > len) {
  		copied = len;
  		msg->msg_flags |= MSG_TRUNC;
  	}

	if (skb->ip_summed==CHECKSUM_UNNECESSARY) {
		err = skb_copy_datagram_iovec(skb, sizeof(struct udphdr), msg->msg_iov,
					      copied);
	} else if (msg->msg_flags&MSG_TRUNC) {
		if (__skb_checksum_complete(skb))
			goto csum_copy_err;
		err = skb_copy_datagram_iovec(skb, sizeof(struct udphdr), msg->msg_iov,
					      copied);
	} else {
		err = skb_copy_and_csum_datagram_iovec(skb, sizeof(struct udphdr), msg->msg_iov);
		if (err == -EINVAL)
			goto csum_copy_err;
	}
	if (err)
		goto out_free;

	sock_recv_timestamp(msg, sk, skb);

	/* Copy the address. */
	if (msg->msg_name) {
		struct sockaddr_in6 *sin6;
	  
		sin6 = (struct sockaddr_in6 *) msg->msg_name;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = skb->h.uh->source;
		sin6->sin6_flowinfo = 0;
		sin6->sin6_scope_id = 0;

		if (skb->protocol == htons(ETH_P_IP))
			ipv6_addr_set(&sin6->sin6_addr, 0, 0,
				      htonl(0xffff), skb->nh.iph->saddr);
		else {
			ipv6_addr_copy(&sin6->sin6_addr, &skb->nh.ipv6h->saddr);
			if (ipv6_addr_type(&sin6->sin6_addr) & IPV6_ADDR_LINKLOCAL)
				sin6->sin6_scope_id = IP6CB(skb)->iif;
		}

	}
	if (skb->protocol == htons(ETH_P_IP)) {
		if (inet->cmsg_flags)
			ip_cmsg_recv(msg, skb);
	} else {
		if (np->rxopt.all)
			datagram_recv_ctl(sk, msg, skb);
  	}

	err = copied;
	if (flags & MSG_TRUNC)
		err = skb->len - sizeof(struct udphdr);

out_free:
	skb_free_datagram(sk, skb);
out:
	return err;

csum_copy_err:
	skb_kill_datagram(sk, skb, flags);

	if (flags & MSG_DONTWAIT) {
		UDP6_INC_STATS_USER(UDP_MIB_INERRORS);
		return -EAGAIN;
	}
	goto try_again;
}

static void udpv6_err(struct sk_buff *skb, struct inet6_skb_parm *opt,
	       int type, int code, int offset, __u32 info)
{
	struct ipv6_pinfo *np;
	struct ipv6hdr *hdr = (struct ipv6hdr*)skb->data;
	struct net_device *dev = skb->dev;
	struct in6_addr *saddr = &hdr->saddr;
	struct in6_addr *daddr = &hdr->daddr;
	struct udphdr *uh = (struct udphdr*)(skb->data+offset);
	struct sock *sk;
	int err;

	sk = udp_v6_lookup(daddr, uh->dest, saddr, uh->source, dev->ifindex);
   
	if (sk == NULL)
		return;

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

static inline int udpv6_queue_rcv_skb(struct sock * sk, struct sk_buff *skb)
{
	int rc;

	if (!xfrm6_policy_check(sk, XFRM_POLICY_IN, skb)) {
		kfree_skb(skb);
		return -1;
	}

	if (skb_checksum_complete(skb)) {
		UDP6_INC_STATS_BH(UDP_MIB_INERRORS);
		kfree_skb(skb);
		return 0;
	}

	if ((rc = sock_queue_rcv_skb(sk,skb)) < 0) {
		/* Note that an ENOMEM error is charged twice */
		if (rc == -ENOMEM)
			UDP6_INC_STATS_BH(UDP_MIB_RCVBUFERRORS);
		UDP6_INC_STATS_BH(UDP_MIB_INERRORS);
		kfree_skb(skb);
		return 0;
	}
	UDP6_INC_STATS_BH(UDP_MIB_INDATAGRAMS);
	return 0;
}

static struct sock *udp_v6_mcast_next(struct sock *sk,
				      u16 loc_port, struct in6_addr *loc_addr,
				      u16 rmt_port, struct in6_addr *rmt_addr,
				      int dif)
{
	struct hlist_node *node;
	struct sock *s = sk;
	unsigned short num = ntohs(loc_port);

	sk_for_each_from(s, node) {
		struct inet_sock *inet = inet_sk(s);

		if (inet->num == num && s->sk_family == PF_INET6) {
			struct ipv6_pinfo *np = inet6_sk(s);
			if (inet->dport) {
				if (inet->dport != rmt_port)
					continue;
			}
			if (!ipv6_addr_any(&np->daddr) &&
			    !ipv6_addr_equal(&np->daddr, rmt_addr))
				continue;

			if (s->sk_bound_dev_if && s->sk_bound_dev_if != dif)
				continue;

			if (!ipv6_addr_any(&np->rcv_saddr)) {
				if (!ipv6_addr_equal(&np->rcv_saddr, loc_addr))
					continue;
			}
			if(!inet6_mc_check(s, loc_addr, rmt_addr))
				continue;
			return s;
		}
	}
	return NULL;
}

/*
 * Note: called only from the BH handler context,
 * so we don't need to lock the hashes.
 */
static void udpv6_mcast_deliver(struct udphdr *uh,
				struct in6_addr *saddr, struct in6_addr *daddr,
				struct sk_buff *skb)
{
	struct sock *sk, *sk2;
	int dif;

	read_lock(&udp_hash_lock);
	sk = sk_head(&udp_hash[ntohs(uh->dest) & (UDP_HTABLE_SIZE - 1)]);
	dif = skb->dev->ifindex;
	sk = udp_v6_mcast_next(sk, uh->dest, daddr, uh->source, saddr, dif);
	if (!sk) {
		kfree_skb(skb);
		goto out;
	}

	sk2 = sk;
	while ((sk2 = udp_v6_mcast_next(sk_next(sk2), uh->dest, daddr,
					uh->source, saddr, dif))) {
		struct sk_buff *buff = skb_clone(skb, GFP_ATOMIC);
		if (buff)
			udpv6_queue_rcv_skb(sk2, buff);
	}
	udpv6_queue_rcv_skb(sk, skb);
out:
	read_unlock(&udp_hash_lock);
}

static int udpv6_rcv(struct sk_buff **pskb)
{
	struct sk_buff *skb = *pskb;
	struct sock *sk;
  	struct udphdr *uh;
	struct net_device *dev = skb->dev;
	struct in6_addr *saddr, *daddr;
	u32 ulen = 0;

	if (!pskb_may_pull(skb, sizeof(struct udphdr)))
		goto short_packet;

	saddr = &skb->nh.ipv6h->saddr;
	daddr = &skb->nh.ipv6h->daddr;
	uh = skb->h.uh;

	ulen = ntohs(uh->len);

	/* Check for jumbo payload */
	if (ulen == 0)
		ulen = skb->len;

	if (ulen > skb->len || ulen < sizeof(*uh))
		goto short_packet;

	if (uh->check == 0) {
		/* RFC 2460 section 8.1 says that we SHOULD log
 this error. Well, it is reasonable.
 */
		LIMIT_NETDEBUG(KERN_INFO "IPv6: udp checksum is 0\n");
		goto discard;
	}

	if (ulen < skb->len) {
		if (pskb_trim_rcsum(skb, ulen))
			goto discard;
		saddr = &skb->nh.ipv6h->saddr;
		daddr = &skb->nh.ipv6h->daddr;
		uh = skb->h.uh;
	}

	if (skb->ip_summed == CHECKSUM_COMPLETE &&
	    !csum_ipv6_magic(saddr, daddr, ulen, IPPROTO_UDP, skb->csum))
		skb->ip_summed = CHECKSUM_UNNECESSARY;

	if (skb->ip_summed != CHECKSUM_UNNECESSARY)
		skb->csum = ~csum_ipv6_magic(saddr, daddr, ulen, IPPROTO_UDP, 0);

	/* 
 * Multicast receive code 
 */
	if (ipv6_addr_is_multicast(daddr)) {
		udpv6_mcast_deliver(uh, saddr, daddr, skb);
		return 0;
	}

	/* Unicast */

	/* 
 * check socket cache ... must talk to Alan about his plans
 * for sock caches... i'll skip this for now.
 */
	sk = udp_v6_lookup(saddr, uh->source, daddr, uh->dest, dev->ifindex);

	if (sk == NULL) {
		if (!xfrm6_policy_check(NULL, XFRM_POLICY_IN, skb))
			goto discard;

		if (skb_checksum_complete(skb))
			goto discard;
		UDP6_INC_STATS_BH(UDP_MIB_NOPORTS);

		icmpv6_send(skb, ICMPV6_DEST_UNREACH, ICMPV6_PORT_UNREACH, 0, dev);

		kfree_skb(skb);
		return(0);
	}
	
	/* deliver */
	
	udpv6_queue_rcv_skb(sk, skb);
	sock_put(sk);
	return(0);

short_packet:	
	if (net_ratelimit())
		printk(KERN_DEBUG "UDP: short packet: %d/%u\n", ulen, skb->len);

discard:
	UDP6_INC_STATS_BH(UDP_MIB_INERRORS);
	kfree_skb(skb);
	return(0);	
}
/*
 * Throw away all pending data and cancel the corking. Socket is locked.
 */
static void udp_v6_flush_pending_frames(struct sock *sk)
{
	struct udp_sock *up = udp_sk(sk);

	if (up->pending) {
		up->len = 0;
		up->pending = 0;
		ip6_flush_pending_frames(sk);
        }
}

/*
 * Sending
 */

static int udp_v6_push_pending_frames(struct sock *sk, struct udp_sock *up)
{
	struct sk_buff *skb;
	struct udphdr *uh;
	struct inet_sock *inet = inet_sk(sk);
	struct flowi *fl = &inet->cork.fl;
	int err = 0;

	/* Grab the skbuff where UDP header space exists. */
	if ((skb = skb_peek(&sk->sk_write_queue)) == NULL)
		goto out;

	/*
 * Create a UDP header
 */
	uh = skb->h.uh;
	uh->source = fl->fl_ip_sport;
	uh->dest = fl->fl_ip_dport;
	uh->len = htons(up->len);
	uh->check = 0;

	if (sk->sk_no_check == UDP_CSUM_NOXMIT) {
		skb->ip_summed = CHECKSUM_NONE;
		goto send;
	}

	if (skb_queue_len(&sk->sk_write_queue) == 1) {
		skb->csum = csum_partial((char *)uh,
				sizeof(struct udphdr), skb->csum);
		uh->check = csum_ipv6_magic(&fl->fl6_src,
					    &fl->fl6_dst,
					    up->len, fl->proto, skb->csum);
	} else {
		u32 tmp_csum = 0;

		skb_queue_walk(&sk->sk_write_queue, skb) {
			tmp_csum = csum_add(tmp_csum, skb->csum);
		}
		tmp_csum = csum_partial((char *)uh,
				sizeof(struct udphdr), tmp_csum);
                tmp_csum = csum_ipv6_magic(&fl->fl6_src,
					   &fl->fl6_dst,
					   up->len, fl->proto, tmp_csum);
                uh->check = tmp_csum;

	}
	if (uh->check == 0)
		uh->check = -1;

send:
	err = ip6_push_pending_frames(sk);
out:
	up->len = 0;
	up->pending = 0;
	return err;
}

static int udpv6_sendmsg(struct kiocb *iocb, struct sock *sk, 
		  struct msghdr *msg, size_t len)
{
	struct ipv6_txoptions opt_space;
	struct udp_sock *up = udp_sk(sk);
	struct inet_sock *inet = inet_sk(sk);
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) msg->msg_name;
	struct in6_addr *daddr, *final_p = NULL, final;
	struct ipv6_txoptions *opt = NULL;
	struct ip6_flowlabel *flowlabel = NULL;
	struct flowi fl;
	struct dst_entry *dst;
	int addr_len = msg->msg_namelen;
	int ulen = len;
	int hlimit = -1;
	int tclass = -1;
	int corkreq = up->corkflag || msg->msg_flags&MSG_MORE;
	int err;
	int connected = 0;

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
		daddr = &np->daddr;
	} else 
		daddr = NULL;

	if (daddr) {
		if (ipv6_addr_type(daddr) == IPV6_ADDR_MAPPED) {
			struct sockaddr_in sin;
			sin.sin_family = AF_INET;
			sin.sin_port = sin6 ? sin6->sin6_port : inet->dport;
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
 better check is made in ip6_build_xmit
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

	memset(&fl, 0, sizeof(fl));

	if (sin6) {
		if (sin6->sin6_port == 0)
			return -EINVAL;

		fl.fl_ip_dport = sin6->sin6_port;
		daddr = &sin6->sin6_addr;

		if (np->sndflow) {
			fl.fl6_flowlabel = sin6->sin6_flowinfo&IPV6_FLOWINFO_MASK;
			if (fl.fl6_flowlabel&IPV6_FLOWLABEL_MASK) {
				flowlabel = fl6_sock_lookup(sk, fl.fl6_flowlabel);
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
		    ipv6_addr_equal(daddr, &np->daddr))
			daddr = &np->daddr;

		if (addr_len >= sizeof(struct sockaddr_in6) &&
		    sin6->sin6_scope_id &&
		    ipv6_addr_type(daddr)&IPV6_ADDR_LINKLOCAL)
			fl.oif = sin6->sin6_scope_id;
	} else {
		if (sk->sk_state != TCP_ESTABLISHED)
			return -EDESTADDRREQ;

		fl.fl_ip_dport = inet->dport;
		daddr = &np->daddr;
		fl.fl6_flowlabel = np->flow_label;
		connected = 1;
	}

	if (!fl.oif)
		fl.oif = sk->sk_bound_dev_if;

	if (msg->msg_controllen) {
		opt = &opt_space;
		memset(opt, 0, sizeof(struct ipv6_txoptions));
		opt->tot_len = sizeof(*opt);

		err = datagram_send_ctl(msg, &fl, opt, &hlimit, &tclass);
		if (err < 0) {
			fl6_sock_release(flowlabel);
			return err;
		}
		if ((fl.fl6_flowlabel&IPV6_FLOWLABEL_MASK) && !flowlabel) {
			flowlabel = fl6_sock_lookup(sk, fl.fl6_flowlabel);
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

	fl.proto = IPPROTO_UDP;
	ipv6_addr_copy(&fl.fl6_dst, daddr);
	if (ipv6_addr_any(&fl.fl6_src) && !ipv6_addr_any(&np->saddr))
		ipv6_addr_copy(&fl.fl6_src, &np->saddr);
	fl.fl_ip_sport = inet->sport;
	
	/* merge ip6_build_xmit from ip6_output */
	if (opt && opt->srcrt) {
		struct rt0_hdr *rt0 = (struct rt0_hdr *) opt->srcrt;
		ipv6_addr_copy(&final, &fl.fl6_dst);
		ipv6_addr_copy(&fl.fl6_dst, rt0->addr);
		final_p = &final;
		connected = 0;
	}

	if (!fl.oif && ipv6_addr_is_multicast(&fl.fl6_dst)) {
		fl.oif = np->mcast_oif;
		connected = 0;
	}

	security_sk_classify_flow(sk, &fl);

	err = ip6_sk_dst_lookup(sk, &dst, &fl);
	if (err)
		goto out;
	if (final_p)
		ipv6_addr_copy(&fl.fl6_dst, final_p);

	if ((err = xfrm_lookup(&dst, &fl, sk, 0)) < 0)
		goto out;

	if (hlimit < 0) {
		if (ipv6_addr_is_multicast(&fl.fl6_dst))
			hlimit = np->mcast_hops;
		else
			hlimit = np->hop_limit;
		if (hlimit < 0)
			hlimit = dst_metric(dst, RTAX_HOPLIMIT);
		if (hlimit < 0)
			hlimit = ipv6_get_hoplimit(dst->dev);
	}

	if (tclass < 0) {
		tclass = np->tclass;
		if (tclass < 0)
			tclass = 0;
	}

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
	up->len += ulen;
	err = ip6_append_data(sk, ip_generic_getfrag, msg->msg_iov, ulen,
		sizeof(struct udphdr), hlimit, tclass, opt, &fl,
		(struct rt6_info*)dst,
		corkreq ? msg->msg_flags|MSG_MORE : msg->msg_flags);
	if (err)
		udp_v6_flush_pending_frames(sk);
	else if (!corkreq)
		err = udp_v6_push_pending_frames(sk, up);

	if (dst) {
		if (connected) {
			ip6_dst_store(sk, dst,
				      ipv6_addr_equal(&fl.fl6_dst, &np->daddr) ?
				      &np->daddr : NULL,
#ifdef CONFIG_IPV6_SUBTREES
				      ipv6_addr_equal(&fl.fl6_src, &np->saddr) ?
				      &np->saddr :
#endif
				      NULL);
		} else {
			dst_release(dst);
		}
	}

	if (err > 0)
		err = np->recverr ? net_xmit_errno(err) : 0;
	release_sock(sk);
out:
	fl6_sock_release(flowlabel);
	if (!err) {
		UDP6_INC_STATS_USER(UDP_MIB_OUTDATAGRAMS);
		return len;
	}
	/*
 * ENOBUFS = no kernel mem, SOCK_NOSPACE = no sndbuf space. Reporting
 * ENOBUFS might not be good (it's not tunable per se), but otherwise
 * we don't have a good statistic (IpOutDiscards but it can be too many
 * things). We could add another new stat but at least for now that
 * seems like overkill.
 */
	if (err == -ENOBUFS || test_bit(SOCK_NOSPACE, &sk->sk_socket->flags)) {
		UDP6_INC_STATS_USER(UDP_MIB_SNDBUFERRORS);
	}
	return err;

do_confirm:
	dst_confirm(dst);
	if (!(msg->msg_flags&MSG_PROBE) || len)
		goto back_from_confirm;
	err = 0;
	goto out;
}

static int udpv6_destroy_sock(struct sock *sk)
{
	lock_sock(sk);
	udp_v6_flush_pending_frames(sk);
	release_sock(sk);

	inet6_destroy_sock(sk);

	return 0;
}

/*
 * Socket option code for UDP
 */
static int do_udpv6_setsockopt(struct sock *sk, int level, int optname,
			  char __user *optval, int optlen)
{
	struct udp_sock *up = udp_sk(sk);
	int val;
	int err = 0;

	if(optlen<sizeof(int))
		return -EINVAL;

	if (get_user(val, (int __user *)optval))
		return -EFAULT;

	switch(optname) {
	case UDP_CORK:
		if (val != 0) {
			up->corkflag = 1;
		} else {
			up->corkflag = 0;
			lock_sock(sk);
			udp_v6_push_pending_frames(sk, up);
			release_sock(sk);
		}
		break;
		
	case UDP_ENCAP:
		switch (val) {
		case 0:
			up->encap_type = val;
			break;
		default:
			err = -ENOPROTOOPT;
			break;
		}
		break;

	default:
		err = -ENOPROTOOPT;
		break;
	};

	return err;
}

static int udpv6_setsockopt(struct sock *sk, int level, int optname,
			  char __user *optval, int optlen)
{
	if (level != SOL_UDP)
		return ipv6_setsockopt(sk, level, optname, optval, optlen);
	return do_udpv6_setsockopt(sk, level, optname, optval, optlen);
}

#ifdef CONFIG_COMPAT
static int compat_udpv6_setsockopt(struct sock *sk, int level, int optname,
				   char __user *optval, int optlen)
{
	if (level != SOL_UDP)
		return compat_ipv6_setsockopt(sk, level, optname,
					      optval, optlen);
	return do_udpv6_setsockopt(sk, level, optname, optval, optlen);
}
#endif

static int do_udpv6_getsockopt(struct sock *sk, int level, int optname,
			  char __user *optval, int __user *optlen)
{
	struct udp_sock *up = udp_sk(sk);
	int val, len;

	if(get_user(len,optlen))
		return -EFAULT;

	len = min_t(unsigned int, len, sizeof(int));
	
	if(len < 0)
		return -EINVAL;

	switch(optname) {
	case UDP_CORK:
		val = up->corkflag;
		break;

	case UDP_ENCAP:
		val = up->encap_type;
		break;

	default:
		return -ENOPROTOOPT;
	};

  	if(put_user(len, optlen))
  		return -EFAULT;
	if(copy_to_user(optval, &val,len))
		return -EFAULT;
  	return 0;
}

static int udpv6_getsockopt(struct sock *sk, int level, int optname,
			  char __user *optval, int __user *optlen)
{
	if (level != SOL_UDP)
		return ipv6_getsockopt(sk, level, optname, optval, optlen);
	return do_udpv6_getsockopt(sk, level, optname, optval, optlen);
}

#ifdef CONFIG_COMPAT
static int compat_udpv6_getsockopt(struct sock *sk, int level, int optname,
				   char __user *optval, int __user *optlen)
{
	if (level != SOL_UDP)
		return compat_ipv6_getsockopt(sk, level, optname,
					      optval, optlen);
	return do_udpv6_getsockopt(sk, level, optname, optval, optlen);
}
#endif

static struct inet6_protocol udpv6_protocol = {
	.handler	=	udpv6_rcv,
	.err_handler	=	udpv6_err,
	.flags		=	INET6_PROTO_NOPOLICY|INET6_PROTO_FINAL,
};

/* ------------------------------------------------------------------------ */
#ifdef CONFIG_PROC_FS

static void udp6_sock_seq_show(struct seq_file *seq, struct sock *sp, int bucket)
{
	struct inet_sock *inet = inet_sk(sp);
	struct ipv6_pinfo *np = inet6_sk(sp);
	struct in6_addr *dest, *src;
	__u16 destp, srcp;

	dest  = &np->daddr;
	src   = &np->rcv_saddr;
	destp = ntohs(inet->dport);
	srcp  = ntohs(inet->sport);
	seq_printf(seq,
		   "%4d: %08X%08X%08X%08X:%04X %08X%08X%08X%08X:%04X "
		   "%02X %08X:%08X %02X:%08lX %08X %5d %8d %lu %d %p\n",
		   bucket,
		   src->s6_addr32[0], src->s6_addr32[1],
		   src->s6_addr32[2], src->s6_addr32[3], srcp,
		   dest->s6_addr32[0], dest->s6_addr32[1],
		   dest->s6_addr32[2], dest->s6_addr32[3], destp,
		   sp->sk_state, 
		   atomic_read(&sp->sk_wmem_alloc),
		   atomic_read(&sp->sk_rmem_alloc),
		   0, 0L, 0,
		   sock_i_uid(sp), 0,
		   sock_i_ino(sp),
		   atomic_read(&sp->sk_refcnt), sp);
}

static int udp6_seq_show(struct seq_file *seq, void *v)
{
	if (v == SEQ_START_TOKEN)
		seq_printf(seq,
			   " sl "
			   "local_address "
			   "remote_address "
			   "st tx_queue rx_queue tr tm->when retrnsmt"
			   " uid timeout inode\n");
	else
		udp6_sock_seq_show(seq, v, ((struct udp_iter_state *)seq->private)->bucket);
	return 0;
}

static struct file_operations udp6_seq_fops;
static struct udp_seq_afinfo udp6_seq_afinfo = {
	.owner		= THIS_MODULE,
	.name		= "udp6",
	.family		= AF_INET6,
	.seq_show	= udp6_seq_show,
	.seq_fops	= &udp6_seq_fops,
};

int __init udp6_proc_init(void)
{
	return udp_proc_register(&udp6_seq_afinfo);
}

void udp6_proc_exit(void) {
	udp_proc_unregister(&udp6_seq_afinfo);
}
#endif /* CONFIG_PROC_FS */

/* ------------------------------------------------------------------------ */

struct proto udpv6_prot = {
	.name		   = "UDPv6",
	.owner		   = THIS_MODULE,
	.close		   = udpv6_close,
	.connect	   = ip6_datagram_connect,
	.disconnect	   = udp_disconnect,
	.ioctl		   = udp_ioctl,
	.destroy	   = udpv6_destroy_sock,
	.setsockopt	   = udpv6_setsockopt,
	.getsockopt	   = udpv6_getsockopt,
	.sendmsg	   = udpv6_sendmsg,
	.recvmsg	   = udpv6_recvmsg,
	.backlog_rcv	   = udpv6_queue_rcv_skb,
	.hash		   = udp_v6_hash,
	.unhash		   = udp_v6_unhash,
	.get_port	   = udp_v6_get_port,
	.obj_size	   = sizeof(struct udp6_sock),
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_udpv6_setsockopt,
	.compat_getsockopt = compat_udpv6_getsockopt,
#endif
};

static struct inet_protosw udpv6_protosw = {
	.type =      SOCK_DGRAM,
	.protocol =  IPPROTO_UDP,
	.prot = &udpv6_prot,
	.ops = &inet6_dgram_ops,
	.capability =-1,
	.no_check =  UDP_CSUM_DEFAULT,
	.flags =     INET_PROTOSW_PERMANENT,
};


void __init udpv6_init(void)
{
	if (inet6_add_protocol(&udpv6_protocol, IPPROTO_UDP) < 0)
		printk(KERN_ERR "udpv6_init: Could not register protocol\n");
	inet6_register_protosw(&udpv6_protosw);
}