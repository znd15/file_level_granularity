

/*
 * INET An implementation of the TCP/IP protocol suite for the LINUX
 * operating system. INET is implemented using the BSD Socket
 * interface as the means of communication with the user level.
 *
 * RAW - implementation of IP "raw" sockets.
 *
 * Authors: Ross Biro
 * Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 * Fixes:
 * Alan Cox : verify_area() fixed up
 * Alan Cox : ICMP error handling
 * Alan Cox : EMSGSIZE if you send too big a packet
 * Alan Cox : Now uses generic datagrams and shared
 * skbuff library. No more peek crashes,
 * no more backlogs
 * Alan Cox : Checks sk->broadcast.
 * Alan Cox : Uses skb_free_datagram/skb_copy_datagram
 * Alan Cox : Raw passes ip options too
 * Alan Cox : Setsocketopt added
 * Alan Cox : Fixed error return for broadcasts
 * Alan Cox : Removed wake_up calls
 * Alan Cox : Use ttl/tos
 * Alan Cox : Cleaned up old debugging
 * Alan Cox : Use new kernel side addresses
 * Arnt Gulbrandsen : Fixed MSG_DONTROUTE in raw sockets.
 * Alan Cox : BSD style RAW socket demultiplexing.
 * Alan Cox : Beginnings of mrouted support.
 * Alan Cox : Added IP_HDRINCL option.
 * Alan Cox : Skip broadcast check if BSDism set.
 * David S. Miller : New socket lookup architecture.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/types.h>
#include <linux/atomic.h>
#include <asm/byteorder.h>
#include <asm/current.h>
#include <asm/uaccess.h>
#include <asm/ioctls.h>
#include <linux/stddef.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/aio.h>
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/spinlock.h>
#include <linux/sockios.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/mroute.h>
#include <linux/netdevice.h>
#include <linux/in_route.h>
#include <linux/route.h>
#include <linux/skbuff.h>
#include <net/net_namespace.h>
#include <net/dst.h>
#include <net/sock.h>
#include <linux/ip.h>
#include <linux/net.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/udp.h>
#include <net/raw.h>
#include <net/snmp.h>
#include <net/tcp_states.h>
#include <net/inet_common.h>
#include <net/checksum.h>
#include <net/xfrm.h>
#include <linux/rtnetlink.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/compat.h>

static struct raw_hashinfo raw_v4_hashinfo = {
	.lock = __RW_LOCK_UNLOCKED(raw_v4_hashinfo.lock),
};

void raw_hash_sk(struct sock *sk)
{
	struct raw_hashinfo *h = sk->sk_prot->h.raw_hash;
	struct hlist_head *head;

	head = &h->ht[inet_sk(sk)->inet_num & (RAW_HTABLE_SIZE - 1)];

	write_lock_bh(&h->lock);
	sk_add_node(sk, head);
	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, 1);
	write_unlock_bh(&h->lock);
}
EXPORT_SYMBOL_GPL(raw_hash_sk);

void raw_unhash_sk(struct sock *sk)
{
	struct raw_hashinfo *h = sk->sk_prot->h.raw_hash;

	write_lock_bh(&h->lock);
	if (sk_del_node_init(sk))
		sock_prot_inuse_add(sock_net(sk), sk->sk_prot, -1);
	write_unlock_bh(&h->lock);
}
EXPORT_SYMBOL_GPL(raw_unhash_sk);

static struct sock *__raw_v4_lookup(struct net *net, struct sock *sk,
		unsigned short num, __be32 raddr, __be32 laddr, int dif)
{
	sk_for_each_from(sk) {
		struct inet_sock *inet = inet_sk(sk);

		if (net_eq(sock_net(sk), net) && inet->inet_num == num	&&
		    !(inet->inet_daddr && inet->inet_daddr != raddr) &&
		    !(inet->inet_rcv_saddr && inet->inet_rcv_saddr != laddr) &&
		    !(sk->sk_bound_dev_if && sk->sk_bound_dev_if != dif))
			goto found; /* gotcha */
	}
	sk = NULL;
found:
	return sk;
}

/*
 * 0 - deliver
 * 1 - block
 */
static int icmp_filter(const struct sock *sk, const struct sk_buff *skb)
{
	struct icmphdr _hdr;
	const struct icmphdr *hdr;

	hdr = skb_header_pointer(skb, skb_transport_offset(skb),
				 sizeof(_hdr), &_hdr);
	if (!hdr)
		return 1;

	if (hdr->type < 32) {
		__u32 data = raw_sk(sk)->filter.data;

		return ((1U << hdr->type) & data) != 0;
	}

	/* Do not block unknown ICMP types */
	return 0;
}

/* IP input processing comes here for RAW socket delivery.
 * Caller owns SKB, so we must make clones.
 *
 * RFC 1122: SHOULD pass TOS value up to the transport layer.
 * -> It does. And not only TOS, but all IP header.
 */
static int raw_v4_input(struct sk_buff *skb, const struct iphdr *iph, int hash)
{
	struct sock *sk;
	struct hlist_head *head;
	int delivered = 0;
	struct net *net;

	read_lock(&raw_v4_hashinfo.lock);
	head = &raw_v4_hashinfo.ht[hash];
	if (hlist_empty(head))
		goto out;

	net = dev_net(skb->dev);
	sk = __raw_v4_lookup(net, __sk_head(head), iph->protocol,
			     iph->saddr, iph->daddr,
			     skb->dev->ifindex);

	while (sk) {
		delivered = 1;
		if (iph->protocol != IPPROTO_ICMP || !icmp_filter(sk, skb)) {
			struct sk_buff *clone = skb_clone(skb, GFP_ATOMIC);

			/* Not releasing hash table! */
			if (clone)
				raw_rcv(sk, clone);
		}
		sk = __raw_v4_lookup(net, sk_next(sk), iph->protocol,
				     iph->saddr, iph->daddr,
				     skb->dev->ifindex);
	}
out:
	read_unlock(&raw_v4_hashinfo.lock);
	return delivered;
}

int raw_local_deliver(struct sk_buff *skb, int protocol)
{
	int hash;
	struct sock *raw_sk;

	hash = protocol & (RAW_HTABLE_SIZE - 1);
	raw_sk = sk_head(&raw_v4_hashinfo.ht[hash]);

	/* If there maybe a raw socket we must check - if not we
 * don't care less
 */
	if (raw_sk && !raw_v4_input(skb, ip_hdr(skb), hash))
		raw_sk = NULL;

	return raw_sk != NULL;

}

static void raw_err(struct sock *sk, struct sk_buff *skb, u32 info)
{
	struct inet_sock *inet = inet_sk(sk);
	const int type = icmp_hdr(skb)->type;
	const int code = icmp_hdr(skb)->code;
	int err = 0;
	int harderr = 0;

	if (type == ICMP_DEST_UNREACH && code == ICMP_FRAG_NEEDED)
		ipv4_sk_update_pmtu(skb, sk, info);
	else if (type == ICMP_REDIRECT) {
		ipv4_sk_redirect(skb, sk);
		return;
	}

	/* Report error on raw socket, if:
 1. User requested ip_recverr.
 2. Socket is connected (otherwise the error indication
 is useless without ip_recverr and error is hard.
 */
	if (!inet->recverr && sk->sk_state != TCP_ESTABLISHED)
		return;

	switch (type) {
	default:
	case ICMP_TIME_EXCEEDED:
		err = EHOSTUNREACH;
		break;
	case ICMP_SOURCE_QUENCH:
		return;
	case ICMP_PARAMETERPROB:
		err = EPROTO;
		harderr = 1;
		break;
	case ICMP_DEST_UNREACH:
		err = EHOSTUNREACH;
		if (code > NR_ICMP_UNREACH)
			break;
		err = icmp_err_convert[code].errno;
		harderr = icmp_err_convert[code].fatal;
		if (code == ICMP_FRAG_NEEDED) {
			harderr = inet->pmtudisc != IP_PMTUDISC_DONT;
			err = EMSGSIZE;
		}
	}

	if (inet->recverr) {
		const struct iphdr *iph = (const struct iphdr *)skb->data;
		u8 *payload = skb->data + (iph->ihl << 2);

		if (inet->hdrincl)
			payload = skb->data;
		ip_icmp_error(sk, skb, err, 0, info, payload);
	}

	if (inet->recverr || harderr) {
		sk->sk_err = err;
		sk->sk_error_report(sk);
	}
}

void raw_icmp_error(struct sk_buff *skb, int protocol, u32 info)
{
	int hash;
	struct sock *raw_sk;
	const struct iphdr *iph;
	struct net *net;

	hash = protocol & (RAW_HTABLE_SIZE - 1);

	read_lock(&raw_v4_hashinfo.lock);
	raw_sk = sk_head(&raw_v4_hashinfo.ht[hash]);
	if (raw_sk != NULL) {
		iph = (const struct iphdr *)skb->data;
		net = dev_net(skb->dev);

		while ((raw_sk = __raw_v4_lookup(net, raw_sk, protocol,
						iph->daddr, iph->saddr,
						skb->dev->ifindex)) != NULL) {
			raw_err(raw_sk, skb, info);
			raw_sk = sk_next(raw_sk);
			iph = (const struct iphdr *)skb->data;
		}
	}
	read_unlock(&raw_v4_hashinfo.lock);
}

static int raw_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	/* Charge it to the socket. */

	ipv4_pktinfo_prepare(sk, skb);
	if (sock_queue_rcv_skb(sk, skb) < 0) {
		kfree_skb(skb);
		return NET_RX_DROP;
	}

	return NET_RX_SUCCESS;
}

int raw_rcv(struct sock *sk, struct sk_buff *skb)
{
	if (!xfrm4_policy_check(sk, XFRM_POLICY_IN, skb)) {
		atomic_inc(&sk->sk_drops);
		kfree_skb(skb);
		return NET_RX_DROP;
	}
	nf_reset(skb);

	skb_push(skb, skb->data - skb_network_header(skb));

	raw_rcv_skb(sk, skb);
	return 0;
}

static int raw_send_hdrinc(struct sock *sk, struct flowi4 *fl4,
			   void *from, size_t length,
			   struct rtable **rtp,
			   unsigned int flags)
{
	struct inet_sock *inet = inet_sk(sk);
	struct net *net = sock_net(sk);
	struct iphdr *iph;
	struct sk_buff *skb;
	unsigned int iphlen;
	int err;
	struct rtable *rt = *rtp;
	int hlen, tlen;

	if (length > rt->dst.dev->mtu) {
		ip_local_error(sk, EMSGSIZE, fl4->daddr, inet->inet_dport,
			       rt->dst.dev->mtu);
		return -EMSGSIZE;
	}
	if (flags&MSG_PROBE)
		goto out;

	hlen = LL_RESERVED_SPACE(rt->dst.dev);
	tlen = rt->dst.dev->needed_tailroom;
	skb = sock_alloc_send_skb(sk,
				  length + hlen + tlen + 15,
				  flags & MSG_DONTWAIT, &err);
	if (skb == NULL)
		goto error;
	skb_reserve(skb, hlen);

	skb->priority = sk->sk_priority;
	skb->mark = sk->sk_mark;
	skb_dst_set(skb, &rt->dst);
	*rtp = NULL;

	skb_reset_network_header(skb);
	iph = ip_hdr(skb);
	skb_put(skb, length);

	skb->ip_summed = CHECKSUM_NONE;

	skb->transport_header = skb->network_header;
	err = -EFAULT;
	if (memcpy_fromiovecend((void *)iph, from, 0, length))
		goto error_free;

	iphlen = iph->ihl * 4;

	/*
 * We don't want to modify the ip header, but we do need to
 * be sure that it won't cause problems later along the network
 * stack. Specifically we want to make sure that iph->ihl is a
 * sane value. If ihl points beyond the length of the buffer passed
 * in, reject the frame as invalid
 */
	err = -EINVAL;
	if (iphlen > length)
		goto error_free;

	if (iphlen >= sizeof(*iph)) {
		if (!iph->saddr)
			iph->saddr = fl4->saddr;
		iph->check   = 0;
		iph->tot_len = htons(length);
		if (!iph->id)
			ip_select_ident(skb, &rt->dst, NULL);

		iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
	}
	if (iph->protocol == IPPROTO_ICMP)
		icmp_out_count(net, ((struct icmphdr *)
			skb_transport_header(skb))->type);

	err = NF_HOOK(NFPROTO_IPV4, NF_INET_LOCAL_OUT, skb, NULL,
		      rt->dst.dev, dst_output);
	if (err > 0)
		err = net_xmit_errno(err);
	if (err)
		goto error;
out:
	return 0;

error_free:
	kfree_skb(skb);
error:
	IP_INC_STATS(net, IPSTATS_MIB_OUTDISCARDS);
	if (err == -ENOBUFS && !inet->recverr)
		err = 0;
	return err;
}

static int raw_probe_proto_opt(struct flowi4 *fl4, struct msghdr *msg)
{
	struct iovec *iov;
	u8 __user *type = NULL;
	u8 __user *code = NULL;
	int probed = 0;
	unsigned int i;

	if (!msg->msg_iov)
		return 0;

	for (i = 0; i < msg->msg_iovlen; i++) {
		iov = &msg->msg_iov[i];
		if (!iov)
			continue;

		switch (fl4->flowi4_proto) {
		case IPPROTO_ICMP:
			/* check if one-byte field is readable or not. */
			if (iov->iov_base && iov->iov_len < 1)
				break;

			if (!type) {
				type = iov->iov_base;
				/* check if code field is readable or not. */
				if (iov->iov_len > 1)
					code = type + 1;
			} else if (!code)
				code = iov->iov_base;

			if (type && code) {
				if (get_user(fl4->fl4_icmp_type, type) ||
				    get_user(fl4->fl4_icmp_code, code))
					return -EFAULT;
				probed = 1;
			}
			break;
		default:
			probed = 1;
			break;
		}
		if (probed)
			break;
	}
	return 0;
}

static int raw_sendmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
		       size_t len)
{
	struct inet_sock *inet = inet_sk(sk);
	struct ipcm_cookie ipc;
	struct rtable *rt = NULL;
	struct flowi4 fl4;
	int free = 0;
	__be32 daddr;
	__be32 saddr;
	u8  tos;
	int err;
	struct ip_options_data opt_copy;

	err = -EMSGSIZE;
	if (len > 0xFFFF)
		goto out;

	/*
 * Check the flags.
 */

	err = -EOPNOTSUPP;
	if (msg->msg_flags & MSG_OOB)	/* Mirror BSD error message */
		goto out;               /* compatibility */

	/*
 * Get and verify the address.
 */

	if (msg->msg_namelen) {
		struct sockaddr_in *usin = (struct sockaddr_in *)msg->msg_name;
		err = -EINVAL;
		if (msg->msg_namelen < sizeof(*usin))
			goto out;
		if (usin->sin_family != AF_INET) {
			pr_info_once("%s: %s forgot to set AF_INET. Fix it!\n",
				     __func__, current->comm);
			err = -EAFNOSUPPORT;
			if (usin->sin_family)
				goto out;
		}
		daddr = usin->sin_addr.s_addr;
		/* ANK: I did not forget to get protocol from port field.
 * I just do not know, who uses this weirdness.
 * IP_HDRINCL is much more convenient.
 */
	} else {
		err = -EDESTADDRREQ;
		if (sk->sk_state != TCP_ESTABLISHED)
			goto out;
		daddr = inet->inet_daddr;
	}

	ipc.addr = inet->inet_saddr;
	ipc.opt = NULL;
	ipc.tx_flags = 0;
	ipc.ttl = 0;
	ipc.tos = -1;
	ipc.oif = sk->sk_bound_dev_if;

	if (msg->msg_controllen) {
		err = ip_cmsg_send(sock_net(sk), msg, &ipc);
		if (err)
			goto out;
		if (ipc.opt)
			free = 1;
	}

	saddr = ipc.addr;
	ipc.addr = daddr;

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

	if (ipc.opt) {
		err = -EINVAL;
		/* Linux does not mangle headers on raw sockets,
 * so that IP options + IP_HDRINCL is non-sense.
 */
		if (inet->hdrincl)
			goto done;
		if (ipc.opt->opt.srr) {
			if (!daddr)
				goto done;
			daddr = ipc.opt->opt.faddr;
		}
	}
	tos = get_rtconn_flags(&ipc, sk);
	if (msg->msg_flags & MSG_DONTROUTE)
		tos |= RTO_ONLINK;

	if (ipv4_is_multicast(daddr)) {
		if (!ipc.oif)
			ipc.oif = inet->mc_index;
		if (!saddr)
			saddr = inet->mc_addr;
	} else if (!ipc.oif)
		ipc.oif = inet->uc_index;

	flowi4_init_output(&fl4, ipc.oif, sk->sk_mark, tos,
			   RT_SCOPE_UNIVERSE,
			   inet->hdrincl ? IPPROTO_RAW : sk->sk_protocol,
			   inet_sk_flowi_flags(sk) | FLOWI_FLAG_CAN_SLEEP |
			    (inet->hdrincl ? FLOWI_FLAG_KNOWN_NH : 0),
			   daddr, saddr, 0, 0);

	if (!inet->hdrincl) {
		err = raw_probe_proto_opt(&fl4, msg);
		if (err)
			goto done;
	}

	security_sk_classify_flow(sk, flowi4_to_flowi(&fl4));
	rt = ip_route_output_flow(sock_net(sk), &fl4, sk);
	if (IS_ERR(rt)) {
		err = PTR_ERR(rt);
		rt = NULL;
		goto done;
	}

	err = -EACCES;
	if (rt->rt_flags & RTCF_BROADCAST && !sock_flag(sk, SOCK_BROADCAST))
		goto done;

	if (msg->msg_flags & MSG_CONFIRM)
		goto do_confirm;
back_from_confirm:

	if (inet->hdrincl)
		err = raw_send_hdrinc(sk, &fl4, msg->msg_iov, len,
				      &rt, msg->msg_flags);

	 else {
		if (!ipc.addr)
			ipc.addr = fl4.daddr;
		lock_sock(sk);
		err = ip_append_data(sk, &fl4, ip_generic_getfrag,
				     msg->msg_iov, len, 0,
				     &ipc, &rt, msg->msg_flags);
		if (err)
			ip_flush_pending_frames(sk);
		else if (!(msg->msg_flags & MSG_MORE)) {
			err = ip_push_pending_frames(sk, &fl4);
			if (err == -ENOBUFS && !inet->recverr)
				err = 0;
		}
		release_sock(sk);
	}
done:
	if (free)
		kfree(ipc.opt);
	ip_rt_put(rt);

out:
	if (err < 0)
		return err;
	return len;

do_confirm:
	dst_confirm(&rt->dst);
	if (!(msg->msg_flags & MSG_PROBE) || len)
		goto back_from_confirm;
	err = 0;
	goto done;
}

static void raw_close(struct sock *sk, long timeout)
{
	/*
 * Raw sockets may have direct kernel references. Kill them.
 */
	ip_ra_control(sk, 0, NULL);

	sk_common_release(sk);
}

static void raw_destroy(struct sock *sk)
{
	lock_sock(sk);
	ip_flush_pending_frames(sk);
	release_sock(sk);
}

/* This gets rid of all the nasties in af_inet. -DaveM */
static int raw_bind(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	struct inet_sock *inet = inet_sk(sk);
	struct sockaddr_in *addr = (struct sockaddr_in *) uaddr;
	int ret = -EINVAL;
	int chk_addr_ret;

	if (sk->sk_state != TCP_CLOSE || addr_len < sizeof(struct sockaddr_in))
		goto out;
	chk_addr_ret = inet_addr_type(sock_net(sk), addr->sin_addr.s_addr);
	ret = -EADDRNOTAVAIL;
	if (addr->sin_addr.s_addr && chk_addr_ret != RTN_LOCAL &&
	    chk_addr_ret != RTN_MULTICAST && chk_addr_ret != RTN_BROADCAST)
		goto out;
	inet->inet_rcv_saddr = inet->inet_saddr = addr->sin_addr.s_addr;
	if (chk_addr_ret == RTN_MULTICAST || chk_addr_ret == RTN_BROADCAST)
		inet->inet_saddr = 0;  /* Use device */
	sk_dst_reset(sk);
	ret = 0;
out:	return ret;
}

/*
 * This should be easy, if there is something there
 * we return it, otherwise we block.
 */

static int raw_recvmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
		       size_t len, int noblock, int flags, int *addr_len)
{
	struct inet_sock *inet = inet_sk(sk);
	size_t copied = 0;
	int err = -EOPNOTSUPP;
	struct sockaddr_in *sin = (struct sockaddr_in *)msg->msg_name;
	struct sk_buff *skb;

	if (flags & MSG_OOB)
		goto out;

	if (addr_len)
		*addr_len = sizeof(*sin);

	if (flags & MSG_ERRQUEUE) {
		err = ip_recv_error(sk, msg, len);
		goto out;
	}

	skb = skb_recv_datagram(sk, flags, noblock, &err);
	if (!skb)
		goto out;

	copied = skb->len;
	if (len < copied) {
		msg->msg_flags |= MSG_TRUNC;
		copied = len;
	}

	err = skb_copy_datagram_iovec(skb, 0, msg->msg_iov, copied);
	if (err)
		goto done;

	sock_recv_ts_and_drops(msg, sk, skb);

	/* Copy the address. */
	if (sin) {
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = ip_hdr(skb)->saddr;
		sin->sin_port = 0;
		memset(&sin->sin_zero, 0, sizeof(sin->sin_zero));
	}
	if (inet->cmsg_flags)
		ip_cmsg_recv(msg, skb);
	if (flags & MSG_TRUNC)
		copied = skb->len;
done:
	skb_free_datagram(sk, skb);
out:
	if (err)
		return err;
	return copied;
}

static int raw_init(struct sock *sk)
{
	struct raw_sock *rp = raw_sk(sk);

	if (inet_sk(sk)->inet_num == IPPROTO_ICMP)
		memset(&rp->filter, 0, sizeof(rp->filter));
	return 0;
}

static int raw_seticmpfilter(struct sock *sk, char __user *optval, int optlen)
{
	if (optlen > sizeof(struct icmp_filter))
		optlen = sizeof(struct icmp_filter);
	if (copy_from_user(&raw_sk(sk)->filter, optval, optlen))
		return -EFAULT;
	return 0;
}

static int raw_geticmpfilter(struct sock *sk, char __user *optval, int __user *optlen)
{
	int len, ret = -EFAULT;

	if (get_user(len, optlen))
		goto out;
	ret = -EINVAL;
	if (len < 0)
		goto out;
	if (len > sizeof(struct icmp_filter))
		len = sizeof(struct icmp_filter);
	ret = -EFAULT;
	if (put_user(len, optlen) ||
	    copy_to_user(optval, &raw_sk(sk)->filter, len))
		goto out;
	ret = 0;
out:	return ret;
}

static int do_raw_setsockopt(struct sock *sk, int level, int optname,
			  char __user *optval, unsigned int optlen)
{
	if (optname == ICMP_FILTER) {
		if (inet_sk(sk)->inet_num != IPPROTO_ICMP)
			return -EOPNOTSUPP;
		else
			return raw_seticmpfilter(sk, optval, optlen);
	}
	return -ENOPROTOOPT;
}

static int raw_setsockopt(struct sock *sk, int level, int optname,
			  char __user *optval, unsigned int optlen)
{
	if (level != SOL_RAW)
		return ip_setsockopt(sk, level, optname, optval, optlen);
	return do_raw_setsockopt(sk, level, optname, optval, optlen);
}

#ifdef CONFIG_COMPAT
static int compat_raw_setsockopt(struct sock *sk, int level, int optname,
				 char __user *optval, unsigned int optlen)
{
	if (level != SOL_RAW)
		return compat_ip_setsockopt(sk, level, optname, optval, optlen);
	return do_raw_setsockopt(sk, level, optname, optval, optlen);
}
#endif

static int do_raw_getsockopt(struct sock *sk, int level, int optname,
			  char __user *optval, int __user *optlen)
{
	if (optname == ICMP_FILTER) {
		if (inet_sk(sk)->inet_num != IPPROTO_ICMP)
			return -EOPNOTSUPP;
		else
			return raw_geticmpfilter(sk, optval, optlen);
	}
	return -ENOPROTOOPT;
}

static int raw_getsockopt(struct sock *sk, int level, int optname,
			  char __user *optval, int __user *optlen)
{
	if (level != SOL_RAW)
		return ip_getsockopt(sk, level, optname, optval, optlen);
	return do_raw_getsockopt(sk, level, optname, optval, optlen);
}

#ifdef CONFIG_COMPAT
static int compat_raw_getsockopt(struct sock *sk, int level, int optname,
				 char __user *optval, int __user *optlen)
{
	if (level != SOL_RAW)
		return compat_ip_getsockopt(sk, level, optname, optval, optlen);
	return do_raw_getsockopt(sk, level, optname, optval, optlen);
}
#endif

static int raw_ioctl(struct sock *sk, int cmd, unsigned long arg)
{
	switch (cmd) {
	case SIOCOUTQ: {
		int amount = sk_wmem_alloc_get(sk);

		return put_user(amount, (int __user *)arg);
	}
	case SIOCINQ: {
		struct sk_buff *skb;
		int amount = 0;

		spin_lock_bh(&sk->sk_receive_queue.lock);
		skb = skb_peek(&sk->sk_receive_queue);
		if (skb != NULL)
			amount = skb->len;
		spin_unlock_bh(&sk->sk_receive_queue.lock);
		return put_user(amount, (int __user *)arg);
	}

	default:
#ifdef CONFIG_IP_MROUTE
		return ipmr_ioctl(sk, cmd, (void __user *)arg);
#else
		return -ENOIOCTLCMD;
#endif
	}
}

#ifdef CONFIG_COMPAT
static int compat_raw_ioctl(struct sock *sk, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case SIOCOUTQ:
	case SIOCINQ:
		return -ENOIOCTLCMD;
	default:
#ifdef CONFIG_IP_MROUTE
		return ipmr_compat_ioctl(sk, cmd, compat_ptr(arg));
#else
		return -ENOIOCTLCMD;
#endif
	}
}
#endif

struct proto raw_prot = {
	.name		   = "RAW",
	.owner		   = THIS_MODULE,
	.close		   = raw_close,
	.destroy	   = raw_destroy,
	.connect	   = ip4_datagram_connect,
	.disconnect	   = udp_disconnect,
	.ioctl		   = raw_ioctl,
	.init		   = raw_init,
	.setsockopt	   = raw_setsockopt,
	.getsockopt	   = raw_getsockopt,
	.sendmsg	   = raw_sendmsg,
	.recvmsg	   = raw_recvmsg,
	.bind		   = raw_bind,
	.backlog_rcv	   = raw_rcv_skb,
	.release_cb	   = ip4_datagram_release_cb,
	.hash		   = raw_hash_sk,
	.unhash		   = raw_unhash_sk,
	.obj_size	   = sizeof(struct raw_sock),
	.h.raw_hash	   = &raw_v4_hashinfo,
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_raw_setsockopt,
	.compat_getsockopt = compat_raw_getsockopt,
	.compat_ioctl	   = compat_raw_ioctl,
#endif
};

#ifdef CONFIG_PROC_FS
static struct sock *raw_get_first(struct seq_file *seq)
{
	struct sock *sk;
	struct raw_iter_state *state = raw_seq_private(seq);

	for (state->bucket = 0; state->bucket < RAW_HTABLE_SIZE;
			++state->bucket) {
		sk_for_each(sk, &state->h->ht[state->bucket])
			if (sock_net(sk) == seq_file_net(seq))
				goto found;
	}
	sk = NULL;
found:
	return sk;
}

static struct sock *raw_get_next(struct seq_file *seq, struct sock *sk)
{
	struct raw_iter_state *state = raw_seq_private(seq);

	do {
		sk = sk_next(sk);
try_again:
		;
	} while (sk && sock_net(sk) != seq_file_net(seq));

	if (!sk && ++state->bucket < RAW_HTABLE_SIZE) {
		sk = sk_head(&state->h->ht[state->bucket]);
		goto try_again;
	}
	return sk;
}

static struct sock *raw_get_idx(struct seq_file *seq, loff_t pos)
{
	struct sock *sk = raw_get_first(seq);

	if (sk)
		while (pos && (sk = raw_get_next(seq, sk)) != NULL)
			--pos;
	return pos ? NULL : sk;
}

void *raw_seq_start(struct seq_file *seq, loff_t *pos)
{
	struct raw_iter_state *state = raw_seq_private(seq);

	read_lock(&state->h->lock);
	return *pos ? raw_get_idx(seq, *pos - 1) : SEQ_START_TOKEN;
}
EXPORT_SYMBOL_GPL(raw_seq_start);

void *raw_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct sock *sk;

	if (v == SEQ_START_TOKEN)
		sk = raw_get_first(seq);
	else
		sk = raw_get_next(seq, v);
	++*pos;
	return sk;
}
EXPORT_SYMBOL_GPL(raw_seq_next);

void raw_seq_stop(struct seq_file *seq, void *v)
{
	struct raw_iter_state *state = raw_seq_private(seq);

	read_unlock(&state->h->lock);
}
EXPORT_SYMBOL_GPL(raw_seq_stop);

static void raw_sock_seq_show(struct seq_file *seq, struct sock *sp, int i)
{
	struct inet_sock *inet = inet_sk(sp);
	__be32 dest = inet->inet_daddr,
	       src = inet->inet_rcv_saddr;
	__u16 destp = 0,
	      srcp  = inet->inet_num;

	seq_printf(seq, "%4d: %08X:%04X %08X:%04X"
		" %02X %08X:%08X %02X:%08lX %08X %5u %8d %lu %d %pK %d\n",
		i, src, srcp, dest, destp, sp->sk_state,
		sk_wmem_alloc_get(sp),
		sk_rmem_alloc_get(sp),
		0, 0L, 0,
		from_kuid_munged(seq_user_ns(seq), sock_i_uid(sp)),
		0, sock_i_ino(sp),
		atomic_read(&sp->sk_refcnt), sp, atomic_read(&sp->sk_drops));
}

static int raw_seq_show(struct seq_file *seq, void *v)
{
	if (v == SEQ_START_TOKEN)
		seq_printf(seq, " sl local_address rem_address st tx_queue "
				"rx_queue tr tm->when retrnsmt uid timeout "
				"inode ref pointer drops\n");
	else
		raw_sock_seq_show(seq, v, raw_seq_private(seq)->bucket);
	return 0;
}

static const struct seq_operations raw_seq_ops = {
	.start = raw_seq_start,
	.next  = raw_seq_next,
	.stop  = raw_seq_stop,
	.show  = raw_seq_show,
};

int raw_seq_open(struct inode *ino, struct file *file,
		 struct raw_hashinfo *h, const struct seq_operations *ops)
{
	int err;
	struct raw_iter_state *i;

	err = seq_open_net(ino, file, ops, sizeof(struct raw_iter_state));
	if (err < 0)
		return err;

	i = raw_seq_private((struct seq_file *)file->private_data);
	i->h = h;
	return 0;
}
EXPORT_SYMBOL_GPL(raw_seq_open);

static int raw_v4_seq_open(struct inode *inode, struct file *file)
{
	return raw_seq_open(inode, file, &raw_v4_hashinfo, &raw_seq_ops);
}

static const struct file_operations raw_seq_fops = {
	.owner	 = THIS_MODULE,
	.open	 = raw_v4_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = seq_release_net,
};

static __net_init int raw_init_net(struct net *net)
{
	if (!proc_create("raw", S_IRUGO, net->proc_net, &raw_seq_fops))
		return -ENOMEM;

	return 0;
}

static __net_exit void raw_exit_net(struct net *net)
{
	remove_proc_entry("raw", net->proc_net);
}

static __net_initdata struct pernet_operations raw_net_ops = {
	.init = raw_init_net,
	.exit = raw_exit_net,
};

int __init raw_proc_init(void)
{
	return register_pernet_subsys(&raw_net_ops);
}

void __init raw_proc_exit(void)
{
	unregister_pernet_subsys(&raw_net_ops);
}
#endif /* CONFIG_PROC_FS */

/*
 * RAW sockets for IPv6
 * Linux INET6 implementation
 *
 * Authors:
 * Pedro Roque <roque@di.fc.ul.pt>
 *
 * Adapted from linux/net/ipv4/raw.c
 *
 * Fixes:
 * Hideaki YOSHIFUJI : sin6_scope_id support
 * YOSHIFUJI,H.@USAGI : raw checksum (RFC2292(bis) compliance)
 * Kazunori MIYAZAWA @USAGI: change process style to use ip6_append_data
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/slab.h>
#include <linux/sockios.h>
#include <linux/net.h>
#include <linux/in6.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/icmpv6.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv6.h>
#include <linux/skbuff.h>
#include <linux/compat.h>
#include <asm/uaccess.h>
#include <asm/ioctls.h>

#include <net/net_namespace.h>
#include <net/ip.h>
#include <net/sock.h>
#include <net/snmp.h>

#include <net/ipv6.h>
#include <net/ndisc.h>
#include <net/protocol.h>
#include <net/ip6_route.h>
#include <net/ip6_checksum.h>
#include <net/addrconf.h>
#include <net/transp_v6.h>
#include <net/udp.h>
#include <net/inet_common.h>
#include <net/tcp_states.h>
#if IS_ENABLED(CONFIG_IPV6_MIP6)
#include <net/mip6.h>
#endif
#include <linux/mroute6.h>

#include <net/raw.h>
#include <net/rawv6.h>
#include <net/xfrm.h>

#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/export.h>

#define ICMPV6_HDRLEN 4	/* ICMPv6 header, RFC 4443 Section 2.1 */

static struct raw_hashinfo raw_v6_hashinfo = {
	.lock = __RW_LOCK_UNLOCKED(raw_v6_hashinfo.lock),
};

static struct sock *__raw_v6_lookup(struct net *net, struct sock *sk,
		unsigned short num, const struct in6_addr *loc_addr,
		const struct in6_addr *rmt_addr, int dif)
{
	bool is_multicast = ipv6_addr_is_multicast(loc_addr);

	sk_for_each_from(sk)
		if (inet_sk(sk)->inet_num == num) {

			if (!net_eq(sock_net(sk), net))
				continue;

			if (!ipv6_addr_any(&sk->sk_v6_daddr) &&
			    !ipv6_addr_equal(&sk->sk_v6_daddr, rmt_addr))
				continue;

			if (sk->sk_bound_dev_if && sk->sk_bound_dev_if != dif)
				continue;

			if (!ipv6_addr_any(&sk->sk_v6_rcv_saddr)) {
				if (ipv6_addr_equal(&sk->sk_v6_rcv_saddr, loc_addr))
					goto found;
				if (is_multicast &&
				    inet6_mc_check(sk, loc_addr, rmt_addr))
					goto found;
				continue;
			}
			goto found;
		}
	sk = NULL;
found:
	return sk;
}

/*
 * 0 - deliver
 * 1 - block
 */
static int icmpv6_filter(const struct sock *sk, const struct sk_buff *skb)
{
	struct icmp6hdr _hdr;
	const struct icmp6hdr *hdr;

	/* We require only the four bytes of the ICMPv6 header, not any
 * additional bytes of message body in "struct icmp6hdr".
 */
	hdr = skb_header_pointer(skb, skb_transport_offset(skb),
				 ICMPV6_HDRLEN, &_hdr);
	if (hdr) {
		const __u32 *data = &raw6_sk(sk)->filter.data[0];
		unsigned int type = hdr->icmp6_type;

		return (data[type >> 5] & (1U << (type & 31))) != 0;
	}
	return 1;
}

#if IS_ENABLED(CONFIG_IPV6_MIP6)
typedef int mh_filter_t(struct sock *sock, struct sk_buff *skb);

static mh_filter_t __rcu *mh_filter __read_mostly;

int rawv6_mh_filter_register(mh_filter_t filter)
{
	rcu_assign_pointer(mh_filter, filter);
	return 0;
}
EXPORT_SYMBOL(rawv6_mh_filter_register);

int rawv6_mh_filter_unregister(mh_filter_t filter)
{
	RCU_INIT_POINTER(mh_filter, NULL);
	synchronize_rcu();
	return 0;
}
EXPORT_SYMBOL(rawv6_mh_filter_unregister);

#endif

/*
 * demultiplex raw sockets.
 * (should consider queueing the skb in the sock receive_queue
 * without calling rawv6.c)
 *
 * Caller owns SKB so we must make clones.
 */
static bool ipv6_raw_deliver(struct sk_buff *skb, int nexthdr)
{
	const struct in6_addr *saddr;
	const struct in6_addr *daddr;
	struct sock *sk;
	bool delivered = false;
	__u8 hash;
	struct net *net;

	saddr = &ipv6_hdr(skb)->saddr;
	daddr = saddr + 1;

	hash = nexthdr & (RAW_HTABLE_SIZE - 1);

	read_lock(&raw_v6_hashinfo.lock);
	sk = sk_head(&raw_v6_hashinfo.ht[hash]);

	if (sk == NULL)
		goto out;

	net = dev_net(skb->dev);
	sk = __raw_v6_lookup(net, sk, nexthdr, daddr, saddr, IP6CB(skb)->iif);

	while (sk) {
		int filtered;

		delivered = true;
		switch (nexthdr) {
		case IPPROTO_ICMPV6:
			filtered = icmpv6_filter(sk, skb);
			break;

#if IS_ENABLED(CONFIG_IPV6_MIP6)
		case IPPROTO_MH:
		{
			/* XXX: To validate MH only once for each packet,
 * this is placed here. It should be after checking
 * xfrm policy, however it doesn't. The checking xfrm
 * policy is placed in rawv6_rcv() because it is
 * required for each socket.
 */
			mh_filter_t *filter;

			filter = rcu_dereference(mh_filter);
			filtered = filter ? (*filter)(sk, skb) : 0;
			break;
		}
#endif
		default:
			filtered = 0;
			break;
		}

		if (filtered < 0)
			break;
		if (filtered == 0) {
			struct sk_buff *clone = skb_clone(skb, GFP_ATOMIC);

			/* Not releasing hash table! */
			if (clone) {
				nf_reset(clone);
				rawv6_rcv(sk, clone);
			}
		}
		sk = __raw_v6_lookup(net, sk_next(sk), nexthdr, daddr, saddr,
				     IP6CB(skb)->iif);
	}
out:
	read_unlock(&raw_v6_hashinfo.lock);
	return delivered;
}

bool raw6_local_deliver(struct sk_buff *skb, int nexthdr)
{
	struct sock *raw_sk;

	raw_sk = sk_head(&raw_v6_hashinfo.ht[nexthdr & (RAW_HTABLE_SIZE - 1)]);
	if (raw_sk && !ipv6_raw_deliver(skb, nexthdr))
		raw_sk = NULL;

	return raw_sk != NULL;
}

/* This cleans up af_inet6 a bit. -DaveM */
static int rawv6_bind(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	struct inet_sock *inet = inet_sk(sk);
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct sockaddr_in6 *addr = (struct sockaddr_in6 *) uaddr;
	__be32 v4addr = 0;
	int addr_type;
	int err;

	if (addr_len < SIN6_LEN_RFC2133)
		return -EINVAL;
	addr_type = ipv6_addr_type(&addr->sin6_addr);

	/* Raw sockets are IPv6 only */
	if (addr_type == IPV6_ADDR_MAPPED)
		return -EADDRNOTAVAIL;

	lock_sock(sk);

	err = -EINVAL;
	if (sk->sk_state != TCP_CLOSE)
		goto out;

	rcu_read_lock();
	/* Check if the address belongs to the host. */
	if (addr_type != IPV6_ADDR_ANY) {
		struct net_device *dev = NULL;

		if (__ipv6_addr_needs_scope_id(addr_type)) {
			if (addr_len >= sizeof(struct sockaddr_in6) &&
			    addr->sin6_scope_id) {
				/* Override any existing binding, if another
 * one is supplied by user.
 */
				sk->sk_bound_dev_if = addr->sin6_scope_id;
			}

			/* Binding to link-local address requires an interface */
			if (!sk->sk_bound_dev_if)
				goto out_unlock;

			err = -ENODEV;
			dev = dev_get_by_index_rcu(sock_net(sk),
						   sk->sk_bound_dev_if);
			if (!dev)
				goto out_unlock;
		}

		/* ipv4 addr of the socket is invalid. Only the
 * unspecified and mapped address have a v4 equivalent.
 */
		v4addr = LOOPBACK4_IPV6;
		if (!(addr_type & IPV6_ADDR_MULTICAST)) {
			err = -EADDRNOTAVAIL;
			if (!ipv6_chk_addr(sock_net(sk), &addr->sin6_addr,
					   dev, 0)) {
				goto out_unlock;
			}
		}
	}

	inet->inet_rcv_saddr = inet->inet_saddr = v4addr;
	sk->sk_v6_rcv_saddr = addr->sin6_addr;
	if (!(addr_type & IPV6_ADDR_MULTICAST))
		np->saddr = addr->sin6_addr;
	err = 0;
out_unlock:
	rcu_read_unlock();
out:
	release_sock(sk);
	return err;
}

static void rawv6_err(struct sock *sk, struct sk_buff *skb,
	       struct inet6_skb_parm *opt,
	       u8 type, u8 code, int offset, __be32 info)
{
	struct inet_sock *inet = inet_sk(sk);
	struct ipv6_pinfo *np = inet6_sk(sk);
	int err;
	int harderr;

	/* Report error on raw socket, if:
 1. User requested recverr.
 2. Socket is connected (otherwise the error indication
 is useless without recverr and error is hard.
 */
	if (!np->recverr && sk->sk_state != TCP_ESTABLISHED)
		return;

	harderr = icmpv6_err_convert(type, code, &err);
	if (type == ICMPV6_PKT_TOOBIG) {
		ip6_sk_update_pmtu(skb, sk, info);
		harderr = (np->pmtudisc == IPV6_PMTUDISC_DO);
	}
	if (type == NDISC_REDIRECT) {
		ip6_sk_redirect(skb, sk);
		return;
	}
	if (np->recverr) {
		u8 *payload = skb->data;
		if (!inet->hdrincl)
			payload += offset;
		ipv6_icmp_error(sk, skb, err, 0, ntohl(info), payload);
	}

	if (np->recverr || harderr) {
		sk->sk_err = err;
		sk->sk_error_report(sk);
	}
}

void raw6_icmp_error(struct sk_buff *skb, int nexthdr,
		u8 type, u8 code, int inner_offset, __be32 info)
{
	struct sock *sk;
	int hash;
	const struct in6_addr *saddr, *daddr;
	struct net *net;

	hash = nexthdr & (RAW_HTABLE_SIZE - 1);

	read_lock(&raw_v6_hashinfo.lock);
	sk = sk_head(&raw_v6_hashinfo.ht[hash]);
	if (sk != NULL) {
		/* Note: ipv6_hdr(skb) != skb->data */
		const struct ipv6hdr *ip6h = (const struct ipv6hdr *)skb->data;
		saddr = &ip6h->saddr;
		daddr = &ip6h->daddr;
		net = dev_net(skb->dev);

		while ((sk = __raw_v6_lookup(net, sk, nexthdr, saddr, daddr,
						IP6CB(skb)->iif))) {
			rawv6_err(sk, skb, NULL, type, code,
					inner_offset, info);
			sk = sk_next(sk);
		}
	}
	read_unlock(&raw_v6_hashinfo.lock);
}

static inline int rawv6_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	if ((raw6_sk(sk)->checksum || rcu_access_pointer(sk->sk_filter)) &&
	    skb_checksum_complete(skb)) {
		atomic_inc(&sk->sk_drops);
		kfree_skb(skb);
		return NET_RX_DROP;
	}

	/* Charge it to the socket. */
	skb_dst_drop(skb);
	if (sock_queue_rcv_skb(sk, skb) < 0) {
		kfree_skb(skb);
		return NET_RX_DROP;
	}

	return 0;
}

/*
 * This is next to useless...
 * if we demultiplex in network layer we don't need the extra call
 * just to queue the skb...
 * maybe we could have the network decide upon a hint if it
 * should call raw_rcv for demultiplexing
 */
int rawv6_rcv(struct sock *sk, struct sk_buff *skb)
{
	struct inet_sock *inet = inet_sk(sk);
	struct raw6_sock *rp = raw6_sk(sk);

	if (!xfrm6_policy_check(sk, XFRM_POLICY_IN, skb)) {
		atomic_inc(&sk->sk_drops);
		kfree_skb(skb);
		return NET_RX_DROP;
	}

	if (!rp->checksum)
		skb->ip_summed = CHECKSUM_UNNECESSARY;

	if (skb->ip_summed == CHECKSUM_COMPLETE) {
		skb_postpull_rcsum(skb, skb_network_header(skb),
				   skb_network_header_len(skb));
		if (!csum_ipv6_magic(&ipv6_hdr(skb)->saddr,
				     &ipv6_hdr(skb)->daddr,
				     skb->len, inet->inet_num, skb->csum))
			skb->ip_summed = CHECKSUM_UNNECESSARY;
	}
	if (!skb_csum_unnecessary(skb))
		skb->csum = ~csum_unfold(csum_ipv6_magic(&ipv6_hdr(skb)->saddr,
							 &ipv6_hdr(skb)->daddr,
							 skb->len,
							 inet->inet_num, 0));

	if (inet->hdrincl) {
		if (skb_checksum_complete(skb)) {
			atomic_inc(&sk->sk_drops);
			kfree_skb(skb);
			return NET_RX_DROP;
		}
	}

	rawv6_rcv_skb(sk, skb);
	return 0;
}


/*
 * This should be easy, if there is something there
 * we return it, otherwise we block.
 */

static int rawv6_recvmsg(struct kiocb *iocb, struct sock *sk,
		  struct msghdr *msg, size_t len,
		  int noblock, int flags, int *addr_len)
{
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)msg->msg_name;
	struct sk_buff *skb;
	size_t copied;
	int err;

	if (flags & MSG_OOB)
		return -EOPNOTSUPP;

	if (addr_len)
		*addr_len=sizeof(*sin6);

	if (flags & MSG_ERRQUEUE)
		return ipv6_recv_error(sk, msg, len);

	if (np->rxpmtu && np->rxopt.bits.rxpmtu)
		return ipv6_recv_rxpmtu(sk, msg, len);

	skb = skb_recv_datagram(sk, flags, noblock, &err);
	if (!skb)
		goto out;

	copied = skb->len;
	if (copied > len) {
		copied = len;
		msg->msg_flags |= MSG_TRUNC;
	}

	if (skb_csum_unnecessary(skb)) {
		err = skb_copy_datagram_iovec(skb, 0, msg->msg_iov, copied);
	} else if (msg->msg_flags&MSG_TRUNC) {
		if (__skb_checksum_complete(skb))
			goto csum_copy_err;
		err = skb_copy_datagram_iovec(skb, 0, msg->msg_iov, copied);
	} else {
		err = skb_copy_and_csum_datagram_iovec(skb, 0, msg->msg_iov);
		if (err == -EINVAL)
			goto csum_copy_err;
	}
	if (err)
		goto out_free;

	/* Copy the address. */
	if (sin6) {
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = 0;
		sin6->sin6_addr = ipv6_hdr(skb)->saddr;
		sin6->sin6_flowinfo = 0;
		sin6->sin6_scope_id = ipv6_iface_scope_id(&sin6->sin6_addr,
							  IP6CB(skb)->iif);
	}

	sock_recv_ts_and_drops(msg, sk, skb);

	if (np->rxopt.all)
		ip6_datagram_recv_ctl(sk, msg, skb);

	err = copied;
	if (flags & MSG_TRUNC)
		err = skb->len;

out_free:
	skb_free_datagram(sk, skb);
out:
	return err;

csum_copy_err:
	skb_kill_datagram(sk, skb, flags);

	/* Error for blocking case is chosen to masquerade
 as some normal condition.
 */
	err = (flags&MSG_DONTWAIT) ? -EAGAIN : -EHOSTUNREACH;
	goto out;
}

static int rawv6_push_pending_frames(struct sock *sk, struct flowi6 *fl6,
				     struct raw6_sock *rp)
{
	struct sk_buff *skb;
	int err = 0;
	int offset;
	int len;
	int total_len;
	__wsum tmp_csum;
	__sum16 csum;

	if (!rp->checksum)
		goto send;

	if ((skb = skb_peek(&sk->sk_write_queue)) == NULL)
		goto out;

	offset = rp->offset;
	total_len = inet_sk(sk)->cork.base.length;
	if (offset >= total_len - 1) {
		err = -EINVAL;
		ip6_flush_pending_frames(sk);
		goto out;
	}

	/* should be check HW csum miyazawa */
	if (skb_queue_len(&sk->sk_write_queue) == 1) {
		/*
 * Only one fragment on the socket.
 */
		tmp_csum = skb->csum;
	} else {
		struct sk_buff *csum_skb = NULL;
		tmp_csum = 0;

		skb_queue_walk(&sk->sk_write_queue, skb) {
			tmp_csum = csum_add(tmp_csum, skb->csum);

			if (csum_skb)
				continue;

			len = skb->len - skb_transport_offset(skb);
			if (offset >= len) {
				offset -= len;
				continue;
			}

			csum_skb = skb;
		}

		skb = csum_skb;
	}

	offset += skb_transport_offset(skb);
	if (skb_copy_bits(skb, offset, &csum, 2))
		BUG();

	/* in case cksum was not initialized */
	if (unlikely(csum))
		tmp_csum = csum_sub(tmp_csum, csum_unfold(csum));

	csum = csum_ipv6_magic(&fl6->saddr, &fl6->daddr,
			       total_len, fl6->flowi6_proto, tmp_csum);

	if (csum == 0 && fl6->flowi6_proto == IPPROTO_UDP)
		csum = CSUM_MANGLED_0;

	if (skb_store_bits(skb, offset, &csum, 2))
		BUG();

send:
	err = ip6_push_pending_frames(sk);
out:
	return err;
}

static int rawv6_send_hdrinc(struct sock *sk, void *from, int length,
			struct flowi6 *fl6, struct dst_entry **dstp,
			unsigned int flags)
{
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct ipv6hdr *iph;
	struct sk_buff *skb;
	int err;
	struct rt6_info *rt = (struct rt6_info *)*dstp;
	int hlen = LL_RESERVED_SPACE(rt->dst.dev);
	int tlen = rt->dst.dev->needed_tailroom;

	if (length > rt->dst.dev->mtu) {
		ipv6_local_error(sk, EMSGSIZE, fl6, rt->dst.dev->mtu);
		return -EMSGSIZE;
	}
	if (flags&MSG_PROBE)
		goto out;

	skb = sock_alloc_send_skb(sk,
				  length + hlen + tlen + 15,
				  flags & MSG_DONTWAIT, &err);
	if (skb == NULL)
		goto error;
	skb_reserve(skb, hlen);

	skb->protocol = htons(ETH_P_IPV6);
	skb->priority = sk->sk_priority;
	skb->mark = sk->sk_mark;
	skb_dst_set(skb, &rt->dst);
	*dstp = NULL;

	skb_put(skb, length);
	skb_reset_network_header(skb);
	iph = ipv6_hdr(skb);

	skb->ip_summed = CHECKSUM_NONE;

	skb->transport_header = skb->network_header;
	err = memcpy_fromiovecend((void *)iph, from, 0, length);
	if (err)
		goto error_fault;

	IP6_UPD_PO_STATS(sock_net(sk), rt->rt6i_idev, IPSTATS_MIB_OUT, skb->len);
	err = NF_HOOK(NFPROTO_IPV6, NF_INET_LOCAL_OUT, skb, NULL,
		      rt->dst.dev, dst_output);
	if (err > 0)
		err = net_xmit_errno(err);
	if (err)
		goto error;
out:
	return 0;

error_fault:
	err = -EFAULT;
	kfree_skb(skb);
error:
	IP6_INC_STATS(sock_net(sk), rt->rt6i_idev, IPSTATS_MIB_OUTDISCARDS);
	if (err == -ENOBUFS && !np->recverr)
		err = 0;
	return err;
}

static int rawv6_probe_proto_opt(struct flowi6 *fl6, struct msghdr *msg)
{
	struct iovec *iov;
	u8 __user *type = NULL;
	u8 __user *code = NULL;
	u8 len = 0;
	int probed = 0;
	int i;

	if (!msg->msg_iov)
		return 0;

	for (i = 0; i < msg->msg_iovlen; i++) {
		iov = &msg->msg_iov[i];
		if (!iov)
			continue;

		switch (fl6->flowi6_proto) {
		case IPPROTO_ICMPV6:
			/* check if one-byte field is readable or not. */
			if (iov->iov_base && iov->iov_len < 1)
				break;

			if (!type) {
				type = iov->iov_base;
				/* check if code field is readable or not. */
				if (iov->iov_len > 1)
					code = type + 1;
			} else if (!code)
				code = iov->iov_base;

			if (type && code) {
				if (get_user(fl6->fl6_icmp_type, type) ||
				    get_user(fl6->fl6_icmp_code, code))
					return -EFAULT;
				probed = 1;
			}
			break;
		case IPPROTO_MH:
			if (iov->iov_base && iov->iov_len < 1)
				break;
			/* check if type field is readable or not. */
			if (iov->iov_len > 2 - len) {
				u8 __user *p = iov->iov_base;
				if (get_user(fl6->fl6_mh_type, &p[2 - len]))
					return -EFAULT;
				probed = 1;
			} else
				len += iov->iov_len;

			break;
		default:
			probed = 1;
			break;
		}
		if (probed)
			break;
	}
	return 0;
}

static int rawv6_sendmsg(struct kiocb *iocb, struct sock *sk,
		   struct msghdr *msg, size_t len)
{
	struct ipv6_txoptions opt_space;
	struct sockaddr_in6 * sin6 = (struct sockaddr_in6 *) msg->msg_name;
	struct in6_addr *daddr, *final_p, final;
	struct inet_sock *inet = inet_sk(sk);
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct raw6_sock *rp = raw6_sk(sk);
	struct ipv6_txoptions *opt = NULL;
	struct ip6_flowlabel *flowlabel = NULL;
	struct dst_entry *dst = NULL;
	struct flowi6 fl6;
	int addr_len = msg->msg_namelen;
	int hlimit = -1;
	int tclass = -1;
	int dontfrag = -1;
	u16 proto;
	int err;

	/* Rough check on arithmetic overflow,
 better check is made in ip6_append_data().
 */
	if (len > INT_MAX)
		return -EMSGSIZE;

	/* Mirror BSD error message compatibility */
	if (msg->msg_flags & MSG_OOB)
		return -EOPNOTSUPP;

	/*
 * Get and verify the address.
 */
	memset(&fl6, 0, sizeof(fl6));

	fl6.flowi6_mark = sk->sk_mark;

	if (sin6) {
		if (addr_len < SIN6_LEN_RFC2133)
			return -EINVAL;

		if (sin6->sin6_family && sin6->sin6_family != AF_INET6)
			return -EAFNOSUPPORT;

		/* port is the proto value [0..255] carried in nexthdr */
		proto = ntohs(sin6->sin6_port);

		if (!proto)
			proto = inet->inet_num;
		else if (proto != inet->inet_num)
			return -EINVAL;

		if (proto > 255)
			return -EINVAL;

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

		proto = inet->inet_num;
		daddr = &sk->sk_v6_daddr;
		fl6.flowlabel = np->flow_label;
	}

	if (fl6.flowi6_oif == 0)
		fl6.flowi6_oif = sk->sk_bound_dev_if;

	if (msg->msg_controllen) {
		opt = &opt_space;
		memset(opt, 0, sizeof(struct ipv6_txoptions));
		opt->tot_len = sizeof(struct ipv6_txoptions);

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
	}
	if (opt == NULL)
		opt = np->opt;
	if (flowlabel)
		opt = fl6_merge_options(&opt_space, flowlabel, opt);
	opt = ipv6_fixup_options(&opt_space, opt);

	fl6.flowi6_proto = proto;
	err = rawv6_probe_proto_opt(&fl6, msg);
	if (err)
		goto out;

	if (!ipv6_addr_any(daddr))
		fl6.daddr = *daddr;
	else
		fl6.daddr.s6_addr[15] = 0x1; /* :: means loopback (BSD'ism) */
	if (ipv6_addr_any(&fl6.saddr) && !ipv6_addr_any(&np->saddr))
		fl6.saddr = np->saddr;

	final_p = fl6_update_dst(&fl6, opt, &final);

	if (!fl6.flowi6_oif && ipv6_addr_is_multicast(&fl6.daddr))
		fl6.flowi6_oif = np->mcast_oif;
	else if (!fl6.flowi6_oif)
		fl6.flowi6_oif = np->ucast_oif;
	security_sk_classify_flow(sk, flowi6_to_flowi(&fl6));

	dst = ip6_dst_lookup_flow(sk, &fl6, final_p, true);
	if (IS_ERR(dst)) {
		err = PTR_ERR(dst);
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

	if (dontfrag < 0)
		dontfrag = np->dontfrag;

	if (msg->msg_flags&MSG_CONFIRM)
		goto do_confirm;

back_from_confirm:
	if (inet->hdrincl)
		err = rawv6_send_hdrinc(sk, msg->msg_iov, len, &fl6, &dst, msg->msg_flags);
	else {
		lock_sock(sk);
		err = ip6_append_data(sk, ip_generic_getfrag, msg->msg_iov,
			len, 0, hlimit, tclass, opt, &fl6, (struct rt6_info*)dst,
			msg->msg_flags, dontfrag);

		if (err)
			ip6_flush_pending_frames(sk);
		else if (!(msg->msg_flags & MSG_MORE))
			err = rawv6_push_pending_frames(sk, &fl6, rp);
		release_sock(sk);
	}
done:
	dst_release(dst);
out:
	fl6_sock_release(flowlabel);
	return err<0?err:len;
do_confirm:
	dst_confirm(dst);
	if (!(msg->msg_flags & MSG_PROBE) || len)
		goto back_from_confirm;
	err = 0;
	goto done;
}

static int rawv6_seticmpfilter(struct sock *sk, int level, int optname,
			       char __user *optval, int optlen)
{
	switch (optname) {
	case ICMPV6_FILTER:
		if (optlen > sizeof(struct icmp6_filter))
			optlen = sizeof(struct icmp6_filter);
		if (copy_from_user(&raw6_sk(sk)->filter, optval, optlen))
			return -EFAULT;
		return 0;
	default:
		return -ENOPROTOOPT;
	}

	return 0;
}

static int rawv6_geticmpfilter(struct sock *sk, int level, int optname,
			       char __user *optval, int __user *optlen)
{
	int len;

	switch (optname) {
	case ICMPV6_FILTER:
		if (get_user(len, optlen))
			return -EFAULT;
		if (len < 0)
			return -EINVAL;
		if (len > sizeof(struct icmp6_filter))
			len = sizeof(struct icmp6_filter);
		if (put_user(len, optlen))
			return -EFAULT;
		if (copy_to_user(optval, &raw6_sk(sk)->filter, len))
			return -EFAULT;
		return 0;
	default:
		return -ENOPROTOOPT;
	}

	return 0;
}


static int do_rawv6_setsockopt(struct sock *sk, int level, int optname,
			    char __user *optval, unsigned int optlen)
{
	struct raw6_sock *rp = raw6_sk(sk);
	int val;

	if (get_user(val, (int __user *)optval))
		return -EFAULT;

	switch (optname) {
	case IPV6_CHECKSUM:
		if (inet_sk(sk)->inet_num == IPPROTO_ICMPV6 &&
		    level == IPPROTO_IPV6) {
			/*
 * RFC3542 tells that IPV6_CHECKSUM socket
 * option in the IPPROTO_IPV6 level is not
 * allowed on ICMPv6 sockets.
 * If you want to set it, use IPPROTO_RAW
 * level IPV6_CHECKSUM socket option
 * (Linux extension).
 */
			return -EINVAL;
		}

		/* You may get strange result with a positive odd offset;
 RFC2292bis agrees with me. */
		if (val > 0 && (val&1))
			return -EINVAL;
		if (val < 0) {
			rp->checksum = 0;
		} else {
			rp->checksum = 1;
			rp->offset = val;
		}

		return 0;

	default:
		return -ENOPROTOOPT;
	}
}

static int rawv6_setsockopt(struct sock *sk, int level, int optname,
			  char __user *optval, unsigned int optlen)
{
	switch (level) {
	case SOL_RAW:
		break;

	case SOL_ICMPV6:
		if (inet_sk(sk)->inet_num != IPPROTO_ICMPV6)
			return -EOPNOTSUPP;
		return rawv6_seticmpfilter(sk, level, optname, optval, optlen);
	case SOL_IPV6:
		if (optname == IPV6_CHECKSUM)
			break;
	default:
		return ipv6_setsockopt(sk, level, optname, optval, optlen);
	}

	return do_rawv6_setsockopt(sk, level, optname, optval, optlen);
}

#ifdef CONFIG_COMPAT
static int compat_rawv6_setsockopt(struct sock *sk, int level, int optname,
				   char __user *optval, unsigned int optlen)
{
	switch (level) {
	case SOL_RAW:
		break;
	case SOL_ICMPV6:
		if (inet_sk(sk)->inet_num != IPPROTO_ICMPV6)
			return -EOPNOTSUPP;
		return rawv6_seticmpfilter(sk, level, optname, optval, optlen);
	case SOL_IPV6:
		if (optname == IPV6_CHECKSUM)
			break;
	default:
		return compat_ipv6_setsockopt(sk, level, optname,
					      optval, optlen);
	}
	return do_rawv6_setsockopt(sk, level, optname, optval, optlen);
}
#endif

static int do_rawv6_getsockopt(struct sock *sk, int level, int optname,
			    char __user *optval, int __user *optlen)
{
	struct raw6_sock *rp = raw6_sk(sk);
	int val, len;

	if (get_user(len,optlen))
		return -EFAULT;

	switch (optname) {
	case IPV6_CHECKSUM:
		/*
 * We allow getsockopt() for IPPROTO_IPV6-level
 * IPV6_CHECKSUM socket option on ICMPv6 sockets
 * since RFC3542 is silent about it.
 */
		if (rp->checksum == 0)
			val = -1;
		else
			val = rp->offset;
		break;

	default:
		return -ENOPROTOOPT;
	}

	len = min_t(unsigned int, sizeof(int), len);

	if (put_user(len, optlen))
		return -EFAULT;
	if (copy_to_user(optval,&val,len))
		return -EFAULT;
	return 0;
}

static int rawv6_getsockopt(struct sock *sk, int level, int optname,
			  char __user *optval, int __user *optlen)
{
	switch (level) {
	case SOL_RAW:
		break;

	case SOL_ICMPV6:
		if (inet_sk(sk)->inet_num != IPPROTO_ICMPV6)
			return -EOPNOTSUPP;
		return rawv6_geticmpfilter(sk, level, optname, optval, optlen);
	case SOL_IPV6:
		if (optname == IPV6_CHECKSUM)
			break;
	default:
		return ipv6_getsockopt(sk, level, optname, optval, optlen);
	}

	return do_rawv6_getsockopt(sk, level, optname, optval, optlen);
}

#ifdef CONFIG_COMPAT
static int compat_rawv6_getsockopt(struct sock *sk, int level, int optname,
				   char __user *optval, int __user *optlen)
{
	switch (level) {
	case SOL_RAW:
		break;
	case SOL_ICMPV6:
		if (inet_sk(sk)->inet_num != IPPROTO_ICMPV6)
			return -EOPNOTSUPP;
		return rawv6_geticmpfilter(sk, level, optname, optval, optlen);
	case SOL_IPV6:
		if (optname == IPV6_CHECKSUM)
			break;
	default:
		return compat_ipv6_getsockopt(sk, level, optname,
					      optval, optlen);
	}
	return do_rawv6_getsockopt(sk, level, optname, optval, optlen);
}
#endif

static int rawv6_ioctl(struct sock *sk, int cmd, unsigned long arg)
{
	switch (cmd) {
	case SIOCOUTQ: {
		int amount = sk_wmem_alloc_get(sk);

		return put_user(amount, (int __user *)arg);
	}
	case SIOCINQ: {
		struct sk_buff *skb;
		int amount = 0;

		spin_lock_bh(&sk->sk_receive_queue.lock);
		skb = skb_peek(&sk->sk_receive_queue);
		if (skb != NULL)
			amount = skb_tail_pointer(skb) -
				skb_transport_header(skb);
		spin_unlock_bh(&sk->sk_receive_queue.lock);
		return put_user(amount, (int __user *)arg);
	}

	default:
#ifdef CONFIG_IPV6_MROUTE
		return ip6mr_ioctl(sk, cmd, (void __user *)arg);
#else
		return -ENOIOCTLCMD;
#endif
	}
}

#ifdef CONFIG_COMPAT
static int compat_rawv6_ioctl(struct sock *sk, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case SIOCOUTQ:
	case SIOCINQ:
		return -ENOIOCTLCMD;
	default:
#ifdef CONFIG_IPV6_MROUTE
		return ip6mr_compat_ioctl(sk, cmd, compat_ptr(arg));
#else
		return -ENOIOCTLCMD;
#endif
	}
}
#endif

static void rawv6_close(struct sock *sk, long timeout)
{
	if (inet_sk(sk)->inet_num == IPPROTO_RAW)
		ip6_ra_control(sk, -1);
	ip6mr_sk_done(sk);
	sk_common_release(sk);
}

static void raw6_destroy(struct sock *sk)
{
	lock_sock(sk);
	ip6_flush_pending_frames(sk);
	release_sock(sk);

	inet6_destroy_sock(sk);
}

static int rawv6_init_sk(struct sock *sk)
{
	struct raw6_sock *rp = raw6_sk(sk);

	switch (inet_sk(sk)->inet_num) {
	case IPPROTO_ICMPV6:
		rp->checksum = 1;
		rp->offset   = 2;
		break;
	case IPPROTO_MH:
		rp->checksum = 1;
		rp->offset   = 4;
		break;
	default:
		break;
	}
	return 0;
}

struct proto rawv6_prot = {
	.name		   = "RAWv6",
	.owner		   = THIS_MODULE,
	.close		   = rawv6_close,
	.destroy	   = raw6_destroy,
	.connect	   = ip6_datagram_connect,
	.disconnect	   = udp_disconnect,
	.ioctl		   = rawv6_ioctl,
	.init		   = rawv6_init_sk,
	.setsockopt	   = rawv6_setsockopt,
	.getsockopt	   = rawv6_getsockopt,
	.sendmsg	   = rawv6_sendmsg,
	.recvmsg	   = rawv6_recvmsg,
	.bind		   = rawv6_bind,
	.backlog_rcv	   = rawv6_rcv_skb,
	.hash		   = raw_hash_sk,
	.unhash		   = raw_unhash_sk,
	.obj_size	   = sizeof(struct raw6_sock),
	.h.raw_hash	   = &raw_v6_hashinfo,
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_rawv6_setsockopt,
	.compat_getsockopt = compat_rawv6_getsockopt,
	.compat_ioctl	   = compat_rawv6_ioctl,
#endif
};

#ifdef CONFIG_PROC_FS
static int raw6_seq_show(struct seq_file *seq, void *v)
{
	if (v == SEQ_START_TOKEN) {
		seq_puts(seq, IPV6_SEQ_DGRAM_HEADER);
	} else {
		struct sock *sp = v;
		__u16 srcp  = inet_sk(sp)->inet_num;
		ip6_dgram_sock_seq_show(seq, v, srcp, 0,
					raw_seq_private(seq)->bucket);
	}
	return 0;
}

static const struct seq_operations raw6_seq_ops = {
	.start =	raw_seq_start,
	.next =		raw_seq_next,
	.stop =		raw_seq_stop,
	.show =		raw6_seq_show,
};

static int raw6_seq_open(struct inode *inode, struct file *file)
{
	return raw_seq_open(inode, file, &raw_v6_hashinfo, &raw6_seq_ops);
}

static const struct file_operations raw6_seq_fops = {
	.owner =	THIS_MODULE,
	.open =		raw6_seq_open,
	.read =		seq_read,
	.llseek =	seq_lseek,
	.release =	seq_release_net,
};

static int __net_init raw6_init_net(struct net *net)
{
	if (!proc_create("raw6", S_IRUGO, net->proc_net, &raw6_seq_fops))
		return -ENOMEM;

	return 0;
}

static void __net_exit raw6_exit_net(struct net *net)
{
	remove_proc_entry("raw6", net->proc_net);
}

static struct pernet_operations raw6_net_ops = {
	.init = raw6_init_net,
	.exit = raw6_exit_net,
};

int __init raw6_proc_init(void)
{
	return register_pernet_subsys(&raw6_net_ops);
}

void raw6_proc_exit(void)
{
	unregister_pernet_subsys(&raw6_net_ops);
}
#endif	/* CONFIG_PROC_FS */

/* Same as inet6_dgram_ops, sans udp_poll. */
static const struct proto_ops inet6_sockraw_ops = {
	.family		   = PF_INET6,
	.owner		   = THIS_MODULE,
	.release	   = inet6_release,
	.bind		   = inet6_bind,
	.connect	   = inet_dgram_connect,	/* ok */
	.socketpair	   = sock_no_socketpair,	/* a do nothing */
	.accept		   = sock_no_accept,		/* a do nothing */
	.getname	   = inet6_getname,
	.poll		   = datagram_poll,		/* ok */
	.ioctl		   = inet6_ioctl,		/* must change */
	.listen		   = sock_no_listen,		/* ok */
	.shutdown	   = inet_shutdown,		/* ok */
	.setsockopt	   = sock_common_setsockopt,	/* ok */
	.getsockopt	   = sock_common_getsockopt,	/* ok */
	.sendmsg	   = inet_sendmsg,		/* ok */
	.recvmsg	   = sock_common_recvmsg,	/* ok */
	.mmap		   = sock_no_mmap,
	.sendpage	   = sock_no_sendpage,
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_sock_common_setsockopt,
	.compat_getsockopt = compat_sock_common_getsockopt,
#endif
};

static struct inet_protosw rawv6_protosw = {
	.type		= SOCK_RAW,
	.protocol	= IPPROTO_IP,	/* wild card */
	.prot		= &rawv6_prot,
	.ops		= &inet6_sockraw_ops,
	.no_check	= UDP_CSUM_DEFAULT,
	.flags		= INET_PROTOSW_REUSE,
};

int __init rawv6_init(void)
{
	int ret;

	ret = inet6_register_protosw(&rawv6_protosw);
	if (ret)
		goto out;
out:
	return ret;
}

void rawv6_exit(void)
{
	inet6_unregister_protosw(&rawv6_protosw);
}