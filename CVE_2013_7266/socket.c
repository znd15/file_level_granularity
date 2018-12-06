

/*
 *
 * Author Karsten Keil <kkeil@novell.com>
 *
 * Copyright 2008 by Karsten Keil <kkeil@novell.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 */

#include <linux/mISDNif.h>
#include <linux/slab.h>
#include <linux/export.h>
#include "core.h"

static u_int	*debug;

static struct proto mISDN_proto = {
	.name		= "misdn",
	.owner		= THIS_MODULE,
	.obj_size	= sizeof(struct mISDN_sock)
};

#define _pms(sk) ((struct mISDN_sock *)sk)

static struct mISDN_sock_list	data_sockets = {
	.lock = __RW_LOCK_UNLOCKED(data_sockets.lock)
};

static struct mISDN_sock_list	base_sockets = {
	.lock = __RW_LOCK_UNLOCKED(base_sockets.lock)
};

#define L2_HEADER_LEN 4

static inline struct sk_buff *
_l2_alloc_skb(unsigned int len, gfp_t gfp_mask)
{
	struct sk_buff  *skb;

	skb = alloc_skb(len + L2_HEADER_LEN, gfp_mask);
	if (likely(skb))
		skb_reserve(skb, L2_HEADER_LEN);
	return skb;
}

static void
mISDN_sock_link(struct mISDN_sock_list *l, struct sock *sk)
{
	write_lock_bh(&l->lock);
	sk_add_node(sk, &l->head);
	write_unlock_bh(&l->lock);
}

static void mISDN_sock_unlink(struct mISDN_sock_list *l, struct sock *sk)
{
	write_lock_bh(&l->lock);
	sk_del_node_init(sk);
	write_unlock_bh(&l->lock);
}

static int
mISDN_send(struct mISDNchannel *ch, struct sk_buff *skb)
{
	struct mISDN_sock *msk;
	int	err;

	msk = container_of(ch, struct mISDN_sock, ch);
	if (*debug & DEBUG_SOCKET)
		printk(KERN_DEBUG "%s len %d %p\n", __func__, skb->len, skb);
	if (msk->sk.sk_state == MISDN_CLOSED)
		return -EUNATCH;
	__net_timestamp(skb);
	err = sock_queue_rcv_skb(&msk->sk, skb);
	if (err)
		printk(KERN_WARNING "%s: error %d\n", __func__, err);
	return err;
}

static int
mISDN_ctrl(struct mISDNchannel *ch, u_int cmd, void *arg)
{
	struct mISDN_sock *msk;

	msk = container_of(ch, struct mISDN_sock, ch);
	if (*debug & DEBUG_SOCKET)
		printk(KERN_DEBUG "%s(%p, %x, %p)\n", __func__, ch, cmd, arg);
	switch (cmd) {
	case CLOSE_CHANNEL:
		msk->sk.sk_state = MISDN_CLOSED;
		break;
	}
	return 0;
}

static inline void
mISDN_sock_cmsg(struct sock *sk, struct msghdr *msg, struct sk_buff *skb)
{
	struct timeval	tv;

	if (_pms(sk)->cmask & MISDN_TIME_STAMP) {
		skb_get_timestamp(skb, &tv);
		put_cmsg(msg, SOL_MISDN, MISDN_TIME_STAMP, sizeof(tv), &tv);
	}
}

static int
mISDN_sock_recvmsg(struct kiocb *iocb, struct socket *sock,
		   struct msghdr *msg, size_t len, int flags)
{
	struct sk_buff		*skb;
	struct sock		*sk = sock->sk;
	struct sockaddr_mISDN	*maddr;

	int		copied, err;

	if (*debug & DEBUG_SOCKET)
		printk(KERN_DEBUG "%s: len %d, flags %x ch.nr %d, proto %x\n",
		       __func__, (int)len, flags, _pms(sk)->ch.nr,
		       sk->sk_protocol);
	if (flags & (MSG_OOB))
		return -EOPNOTSUPP;

	if (sk->sk_state == MISDN_CLOSED)
		return 0;

	skb = skb_recv_datagram(sk, flags, flags & MSG_DONTWAIT, &err);
	if (!skb)
		return err;

	if (msg->msg_namelen >= sizeof(struct sockaddr_mISDN)) {
		msg->msg_namelen = sizeof(struct sockaddr_mISDN);
		maddr = (struct sockaddr_mISDN *)msg->msg_name;
		maddr->family = AF_ISDN;
		maddr->dev = _pms(sk)->dev->id;
		if ((sk->sk_protocol == ISDN_P_LAPD_TE) ||
		    (sk->sk_protocol == ISDN_P_LAPD_NT)) {
			maddr->channel = (mISDN_HEAD_ID(skb) >> 16) & 0xff;
			maddr->tei = (mISDN_HEAD_ID(skb) >> 8) & 0xff;
			maddr->sapi = mISDN_HEAD_ID(skb) & 0xff;
		} else {
			maddr->channel = _pms(sk)->ch.nr;
			maddr->sapi = _pms(sk)->ch.addr & 0xFF;
			maddr->tei = (_pms(sk)->ch.addr >> 8) & 0xFF;
		}
	} else {
		if (msg->msg_namelen)
			printk(KERN_WARNING "%s: too small namelen %d\n",
			       __func__, msg->msg_namelen);
		msg->msg_namelen = 0;
	}

	copied = skb->len + MISDN_HEADER_LEN;
	if (len < copied) {
		if (flags & MSG_PEEK)
			atomic_dec(&skb->users);
		else
			skb_queue_head(&sk->sk_receive_queue, skb);
		return -ENOSPC;
	}
	memcpy(skb_push(skb, MISDN_HEADER_LEN), mISDN_HEAD_P(skb),
	       MISDN_HEADER_LEN);

	err = skb_copy_datagram_iovec(skb, 0, msg->msg_iov, copied);

	mISDN_sock_cmsg(sk, msg, skb);

	skb_free_datagram(sk, skb);

	return err ? : copied;
}

static int
mISDN_sock_sendmsg(struct kiocb *iocb, struct socket *sock,
		   struct msghdr *msg, size_t len)
{
	struct sock		*sk = sock->sk;
	struct sk_buff		*skb;
	int			err = -ENOMEM;
	struct sockaddr_mISDN	*maddr;

	if (*debug & DEBUG_SOCKET)
		printk(KERN_DEBUG "%s: len %d flags %x ch %d proto %x\n",
		       __func__, (int)len, msg->msg_flags, _pms(sk)->ch.nr,
		       sk->sk_protocol);

	if (msg->msg_flags & MSG_OOB)
		return -EOPNOTSUPP;

	if (msg->msg_flags & ~(MSG_DONTWAIT | MSG_NOSIGNAL | MSG_ERRQUEUE))
		return -EINVAL;

	if (len < MISDN_HEADER_LEN)
		return -EINVAL;

	if (sk->sk_state != MISDN_BOUND)
		return -EBADFD;

	lock_sock(sk);

	skb = _l2_alloc_skb(len, GFP_KERNEL);
	if (!skb)
		goto done;

	if (memcpy_fromiovec(skb_put(skb, len), msg->msg_iov, len)) {
		err = -EFAULT;
		goto done;
	}

	memcpy(mISDN_HEAD_P(skb), skb->data, MISDN_HEADER_LEN);
	skb_pull(skb, MISDN_HEADER_LEN);

	if (msg->msg_namelen >= sizeof(struct sockaddr_mISDN)) {
		/* if we have a address, we use it */
		maddr = (struct sockaddr_mISDN *)msg->msg_name;
		mISDN_HEAD_ID(skb) = maddr->channel;
	} else { /* use default for L2 messages */
		if ((sk->sk_protocol == ISDN_P_LAPD_TE) ||
		    (sk->sk_protocol == ISDN_P_LAPD_NT))
			mISDN_HEAD_ID(skb) = _pms(sk)->ch.nr;
	}

	if (*debug & DEBUG_SOCKET)
		printk(KERN_DEBUG "%s: ID:%x\n",
		       __func__, mISDN_HEAD_ID(skb));

	err = -ENODEV;
	if (!_pms(sk)->ch.peer)
		goto done;
	err = _pms(sk)->ch.recv(_pms(sk)->ch.peer, skb);
	if (err)
		goto done;
	else {
		skb = NULL;
		err = len;
	}

done:
	if (skb)
		kfree_skb(skb);
	release_sock(sk);
	return err;
}

static int
data_sock_release(struct socket *sock)
{
	struct sock *sk = sock->sk;

	if (*debug & DEBUG_SOCKET)
		printk(KERN_DEBUG "%s(%p) sk=%p\n", __func__, sock, sk);
	if (!sk)
		return 0;
	switch (sk->sk_protocol) {
	case ISDN_P_TE_S0:
	case ISDN_P_NT_S0:
	case ISDN_P_TE_E1:
	case ISDN_P_NT_E1:
		if (sk->sk_state == MISDN_BOUND)
			delete_channel(&_pms(sk)->ch);
		else
			mISDN_sock_unlink(&data_sockets, sk);
		break;
	case ISDN_P_LAPD_TE:
	case ISDN_P_LAPD_NT:
	case ISDN_P_B_RAW:
	case ISDN_P_B_HDLC:
	case ISDN_P_B_X75SLP:
	case ISDN_P_B_L2DTMF:
	case ISDN_P_B_L2DSP:
	case ISDN_P_B_L2DSPHDLC:
		delete_channel(&_pms(sk)->ch);
		mISDN_sock_unlink(&data_sockets, sk);
		break;
	}

	lock_sock(sk);

	sock_orphan(sk);
	skb_queue_purge(&sk->sk_receive_queue);

	release_sock(sk);
	sock_put(sk);

	return 0;
}

static int
data_sock_ioctl_bound(struct sock *sk, unsigned int cmd, void __user *p)
{
	struct mISDN_ctrl_req	cq;
	int			err = -EINVAL, val[2];
	struct mISDNchannel	*bchan, *next;

	lock_sock(sk);
	if (!_pms(sk)->dev) {
		err = -ENODEV;
		goto done;
	}
	switch (cmd) {
	case IMCTRLREQ:
		if (copy_from_user(&cq, p, sizeof(cq))) {
			err = -EFAULT;
			break;
		}
		if ((sk->sk_protocol & ~ISDN_P_B_MASK) == ISDN_P_B_START) {
			list_for_each_entry_safe(bchan, next,
						 &_pms(sk)->dev->bchannels, list) {
				if (bchan->nr == cq.channel) {
					err = bchan->ctrl(bchan,
							  CONTROL_CHANNEL, &cq);
					break;
				}
			}
		} else
			err = _pms(sk)->dev->D.ctrl(&_pms(sk)->dev->D,
						    CONTROL_CHANNEL, &cq);
		if (err)
			break;
		if (copy_to_user(p, &cq, sizeof(cq)))
			err = -EFAULT;
		break;
	case IMCLEAR_L2:
		if (sk->sk_protocol != ISDN_P_LAPD_NT) {
			err = -EINVAL;
			break;
		}
		val[0] = cmd;
		if (get_user(val[1], (int __user *)p)) {
			err = -EFAULT;
			break;
		}
		err = _pms(sk)->dev->teimgr->ctrl(_pms(sk)->dev->teimgr,
						  CONTROL_CHANNEL, val);
		break;
	case IMHOLD_L1:
		if (sk->sk_protocol != ISDN_P_LAPD_NT
		    && sk->sk_protocol != ISDN_P_LAPD_TE) {
			err = -EINVAL;
			break;
		}
		val[0] = cmd;
		if (get_user(val[1], (int __user *)p)) {
			err = -EFAULT;
			break;
		}
		err = _pms(sk)->dev->teimgr->ctrl(_pms(sk)->dev->teimgr,
						  CONTROL_CHANNEL, val);
		break;
	default:
		err = -EINVAL;
		break;
	}
done:
	release_sock(sk);
	return err;
}

static int
data_sock_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	int			err = 0, id;
	struct sock		*sk = sock->sk;
	struct mISDNdevice	*dev;
	struct mISDNversion	ver;

	switch (cmd) {
	case IMGETVERSION:
		ver.major = MISDN_MAJOR_VERSION;
		ver.minor = MISDN_MINOR_VERSION;
		ver.release = MISDN_RELEASE;
		if (copy_to_user((void __user *)arg, &ver, sizeof(ver)))
			err = -EFAULT;
		break;
	case IMGETCOUNT:
		id = get_mdevice_count();
		if (put_user(id, (int __user *)arg))
			err = -EFAULT;
		break;
	case IMGETDEVINFO:
		if (get_user(id, (int __user *)arg)) {
			err = -EFAULT;
			break;
		}
		dev = get_mdevice(id);
		if (dev) {
			struct mISDN_devinfo di;

			memset(&di, 0, sizeof(di));
			di.id = dev->id;
			di.Dprotocols = dev->Dprotocols;
			di.Bprotocols = dev->Bprotocols | get_all_Bprotocols();
			di.protocol = dev->D.protocol;
			memcpy(di.channelmap, dev->channelmap,
			       sizeof(di.channelmap));
			di.nrbchan = dev->nrbchan;
			strcpy(di.name, dev_name(&dev->dev));
			if (copy_to_user((void __user *)arg, &di, sizeof(di)))
				err = -EFAULT;
		} else
			err = -ENODEV;
		break;
	default:
		if (sk->sk_state == MISDN_BOUND)
			err = data_sock_ioctl_bound(sk, cmd,
						    (void __user *)arg);
		else
			err = -ENOTCONN;
	}
	return err;
}

static int data_sock_setsockopt(struct socket *sock, int level, int optname,
				char __user *optval, unsigned int len)
{
	struct sock *sk = sock->sk;
	int err = 0, opt = 0;

	if (*debug & DEBUG_SOCKET)
		printk(KERN_DEBUG "%s(%p, %d, %x, %p, %d)\n", __func__, sock,
		       level, optname, optval, len);

	lock_sock(sk);

	switch (optname) {
	case MISDN_TIME_STAMP:
		if (get_user(opt, (int __user *)optval)) {
			err = -EFAULT;
			break;
		}

		if (opt)
			_pms(sk)->cmask |= MISDN_TIME_STAMP;
		else
			_pms(sk)->cmask &= ~MISDN_TIME_STAMP;
		break;
	default:
		err = -ENOPROTOOPT;
		break;
	}
	release_sock(sk);
	return err;
}

static int data_sock_getsockopt(struct socket *sock, int level, int optname,
				char __user *optval, int __user *optlen)
{
	struct sock *sk = sock->sk;
	int len, opt;

	if (get_user(len, optlen))
		return -EFAULT;

	if (len != sizeof(char))
		return -EINVAL;

	switch (optname) {
	case MISDN_TIME_STAMP:
		if (_pms(sk)->cmask & MISDN_TIME_STAMP)
			opt = 1;
		else
			opt = 0;

		if (put_user(opt, optval))
			return -EFAULT;
		break;
	default:
		return -ENOPROTOOPT;
	}

	return 0;
}

static int
data_sock_bind(struct socket *sock, struct sockaddr *addr, int addr_len)
{
	struct sockaddr_mISDN *maddr = (struct sockaddr_mISDN *) addr;
	struct sock *sk = sock->sk;
	struct sock *csk;
	int err = 0;

	if (*debug & DEBUG_SOCKET)
		printk(KERN_DEBUG "%s(%p) sk=%p\n", __func__, sock, sk);
	if (addr_len != sizeof(struct sockaddr_mISDN))
		return -EINVAL;
	if (!maddr || maddr->family != AF_ISDN)
		return -EINVAL;

	lock_sock(sk);

	if (_pms(sk)->dev) {
		err = -EALREADY;
		goto done;
	}
	_pms(sk)->dev = get_mdevice(maddr->dev);
	if (!_pms(sk)->dev) {
		err = -ENODEV;
		goto done;
	}

	if (sk->sk_protocol < ISDN_P_B_START) {
		read_lock_bh(&data_sockets.lock);
		sk_for_each(csk, &data_sockets.head) {
			if (sk == csk)
				continue;
			if (_pms(csk)->dev != _pms(sk)->dev)
				continue;
			if (csk->sk_protocol >= ISDN_P_B_START)
				continue;
			if (IS_ISDN_P_TE(csk->sk_protocol)
			    == IS_ISDN_P_TE(sk->sk_protocol))
				continue;
			read_unlock_bh(&data_sockets.lock);
			err = -EBUSY;
			goto done;
		}
		read_unlock_bh(&data_sockets.lock);
	}

	_pms(sk)->ch.send = mISDN_send;
	_pms(sk)->ch.ctrl = mISDN_ctrl;

	switch (sk->sk_protocol) {
	case ISDN_P_TE_S0:
	case ISDN_P_NT_S0:
	case ISDN_P_TE_E1:
	case ISDN_P_NT_E1:
		mISDN_sock_unlink(&data_sockets, sk);
		err = connect_layer1(_pms(sk)->dev, &_pms(sk)->ch,
				     sk->sk_protocol, maddr);
		if (err)
			mISDN_sock_link(&data_sockets, sk);
		break;
	case ISDN_P_LAPD_TE:
	case ISDN_P_LAPD_NT:
		err = create_l2entity(_pms(sk)->dev, &_pms(sk)->ch,
				      sk->sk_protocol, maddr);
		break;
	case ISDN_P_B_RAW:
	case ISDN_P_B_HDLC:
	case ISDN_P_B_X75SLP:
	case ISDN_P_B_L2DTMF:
	case ISDN_P_B_L2DSP:
	case ISDN_P_B_L2DSPHDLC:
		err = connect_Bstack(_pms(sk)->dev, &_pms(sk)->ch,
				     sk->sk_protocol, maddr);
		break;
	default:
		err = -EPROTONOSUPPORT;
	}
	if (err)
		goto done;
	sk->sk_state = MISDN_BOUND;
	_pms(sk)->ch.protocol = sk->sk_protocol;

done:
	release_sock(sk);
	return err;
}

static int
data_sock_getname(struct socket *sock, struct sockaddr *addr,
		  int *addr_len, int peer)
{
	struct sockaddr_mISDN	*maddr = (struct sockaddr_mISDN *) addr;
	struct sock		*sk = sock->sk;

	if (!_pms(sk)->dev)
		return -EBADFD;

	lock_sock(sk);

	*addr_len = sizeof(*maddr);
	maddr->family = AF_ISDN;
	maddr->dev = _pms(sk)->dev->id;
	maddr->channel = _pms(sk)->ch.nr;
	maddr->sapi = _pms(sk)->ch.addr & 0xff;
	maddr->tei = (_pms(sk)->ch.addr >> 8) & 0xff;
	release_sock(sk);
	return 0;
}

static const struct proto_ops data_sock_ops = {
	.family		= PF_ISDN,
	.owner		= THIS_MODULE,
	.release	= data_sock_release,
	.ioctl		= data_sock_ioctl,
	.bind		= data_sock_bind,
	.getname	= data_sock_getname,
	.sendmsg	= mISDN_sock_sendmsg,
	.recvmsg	= mISDN_sock_recvmsg,
	.poll		= datagram_poll,
	.listen		= sock_no_listen,
	.shutdown	= sock_no_shutdown,
	.setsockopt	= data_sock_setsockopt,
	.getsockopt	= data_sock_getsockopt,
	.connect	= sock_no_connect,
	.socketpair	= sock_no_socketpair,
	.accept		= sock_no_accept,
	.mmap		= sock_no_mmap
};

static int
data_sock_create(struct net *net, struct socket *sock, int protocol)
{
	struct sock *sk;

	if (sock->type != SOCK_DGRAM)
		return -ESOCKTNOSUPPORT;

	sk = sk_alloc(net, PF_ISDN, GFP_KERNEL, &mISDN_proto);
	if (!sk)
		return -ENOMEM;

	sock_init_data(sock, sk);

	sock->ops = &data_sock_ops;
	sock->state = SS_UNCONNECTED;
	sock_reset_flag(sk, SOCK_ZAPPED);

	sk->sk_protocol = protocol;
	sk->sk_state    = MISDN_OPEN;
	mISDN_sock_link(&data_sockets, sk);

	return 0;
}

static int
base_sock_release(struct socket *sock)
{
	struct sock *sk = sock->sk;

	printk(KERN_DEBUG "%s(%p) sk=%p\n", __func__, sock, sk);
	if (!sk)
		return 0;

	mISDN_sock_unlink(&base_sockets, sk);
	sock_orphan(sk);
	sock_put(sk);

	return 0;
}

static int
base_sock_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	int			err = 0, id;
	struct mISDNdevice	*dev;
	struct mISDNversion	ver;

	switch (cmd) {
	case IMGETVERSION:
		ver.major = MISDN_MAJOR_VERSION;
		ver.minor = MISDN_MINOR_VERSION;
		ver.release = MISDN_RELEASE;
		if (copy_to_user((void __user *)arg, &ver, sizeof(ver)))
			err = -EFAULT;
		break;
	case IMGETCOUNT:
		id = get_mdevice_count();
		if (put_user(id, (int __user *)arg))
			err = -EFAULT;
		break;
	case IMGETDEVINFO:
		if (get_user(id, (int __user *)arg)) {
			err = -EFAULT;
			break;
		}
		dev = get_mdevice(id);
		if (dev) {
			struct mISDN_devinfo di;

			memset(&di, 0, sizeof(di));
			di.id = dev->id;
			di.Dprotocols = dev->Dprotocols;
			di.Bprotocols = dev->Bprotocols | get_all_Bprotocols();
			di.protocol = dev->D.protocol;
			memcpy(di.channelmap, dev->channelmap,
			       sizeof(di.channelmap));
			di.nrbchan = dev->nrbchan;
			strcpy(di.name, dev_name(&dev->dev));
			if (copy_to_user((void __user *)arg, &di, sizeof(di)))
				err = -EFAULT;
		} else
			err = -ENODEV;
		break;
	case IMSETDEVNAME:
	{
		struct mISDN_devrename dn;
		if (copy_from_user(&dn, (void __user *)arg,
				   sizeof(dn))) {
			err = -EFAULT;
			break;
		}
		dev = get_mdevice(dn.id);
		if (dev)
			err = device_rename(&dev->dev, dn.name);
		else
			err = -ENODEV;
	}
	break;
	default:
		err = -EINVAL;
	}
	return err;
}

static int
base_sock_bind(struct socket *sock, struct sockaddr *addr, int addr_len)
{
	struct sockaddr_mISDN *maddr = (struct sockaddr_mISDN *) addr;
	struct sock *sk = sock->sk;
	int err = 0;

	if (!maddr || maddr->family != AF_ISDN)
		return -EINVAL;

	lock_sock(sk);

	if (_pms(sk)->dev) {
		err = -EALREADY;
		goto done;
	}

	_pms(sk)->dev = get_mdevice(maddr->dev);
	if (!_pms(sk)->dev) {
		err = -ENODEV;
		goto done;
	}
	sk->sk_state = MISDN_BOUND;

done:
	release_sock(sk);
	return err;
}

static const struct proto_ops base_sock_ops = {
	.family		= PF_ISDN,
	.owner		= THIS_MODULE,
	.release	= base_sock_release,
	.ioctl		= base_sock_ioctl,
	.bind		= base_sock_bind,
	.getname	= sock_no_getname,
	.sendmsg	= sock_no_sendmsg,
	.recvmsg	= sock_no_recvmsg,
	.poll		= sock_no_poll,
	.listen		= sock_no_listen,
	.shutdown	= sock_no_shutdown,
	.setsockopt	= sock_no_setsockopt,
	.getsockopt	= sock_no_getsockopt,
	.connect	= sock_no_connect,
	.socketpair	= sock_no_socketpair,
	.accept		= sock_no_accept,
	.mmap		= sock_no_mmap
};


static int
base_sock_create(struct net *net, struct socket *sock, int protocol)
{
	struct sock *sk;

	if (sock->type != SOCK_RAW)
		return -ESOCKTNOSUPPORT;

	sk = sk_alloc(net, PF_ISDN, GFP_KERNEL, &mISDN_proto);
	if (!sk)
		return -ENOMEM;

	sock_init_data(sock, sk);
	sock->ops = &base_sock_ops;
	sock->state = SS_UNCONNECTED;
	sock_reset_flag(sk, SOCK_ZAPPED);
	sk->sk_protocol = protocol;
	sk->sk_state    = MISDN_OPEN;
	mISDN_sock_link(&base_sockets, sk);

	return 0;
}

static int
mISDN_sock_create(struct net *net, struct socket *sock, int proto, int kern)
{
	int err = -EPROTONOSUPPORT;

	switch (proto) {
	case ISDN_P_BASE:
		err = base_sock_create(net, sock, proto);
		break;
	case ISDN_P_TE_S0:
	case ISDN_P_NT_S0:
	case ISDN_P_TE_E1:
	case ISDN_P_NT_E1:
	case ISDN_P_LAPD_TE:
	case ISDN_P_LAPD_NT:
	case ISDN_P_B_RAW:
	case ISDN_P_B_HDLC:
	case ISDN_P_B_X75SLP:
	case ISDN_P_B_L2DTMF:
	case ISDN_P_B_L2DSP:
	case ISDN_P_B_L2DSPHDLC:
		err = data_sock_create(net, sock, proto);
		break;
	default:
		return err;
	}

	return err;
}

static const struct net_proto_family mISDN_sock_family_ops = {
	.owner  = THIS_MODULE,
	.family = PF_ISDN,
	.create = mISDN_sock_create,
};

int
misdn_sock_init(u_int *deb)
{
	int err;

	debug = deb;
	err = sock_register(&mISDN_sock_family_ops);
	if (err)
		printk(KERN_ERR "%s: error(%d)\n", __func__, err);
	return err;
}

void
misdn_sock_cleanup(void)
{
	sock_unregister(PF_ISDN);
}

/*
 * NET An implementation of the SOCKET network access protocol.
 *
 * Version: @(#)socket.c 1.1.93 18/02/95
 *
 * Authors: Orest Zborowski, <obz@Kodak.COM>
 * Ross Biro
 * Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 * Fixes:
 * Anonymous : NOTSOCK/BADF cleanup. Error fix in
 * shutdown()
 * Alan Cox : verify_area() fixes
 * Alan Cox : Removed DDI
 * Jonathan Kamens : SOCK_DGRAM reconnect bug
 * Alan Cox : Moved a load of checks to the very
 * top level.
 * Alan Cox : Move address structures to/from user
 * mode above the protocol layers.
 * Rob Janssen : Allow 0 length sends.
 * Alan Cox : Asynchronous I/O support (cribbed from the
 * tty drivers).
 * Niibe Yutaka : Asynchronous I/O for writes (4.4BSD style)
 * Jeff Uphoff : Made max number of sockets command-line
 * configurable.
 * Matti Aarnio : Made the number of sockets dynamic,
 * to be allocated when needed, and mr.
 * Uphoff's max is used as max to be
 * allowed to allocate.
 * Linus : Argh. removed all the socket allocation
 * altogether: it's in the inode now.
 * Alan Cox : Made sock_alloc()/sock_release() public
 * for NetROM and future kernel nfsd type
 * stuff.
 * Alan Cox : sendmsg/recvmsg basics.
 * Tom Dyas : Export net symbols.
 * Marcin Dalecki : Fixed problems with CONFIG_NET="n".
 * Alan Cox : Added thread locking to sys_* calls
 * for sockets. May have errors at the
 * moment.
 * Kevin Buhr : Fixed the dumb errors in the above.
 * Andi Kleen : Some small cleanups, optimizations,
 * and fixed a copy_from_user() bug.
 * Tigran Aivazian : sys_send(args) calls sys_sendto(args, NULL, 0)
 * Tigran Aivazian : Made listen(2) backlog sanity checks
 * protocol-independent
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 *
 * This module is effectively the top level interface to the BSD socket
 * paradigm.
 *
 * Based upon Swansea University Computer Society NET3.039
 */

#include <linux/mm.h>
#include <linux/socket.h>
#include <linux/file.h>
#include <linux/net.h>
#include <linux/interrupt.h>
#include <linux/thread_info.h>
#include <linux/rcupdate.h>
#include <linux/netdevice.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/mutex.h>
#include <linux/if_bridge.h>
#include <linux/if_frad.h>
#include <linux/if_vlan.h>
#include <linux/init.h>
#include <linux/poll.h>
#include <linux/cache.h>
#include <linux/module.h>
#include <linux/highmem.h>
#include <linux/mount.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/compat.h>
#include <linux/kmod.h>
#include <linux/audit.h>
#include <linux/wireless.h>
#include <linux/nsproxy.h>
#include <linux/magic.h>
#include <linux/slab.h>
#include <linux/xattr.h>

#include <asm/uaccess.h>
#include <asm/unistd.h>

#include <net/compat.h>
#include <net/wext.h>
#include <net/cls_cgroup.h>

#include <net/sock.h>
#include <linux/netfilter.h>

#include <linux/if_tun.h>
#include <linux/ipv6_route.h>
#include <linux/route.h>
#include <linux/sockios.h>
#include <linux/atalk.h>
#include <net/busy_poll.h>

#ifdef CONFIG_NET_RX_BUSY_POLL
unsigned int sysctl_net_busy_read __read_mostly;
unsigned int sysctl_net_busy_poll __read_mostly;
#endif

static int sock_no_open(struct inode *irrelevant, struct file *dontcare);
static ssize_t sock_aio_read(struct kiocb *iocb, const struct iovec *iov,
			 unsigned long nr_segs, loff_t pos);
static ssize_t sock_aio_write(struct kiocb *iocb, const struct iovec *iov,
			  unsigned long nr_segs, loff_t pos);
static int sock_mmap(struct file *file, struct vm_area_struct *vma);

static int sock_close(struct inode *inode, struct file *file);
static unsigned int sock_poll(struct file *file,
			      struct poll_table_struct *wait);
static long sock_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
#ifdef CONFIG_COMPAT
static long compat_sock_ioctl(struct file *file,
			      unsigned int cmd, unsigned long arg);
#endif
static int sock_fasync(int fd, struct file *filp, int on);
static ssize_t sock_sendpage(struct file *file, struct page *page,
			     int offset, size_t size, loff_t *ppos, int more);
static ssize_t sock_splice_read(struct file *file, loff_t *ppos,
				struct pipe_inode_info *pipe, size_t len,
				unsigned int flags);

/*
 * Socket files have a set of 'special' operations as well as the generic file ones. These don't appear
 * in the operation structures but are done directly via the socketcall() multiplexor.
 */

static const struct file_operations socket_file_ops = {
	.owner =	THIS_MODULE,
	.llseek =	no_llseek,
	.aio_read =	sock_aio_read,
	.aio_write =	sock_aio_write,
	.poll =		sock_poll,
	.unlocked_ioctl = sock_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = compat_sock_ioctl,
#endif
	.mmap =		sock_mmap,
	.open =		sock_no_open,	/* special open code to disallow open via /proc */
	.release =	sock_close,
	.fasync =	sock_fasync,
	.sendpage =	sock_sendpage,
	.splice_write = generic_splice_sendpage,
	.splice_read =	sock_splice_read,
};

/*
 * The protocol list. Each protocol is registered in here.
 */

static DEFINE_SPINLOCK(net_family_lock);
static const struct net_proto_family __rcu *net_families[NPROTO] __read_mostly;

/*
 * Statistics counters of the socket lists
 */

static DEFINE_PER_CPU(int, sockets_in_use);

/*
 * Support routines.
 * Move socket addresses back and forth across the kernel/user
 * divide and look after the messy bits.
 */

/**
 * move_addr_to_kernel - copy a socket address into kernel space
 * @uaddr: Address in user space
 * @kaddr: Address in kernel space
 * @ulen: Length in user space
 *
 * The address is copied into kernel space. If the provided address is
 * too long an error code of -EINVAL is returned. If the copy gives
 * invalid addresses -EFAULT is returned. On a success 0 is returned.
 */

int move_addr_to_kernel(void __user *uaddr, int ulen, struct sockaddr_storage *kaddr)
{
	if (ulen < 0 || ulen > sizeof(struct sockaddr_storage))
		return -EINVAL;
	if (ulen == 0)
		return 0;
	if (copy_from_user(kaddr, uaddr, ulen))
		return -EFAULT;
	return audit_sockaddr(ulen, kaddr);
}

/**
 * move_addr_to_user - copy an address to user space
 * @kaddr: kernel space address
 * @klen: length of address in kernel
 * @uaddr: user space address
 * @ulen: pointer to user length field
 *
 * The value pointed to by ulen on entry is the buffer length available.
 * This is overwritten with the buffer space used. -EINVAL is returned
 * if an overlong buffer is specified or a negative buffer size. -EFAULT
 * is returned if either the buffer or the length field are not
 * accessible.
 * After copying the data up to the limit the user specifies, the true
 * length of the data is written over the length limit the user
 * specified. Zero is returned for a success.
 */

static int move_addr_to_user(struct sockaddr_storage *kaddr, int klen,
			     void __user *uaddr, int __user *ulen)
{
	int err;
	int len;

	err = get_user(len, ulen);
	if (err)
		return err;
	if (len > klen)
		len = klen;
	if (len < 0 || len > sizeof(struct sockaddr_storage))
		return -EINVAL;
	if (len) {
		if (audit_sockaddr(klen, kaddr))
			return -ENOMEM;
		if (copy_to_user(uaddr, kaddr, len))
			return -EFAULT;
	}
	/*
 * "fromlen shall refer to the value before truncation.."
 * 1003.1g
 */
	return __put_user(klen, ulen);
}

static struct kmem_cache *sock_inode_cachep __read_mostly;

static struct inode *sock_alloc_inode(struct super_block *sb)
{
	struct socket_alloc *ei;
	struct socket_wq *wq;

	ei = kmem_cache_alloc(sock_inode_cachep, GFP_KERNEL);
	if (!ei)
		return NULL;
	wq = kmalloc(sizeof(*wq), GFP_KERNEL);
	if (!wq) {
		kmem_cache_free(sock_inode_cachep, ei);
		return NULL;
	}
	init_waitqueue_head(&wq->wait);
	wq->fasync_list = NULL;
	RCU_INIT_POINTER(ei->socket.wq, wq);

	ei->socket.state = SS_UNCONNECTED;
	ei->socket.flags = 0;
	ei->socket.ops = NULL;
	ei->socket.sk = NULL;
	ei->socket.file = NULL;

	return &ei->vfs_inode;
}

static void sock_destroy_inode(struct inode *inode)
{
	struct socket_alloc *ei;
	struct socket_wq *wq;

	ei = container_of(inode, struct socket_alloc, vfs_inode);
	wq = rcu_dereference_protected(ei->socket.wq, 1);
	kfree_rcu(wq, rcu);
	kmem_cache_free(sock_inode_cachep, ei);
}

static void init_once(void *foo)
{
	struct socket_alloc *ei = (struct socket_alloc *)foo;

	inode_init_once(&ei->vfs_inode);
}

static int init_inodecache(void)
{
	sock_inode_cachep = kmem_cache_create("sock_inode_cache",
					      sizeof(struct socket_alloc),
					      0,
					      (SLAB_HWCACHE_ALIGN |
					       SLAB_RECLAIM_ACCOUNT |
					       SLAB_MEM_SPREAD),
					      init_once);
	if (sock_inode_cachep == NULL)
		return -ENOMEM;
	return 0;
}

static const struct super_operations sockfs_ops = {
	.alloc_inode	= sock_alloc_inode,
	.destroy_inode	= sock_destroy_inode,
	.statfs		= simple_statfs,
};

/*
 * sockfs_dname() is called from d_path().
 */
static char *sockfs_dname(struct dentry *dentry, char *buffer, int buflen)
{
	return dynamic_dname(dentry, buffer, buflen, "socket:[%lu]",
				dentry->d_inode->i_ino);
}

static const struct dentry_operations sockfs_dentry_operations = {
	.d_dname  = sockfs_dname,
};

static struct dentry *sockfs_mount(struct file_system_type *fs_type,
			 int flags, const char *dev_name, void *data)
{
	return mount_pseudo(fs_type, "socket:", &sockfs_ops,
		&sockfs_dentry_operations, SOCKFS_MAGIC);
}

static struct vfsmount *sock_mnt __read_mostly;

static struct file_system_type sock_fs_type = {
	.name =		"sockfs",
	.mount =	sockfs_mount,
	.kill_sb =	kill_anon_super,
};

/*
 * Obtains the first available file descriptor and sets it up for use.
 *
 * These functions create file structures and maps them to fd space
 * of the current process. On success it returns file descriptor
 * and file struct implicitly stored in sock->file.
 * Note that another thread may close file descriptor before we return
 * from this function. We use the fact that now we do not refer
 * to socket after mapping. If one day we will need it, this
 * function will increment ref. count on file by 1.
 *
 * In any case returned fd MAY BE not valid!
 * This race condition is unavoidable
 * with shared fd spaces, we cannot solve it inside kernel,
 * but we take care of internal coherence yet.
 */

struct file *sock_alloc_file(struct socket *sock, int flags, const char *dname)
{
	struct qstr name = { .name = "" };
	struct path path;
	struct file *file;

	if (dname) {
		name.name = dname;
		name.len = strlen(name.name);
	} else if (sock->sk) {
		name.name = sock->sk->sk_prot_creator->name;
		name.len = strlen(name.name);
	}
	path.dentry = d_alloc_pseudo(sock_mnt->mnt_sb, &name);
	if (unlikely(!path.dentry))
		return ERR_PTR(-ENOMEM);
	path.mnt = mntget(sock_mnt);

	d_instantiate(path.dentry, SOCK_INODE(sock));
	SOCK_INODE(sock)->i_fop = &socket_file_ops;

	file = alloc_file(&path, FMODE_READ | FMODE_WRITE,
		  &socket_file_ops);
	if (unlikely(IS_ERR(file))) {
		/* drop dentry, keep inode */
		ihold(path.dentry->d_inode);
		path_put(&path);
		return file;
	}

	sock->file = file;
	file->f_flags = O_RDWR | (flags & O_NONBLOCK);
	file->private_data = sock;
	return file;
}
EXPORT_SYMBOL(sock_alloc_file);

static int sock_map_fd(struct socket *sock, int flags)
{
	struct file *newfile;
	int fd = get_unused_fd_flags(flags);
	if (unlikely(fd < 0))
		return fd;

	newfile = sock_alloc_file(sock, flags, NULL);
	if (likely(!IS_ERR(newfile))) {
		fd_install(fd, newfile);
		return fd;
	}

	put_unused_fd(fd);
	return PTR_ERR(newfile);
}

struct socket *sock_from_file(struct file *file, int *err)
{
	if (file->f_op == &socket_file_ops)
		return file->private_data;	/* set in sock_map_fd */

	*err = -ENOTSOCK;
	return NULL;
}
EXPORT_SYMBOL(sock_from_file);

/**
 * sockfd_lookup - Go from a file number to its socket slot
 * @fd: file handle
 * @err: pointer to an error code return
 *
 * The file handle passed in is locked and the socket it is bound
 * too is returned. If an error occurs the err pointer is overwritten
 * with a negative errno code and NULL is returned. The function checks
 * for both invalid handles and passing a handle which is not a socket.
 *
 * On a success the socket object pointer is returned.
 */

struct socket *sockfd_lookup(int fd, int *err)
{
	struct file *file;
	struct socket *sock;

	file = fget(fd);
	if (!file) {
		*err = -EBADF;
		return NULL;
	}

	sock = sock_from_file(file, err);
	if (!sock)
		fput(file);
	return sock;
}
EXPORT_SYMBOL(sockfd_lookup);

static struct socket *sockfd_lookup_light(int fd, int *err, int *fput_needed)
{
	struct file *file;
	struct socket *sock;

	*err = -EBADF;
	file = fget_light(fd, fput_needed);
	if (file) {
		sock = sock_from_file(file, err);
		if (sock)
			return sock;
		fput_light(file, *fput_needed);
	}
	return NULL;
}

#define XATTR_SOCKPROTONAME_SUFFIX "sockprotoname"
#define XATTR_NAME_SOCKPROTONAME (XATTR_SYSTEM_PREFIX XATTR_SOCKPROTONAME_SUFFIX)
#define XATTR_NAME_SOCKPROTONAME_LEN (sizeof(XATTR_NAME_SOCKPROTONAME)-1)
static ssize_t sockfs_getxattr(struct dentry *dentry,
			       const char *name, void *value, size_t size)
{
	const char *proto_name;
	size_t proto_size;
	int error;

	error = -ENODATA;
	if (!strncmp(name, XATTR_NAME_SOCKPROTONAME, XATTR_NAME_SOCKPROTONAME_LEN)) {
		proto_name = dentry->d_name.name;
		proto_size = strlen(proto_name);

		if (value) {
			error = -ERANGE;
			if (proto_size + 1 > size)
				goto out;

			strncpy(value, proto_name, proto_size + 1);
		}
		error = proto_size + 1;
	}

out:
	return error;
}

static ssize_t sockfs_listxattr(struct dentry *dentry, char *buffer,
				size_t size)
{
	ssize_t len;
	ssize_t used = 0;

	len = security_inode_listsecurity(dentry->d_inode, buffer, size);
	if (len < 0)
		return len;
	used += len;
	if (buffer) {
		if (size < used)
			return -ERANGE;
		buffer += len;
	}

	len = (XATTR_NAME_SOCKPROTONAME_LEN + 1);
	used += len;
	if (buffer) {
		if (size < used)
			return -ERANGE;
		memcpy(buffer, XATTR_NAME_SOCKPROTONAME, len);
		buffer += len;
	}

	return used;
}

static const struct inode_operations sockfs_inode_ops = {
	.getxattr = sockfs_getxattr,
	.listxattr = sockfs_listxattr,
};

/**
 * sock_alloc - allocate a socket
 *
 * Allocate a new inode and socket object. The two are bound together
 * and initialised. The socket is then returned. If we are out of inodes
 * NULL is returned.
 */

static struct socket *sock_alloc(void)
{
	struct inode *inode;
	struct socket *sock;

	inode = new_inode_pseudo(sock_mnt->mnt_sb);
	if (!inode)
		return NULL;

	sock = SOCKET_I(inode);

	kmemcheck_annotate_bitfield(sock, type);
	inode->i_ino = get_next_ino();
	inode->i_mode = S_IFSOCK | S_IRWXUGO;
	inode->i_uid = current_fsuid();
	inode->i_gid = current_fsgid();
	inode->i_op = &sockfs_inode_ops;

	this_cpu_add(sockets_in_use, 1);
	return sock;
}

/*
 * In theory you can't get an open on this inode, but /proc provides
 * a back door. Remember to keep it shut otherwise you'll let the
 * creepy crawlies in.
 */

static int sock_no_open(struct inode *irrelevant, struct file *dontcare)
{
	return -ENXIO;
}

const struct file_operations bad_sock_fops = {
	.owner = THIS_MODULE,
	.open = sock_no_open,
	.llseek = noop_llseek,
};

/**
 * sock_release - close a socket
 * @sock: socket to close
 *
 * The socket is released from the protocol stack if it has a release
 * callback, and the inode is then released if the socket is bound to
 * an inode not a file.
 */

void sock_release(struct socket *sock)
{
	if (sock->ops) {
		struct module *owner = sock->ops->owner;

		sock->ops->release(sock);
		sock->ops = NULL;
		module_put(owner);
	}

	if (rcu_dereference_protected(sock->wq, 1)->fasync_list)
		printk(KERN_ERR "sock_release: fasync list not empty!\n");

	if (test_bit(SOCK_EXTERNALLY_ALLOCATED, &sock->flags))
		return;

	this_cpu_sub(sockets_in_use, 1);
	if (!sock->file) {
		iput(SOCK_INODE(sock));
		return;
	}
	sock->file = NULL;
}
EXPORT_SYMBOL(sock_release);

void sock_tx_timestamp(struct sock *sk, __u8 *tx_flags)
{
	*tx_flags = 0;
	if (sock_flag(sk, SOCK_TIMESTAMPING_TX_HARDWARE))
		*tx_flags |= SKBTX_HW_TSTAMP;
	if (sock_flag(sk, SOCK_TIMESTAMPING_TX_SOFTWARE))
		*tx_flags |= SKBTX_SW_TSTAMP;
	if (sock_flag(sk, SOCK_WIFI_STATUS))
		*tx_flags |= SKBTX_WIFI_STATUS;
}
EXPORT_SYMBOL(sock_tx_timestamp);

static inline int __sock_sendmsg_nosec(struct kiocb *iocb, struct socket *sock,
				       struct msghdr *msg, size_t size)
{
	struct sock_iocb *si = kiocb_to_siocb(iocb);

	si->sock = sock;
	si->scm = NULL;
	si->msg = msg;
	si->size = size;

	return sock->ops->sendmsg(iocb, sock, msg, size);
}

static inline int __sock_sendmsg(struct kiocb *iocb, struct socket *sock,
				 struct msghdr *msg, size_t size)
{
	int err = security_socket_sendmsg(sock, msg, size);

	return err ?: __sock_sendmsg_nosec(iocb, sock, msg, size);
}

int sock_sendmsg(struct socket *sock, struct msghdr *msg, size_t size)
{
	struct kiocb iocb;
	struct sock_iocb siocb;
	int ret;

	init_sync_kiocb(&iocb, NULL);
	iocb.private = &siocb;
	ret = __sock_sendmsg(&iocb, sock, msg, size);
	if (-EIOCBQUEUED == ret)
		ret = wait_on_sync_kiocb(&iocb);
	return ret;
}
EXPORT_SYMBOL(sock_sendmsg);

static int sock_sendmsg_nosec(struct socket *sock, struct msghdr *msg, size_t size)
{
	struct kiocb iocb;
	struct sock_iocb siocb;
	int ret;

	init_sync_kiocb(&iocb, NULL);
	iocb.private = &siocb;
	ret = __sock_sendmsg_nosec(&iocb, sock, msg, size);
	if (-EIOCBQUEUED == ret)
		ret = wait_on_sync_kiocb(&iocb);
	return ret;
}

int kernel_sendmsg(struct socket *sock, struct msghdr *msg,
		   struct kvec *vec, size_t num, size_t size)
{
	mm_segment_t oldfs = get_fs();
	int result;

	set_fs(KERNEL_DS);
	/*
 * the following is safe, since for compiler definitions of kvec and
 * iovec are identical, yielding the same in-core layout and alignment
 */
	msg->msg_iov = (struct iovec *)vec;
	msg->msg_iovlen = num;
	result = sock_sendmsg(sock, msg, size);
	set_fs(oldfs);
	return result;
}
EXPORT_SYMBOL(kernel_sendmsg);

/*
 * called from sock_recv_timestamp() if sock_flag(sk, SOCK_RCVTSTAMP)
 */
void __sock_recv_timestamp(struct msghdr *msg, struct sock *sk,
	struct sk_buff *skb)
{
	int need_software_tstamp = sock_flag(sk, SOCK_RCVTSTAMP);
	struct timespec ts[3];
	int empty = 1;
	struct skb_shared_hwtstamps *shhwtstamps =
		skb_hwtstamps(skb);

	/* Race occurred between timestamp enabling and packet
 receiving. Fill in the current time for now. */
	if (need_software_tstamp && skb->tstamp.tv64 == 0)
		__net_timestamp(skb);

	if (need_software_tstamp) {
		if (!sock_flag(sk, SOCK_RCVTSTAMPNS)) {
			struct timeval tv;
			skb_get_timestamp(skb, &tv);
			put_cmsg(msg, SOL_SOCKET, SCM_TIMESTAMP,
				 sizeof(tv), &tv);
		} else {
			skb_get_timestampns(skb, &ts[0]);
			put_cmsg(msg, SOL_SOCKET, SCM_TIMESTAMPNS,
				 sizeof(ts[0]), &ts[0]);
		}
	}


	memset(ts, 0, sizeof(ts));
	if (sock_flag(sk, SOCK_TIMESTAMPING_SOFTWARE) &&
	    ktime_to_timespec_cond(skb->tstamp, ts + 0))
		empty = 0;
	if (shhwtstamps) {
		if (sock_flag(sk, SOCK_TIMESTAMPING_SYS_HARDWARE) &&
		    ktime_to_timespec_cond(shhwtstamps->syststamp, ts + 1))
			empty = 0;
		if (sock_flag(sk, SOCK_TIMESTAMPING_RAW_HARDWARE) &&
		    ktime_to_timespec_cond(shhwtstamps->hwtstamp, ts + 2))
			empty = 0;
	}
	if (!empty)
		put_cmsg(msg, SOL_SOCKET,
			 SCM_TIMESTAMPING, sizeof(ts), &ts);
}
EXPORT_SYMBOL_GPL(__sock_recv_timestamp);

void __sock_recv_wifi_status(struct msghdr *msg, struct sock *sk,
	struct sk_buff *skb)
{
	int ack;

	if (!sock_flag(sk, SOCK_WIFI_STATUS))
		return;
	if (!skb->wifi_acked_valid)
		return;

	ack = skb->wifi_acked;

	put_cmsg(msg, SOL_SOCKET, SCM_WIFI_STATUS, sizeof(ack), &ack);
}
EXPORT_SYMBOL_GPL(__sock_recv_wifi_status);

static inline void sock_recv_drops(struct msghdr *msg, struct sock *sk,
				   struct sk_buff *skb)
{
	if (sock_flag(sk, SOCK_RXQ_OVFL) && skb && skb->dropcount)
		put_cmsg(msg, SOL_SOCKET, SO_RXQ_OVFL,
			sizeof(__u32), &skb->dropcount);
}

void __sock_recv_ts_and_drops(struct msghdr *msg, struct sock *sk,
	struct sk_buff *skb)
{
	sock_recv_timestamp(msg, sk, skb);
	sock_recv_drops(msg, sk, skb);
}
EXPORT_SYMBOL_GPL(__sock_recv_ts_and_drops);

static inline int __sock_recvmsg_nosec(struct kiocb *iocb, struct socket *sock,
				       struct msghdr *msg, size_t size, int flags)
{
	struct sock_iocb *si = kiocb_to_siocb(iocb);

	si->sock = sock;
	si->scm = NULL;
	si->msg = msg;
	si->size = size;
	si->flags = flags;

	return sock->ops->recvmsg(iocb, sock, msg, size, flags);
}

static inline int __sock_recvmsg(struct kiocb *iocb, struct socket *sock,
				 struct msghdr *msg, size_t size, int flags)
{
	int err = security_socket_recvmsg(sock, msg, size, flags);

	return err ?: __sock_recvmsg_nosec(iocb, sock, msg, size, flags);
}

int sock_recvmsg(struct socket *sock, struct msghdr *msg,
		 size_t size, int flags)
{
	struct kiocb iocb;
	struct sock_iocb siocb;
	int ret;

	init_sync_kiocb(&iocb, NULL);
	iocb.private = &siocb;
	ret = __sock_recvmsg(&iocb, sock, msg, size, flags);
	if (-EIOCBQUEUED == ret)
		ret = wait_on_sync_kiocb(&iocb);
	return ret;
}
EXPORT_SYMBOL(sock_recvmsg);

static int sock_recvmsg_nosec(struct socket *sock, struct msghdr *msg,
			      size_t size, int flags)
{
	struct kiocb iocb;
	struct sock_iocb siocb;
	int ret;

	init_sync_kiocb(&iocb, NULL);
	iocb.private = &siocb;
	ret = __sock_recvmsg_nosec(&iocb, sock, msg, size, flags);
	if (-EIOCBQUEUED == ret)
		ret = wait_on_sync_kiocb(&iocb);
	return ret;
}

/**
 * kernel_recvmsg - Receive a message from a socket (kernel space)
 * @sock: The socket to receive the message from
 * @msg: Received message
 * @vec: Input s/g array for message data
 * @num: Size of input s/g array
 * @size: Number of bytes to read
 * @flags: Message flags (MSG_DONTWAIT, etc...)
 *
 * On return the msg structure contains the scatter/gather array passed in the
 * vec argument. The array is modified so that it consists of the unfilled
 * portion of the original array.
 *
 * The returned value is the total number of bytes received, or an error.
 */
int kernel_recvmsg(struct socket *sock, struct msghdr *msg,
		   struct kvec *vec, size_t num, size_t size, int flags)
{
	mm_segment_t oldfs = get_fs();
	int result;

	set_fs(KERNEL_DS);
	/*
 * the following is safe, since for compiler definitions of kvec and
 * iovec are identical, yielding the same in-core layout and alignment
 */
	msg->msg_iov = (struct iovec *)vec, msg->msg_iovlen = num;
	result = sock_recvmsg(sock, msg, size, flags);
	set_fs(oldfs);
	return result;
}
EXPORT_SYMBOL(kernel_recvmsg);

static ssize_t sock_sendpage(struct file *file, struct page *page,
			     int offset, size_t size, loff_t *ppos, int more)
{
	struct socket *sock;
	int flags;

	sock = file->private_data;

	flags = (file->f_flags & O_NONBLOCK) ? MSG_DONTWAIT : 0;
	/* more is a combination of MSG_MORE and MSG_SENDPAGE_NOTLAST */
	flags |= more;

	return kernel_sendpage(sock, page, offset, size, flags);
}

static ssize_t sock_splice_read(struct file *file, loff_t *ppos,
				struct pipe_inode_info *pipe, size_t len,
				unsigned int flags)
{
	struct socket *sock = file->private_data;

	if (unlikely(!sock->ops->splice_read))
		return -EINVAL;

	return sock->ops->splice_read(sock, ppos, pipe, len, flags);
}

static struct sock_iocb *alloc_sock_iocb(struct kiocb *iocb,
					 struct sock_iocb *siocb)
{
	if (!is_sync_kiocb(iocb))
		BUG();

	siocb->kiocb = iocb;
	iocb->private = siocb;
	return siocb;
}

static ssize_t do_sock_read(struct msghdr *msg, struct kiocb *iocb,
		struct file *file, const struct iovec *iov,
		unsigned long nr_segs)
{
	struct socket *sock = file->private_data;
	size_t size = 0;
	int i;

	for (i = 0; i < nr_segs; i++)
		size += iov[i].iov_len;

	msg->msg_name = NULL;
	msg->msg_namelen = 0;
	msg->msg_control = NULL;
	msg->msg_controllen = 0;
	msg->msg_iov = (struct iovec *)iov;
	msg->msg_iovlen = nr_segs;
	msg->msg_flags = (file->f_flags & O_NONBLOCK) ? MSG_DONTWAIT : 0;

	return __sock_recvmsg(iocb, sock, msg, size, msg->msg_flags);
}

static ssize_t sock_aio_read(struct kiocb *iocb, const struct iovec *iov,
				unsigned long nr_segs, loff_t pos)
{
	struct sock_iocb siocb, *x;

	if (pos != 0)
		return -ESPIPE;

	if (iocb->ki_nbytes == 0)	/* Match SYS5 behaviour */
		return 0;


	x = alloc_sock_iocb(iocb, &siocb);
	if (!x)
		return -ENOMEM;
	return do_sock_read(&x->async_msg, iocb, iocb->ki_filp, iov, nr_segs);
}

static ssize_t do_sock_write(struct msghdr *msg, struct kiocb *iocb,
			struct file *file, const struct iovec *iov,
			unsigned long nr_segs)
{
	struct socket *sock = file->private_data;
	size_t size = 0;
	int i;

	for (i = 0; i < nr_segs; i++)
		size += iov[i].iov_len;

	msg->msg_name = NULL;
	msg->msg_namelen = 0;
	msg->msg_control = NULL;
	msg->msg_controllen = 0;
	msg->msg_iov = (struct iovec *)iov;
	msg->msg_iovlen = nr_segs;
	msg->msg_flags = (file->f_flags & O_NONBLOCK) ? MSG_DONTWAIT : 0;
	if (sock->type == SOCK_SEQPACKET)
		msg->msg_flags |= MSG_EOR;

	return __sock_sendmsg(iocb, sock, msg, size);
}

static ssize_t sock_aio_write(struct kiocb *iocb, const struct iovec *iov,
			  unsigned long nr_segs, loff_t pos)
{
	struct sock_iocb siocb, *x;

	if (pos != 0)
		return -ESPIPE;

	x = alloc_sock_iocb(iocb, &siocb);
	if (!x)
		return -ENOMEM;

	return do_sock_write(&x->async_msg, iocb, iocb->ki_filp, iov, nr_segs);
}

/*
 * Atomic setting of ioctl hooks to avoid race
 * with module unload.
 */

static DEFINE_MUTEX(br_ioctl_mutex);
static int (*br_ioctl_hook) (struct net *, unsigned int cmd, void __user *arg);

void brioctl_set(int (*hook) (struct net *, unsigned int, void __user *))
{
	mutex_lock(&br_ioctl_mutex);
	br_ioctl_hook = hook;
	mutex_unlock(&br_ioctl_mutex);
}
EXPORT_SYMBOL(brioctl_set);

static DEFINE_MUTEX(vlan_ioctl_mutex);
static int (*vlan_ioctl_hook) (struct net *, void __user *arg);

void vlan_ioctl_set(int (*hook) (struct net *, void __user *))
{
	mutex_lock(&vlan_ioctl_mutex);
	vlan_ioctl_hook = hook;
	mutex_unlock(&vlan_ioctl_mutex);
}
EXPORT_SYMBOL(vlan_ioctl_set);

static DEFINE_MUTEX(dlci_ioctl_mutex);
static int (*dlci_ioctl_hook) (unsigned int, void __user *);

void dlci_ioctl_set(int (*hook) (unsigned int, void __user *))
{
	mutex_lock(&dlci_ioctl_mutex);
	dlci_ioctl_hook = hook;
	mutex_unlock(&dlci_ioctl_mutex);
}
EXPORT_SYMBOL(dlci_ioctl_set);

static long sock_do_ioctl(struct net *net, struct socket *sock,
				 unsigned int cmd, unsigned long arg)
{
	int err;
	void __user *argp = (void __user *)arg;

	err = sock->ops->ioctl(sock, cmd, arg);

	/*
 * If this ioctl is unknown try to hand it down
 * to the NIC driver.
 */
	if (err == -ENOIOCTLCMD)
		err = dev_ioctl(net, cmd, argp);

	return err;
}

/*
 * With an ioctl, arg may well be a user mode pointer, but we don't know
 * what to do with it - that's up to the protocol still.
 */

static long sock_ioctl(struct file *file, unsigned cmd, unsigned long arg)
{
	struct socket *sock;
	struct sock *sk;
	void __user *argp = (void __user *)arg;
	int pid, err;
	struct net *net;

	sock = file->private_data;
	sk = sock->sk;
	net = sock_net(sk);
	if (cmd >= SIOCDEVPRIVATE && cmd <= (SIOCDEVPRIVATE + 15)) {
		err = dev_ioctl(net, cmd, argp);
	} else
#ifdef CONFIG_WEXT_CORE
	if (cmd >= SIOCIWFIRST && cmd <= SIOCIWLAST) {
		err = dev_ioctl(net, cmd, argp);
	} else
#endif
		switch (cmd) {
		case FIOSETOWN:
		case SIOCSPGRP:
			err = -EFAULT;
			if (get_user(pid, (int __user *)argp))
				break;
			err = f_setown(sock->file, pid, 1);
			break;
		case FIOGETOWN:
		case SIOCGPGRP:
			err = put_user(f_getown(sock->file),
				       (int __user *)argp);
			break;
		case SIOCGIFBR:
		case SIOCSIFBR:
		case SIOCBRADDBR:
		case SIOCBRDELBR:
			err = -ENOPKG;
			if (!br_ioctl_hook)
				request_module("bridge");

			mutex_lock(&br_ioctl_mutex);
			if (br_ioctl_hook)
				err = br_ioctl_hook(net, cmd, argp);
			mutex_unlock(&br_ioctl_mutex);
			break;
		case SIOCGIFVLAN:
		case SIOCSIFVLAN:
			err = -ENOPKG;
			if (!vlan_ioctl_hook)
				request_module("8021q");

			mutex_lock(&vlan_ioctl_mutex);
			if (vlan_ioctl_hook)
				err = vlan_ioctl_hook(net, argp);
			mutex_unlock(&vlan_ioctl_mutex);
			break;
		case SIOCADDDLCI:
		case SIOCDELDLCI:
			err = -ENOPKG;
			if (!dlci_ioctl_hook)
				request_module("dlci");

			mutex_lock(&dlci_ioctl_mutex);
			if (dlci_ioctl_hook)
				err = dlci_ioctl_hook(cmd, argp);
			mutex_unlock(&dlci_ioctl_mutex);
			break;
		default:
			err = sock_do_ioctl(net, sock, cmd, arg);
			break;
		}
	return err;
}

int sock_create_lite(int family, int type, int protocol, struct socket **res)
{
	int err;
	struct socket *sock = NULL;

	err = security_socket_create(family, type, protocol, 1);
	if (err)
		goto out;

	sock = sock_alloc();
	if (!sock) {
		err = -ENOMEM;
		goto out;
	}

	sock->type = type;
	err = security_socket_post_create(sock, family, type, protocol, 1);
	if (err)
		goto out_release;

out:
	*res = sock;
	return err;
out_release:
	sock_release(sock);
	sock = NULL;
	goto out;
}
EXPORT_SYMBOL(sock_create_lite);

/* No kernel lock held - perfect */
static unsigned int sock_poll(struct file *file, poll_table *wait)
{
	unsigned int busy_flag = 0;
	struct socket *sock;

	/*
 * We can't return errors to poll, so it's either yes or no.
 */
	sock = file->private_data;

	if (sk_can_busy_loop(sock->sk)) {
		/* this socket can poll_ll so tell the system call */
		busy_flag = POLL_BUSY_LOOP;

		/* once, only if requested by syscall */
		if (wait && (wait->_key & POLL_BUSY_LOOP))
			sk_busy_loop(sock->sk, 1);
	}

	return busy_flag | sock->ops->poll(file, sock, wait);
}

static int sock_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct socket *sock = file->private_data;

	return sock->ops->mmap(file, sock, vma);
}

static int sock_close(struct inode *inode, struct file *filp)
{
	sock_release(SOCKET_I(inode));
	return 0;
}

/*
 * Update the socket async list
 *
 * Fasync_list locking strategy.
 *
 * 1. fasync_list is modified only under process context socket lock
 * i.e. under semaphore.
 * 2. fasync_list is used under read_lock(&sk->sk_callback_lock)
 * or under socket lock
 */

static int sock_fasync(int fd, struct file *filp, int on)
{
	struct socket *sock = filp->private_data;
	struct sock *sk = sock->sk;
	struct socket_wq *wq;

	if (sk == NULL)
		return -EINVAL;

	lock_sock(sk);
	wq = rcu_dereference_protected(sock->wq, sock_owned_by_user(sk));
	fasync_helper(fd, filp, on, &wq->fasync_list);

	if (!wq->fasync_list)
		sock_reset_flag(sk, SOCK_FASYNC);
	else
		sock_set_flag(sk, SOCK_FASYNC);

	release_sock(sk);
	return 0;
}

/* This function may be called only under socket lock or callback_lock or rcu_lock */

int sock_wake_async(struct socket *sock, int how, int band)
{
	struct socket_wq *wq;

	if (!sock)
		return -1;
	rcu_read_lock();
	wq = rcu_dereference(sock->wq);
	if (!wq || !wq->fasync_list) {
		rcu_read_unlock();
		return -1;
	}
	switch (how) {
	case SOCK_WAKE_WAITD:
		if (test_bit(SOCK_ASYNC_WAITDATA, &sock->flags))
			break;
		goto call_kill;
	case SOCK_WAKE_SPACE:
		if (!test_and_clear_bit(SOCK_ASYNC_NOSPACE, &sock->flags))
			break;
		/* fall through */
	case SOCK_WAKE_IO:
call_kill:
		kill_fasync(&wq->fasync_list, SIGIO, band);
		break;
	case SOCK_WAKE_URG:
		kill_fasync(&wq->fasync_list, SIGURG, band);
	}
	rcu_read_unlock();
	return 0;
}
EXPORT_SYMBOL(sock_wake_async);

int __sock_create(struct net *net, int family, int type, int protocol,
			 struct socket **res, int kern)
{
	int err;
	struct socket *sock;
	const struct net_proto_family *pf;

	/*
 * Check protocol is in range
 */
	if (family < 0 || family >= NPROTO)
		return -EAFNOSUPPORT;
	if (type < 0 || type >= SOCK_MAX)
		return -EINVAL;

	/* Compatibility.

 This uglymoron is moved from INET layer to here to avoid
 deadlock in module load.
 */
	if (family == PF_INET && type == SOCK_PACKET) {
		static int warned;
		if (!warned) {
			warned = 1;
			printk(KERN_INFO "%s uses obsolete (PF_INET,SOCK_PACKET)\n",
			       current->comm);
		}
		family = PF_PACKET;
	}

	err = security_socket_create(family, type, protocol, kern);
	if (err)
		return err;

	/*
 * Allocate the socket and allow the family to set things up. if
 * the protocol is 0, the family is instructed to select an appropriate
 * default.
 */
	sock = sock_alloc();
	if (!sock) {
		net_warn_ratelimited("socket: no more sockets\n");
		return -ENFILE;	/* Not exactly a match, but its the
 closest posix thing */
	}

	sock->type = type;

#ifdef CONFIG_MODULES
	/* Attempt to load a protocol module if the find failed.
 *
 * 12/09/1996 Marcin: But! this makes REALLY only sense, if the user
 * requested real, full-featured networking support upon configuration.
 * Otherwise module support will break!
 */
	if (rcu_access_pointer(net_families[family]) == NULL)
		request_module("net-pf-%d", family);
#endif

	rcu_read_lock();
	pf = rcu_dereference(net_families[family]);
	err = -EAFNOSUPPORT;
	if (!pf)
		goto out_release;

	/*
 * We will call the ->create function, that possibly is in a loadable
 * module, so we have to bump that loadable module refcnt first.
 */
	if (!try_module_get(pf->owner))
		goto out_release;

	/* Now protected by module ref count */
	rcu_read_unlock();

	err = pf->create(net, sock, protocol, kern);
	if (err < 0)
		goto out_module_put;

	/*
 * Now to bump the refcnt of the [loadable] module that owns this
 * socket at sock_release time we decrement its refcnt.
 */
	if (!try_module_get(sock->ops->owner))
		goto out_module_busy;

	/*
 * Now that we're done with the ->create function, the [loadable]
 * module can have its refcnt decremented
 */
	module_put(pf->owner);
	err = security_socket_post_create(sock, family, type, protocol, kern);
	if (err)
		goto out_sock_release;
	*res = sock;

	return 0;

out_module_busy:
	err = -EAFNOSUPPORT;
out_module_put:
	sock->ops = NULL;
	module_put(pf->owner);
out_sock_release:
	sock_release(sock);
	return err;

out_release:
	rcu_read_unlock();
	goto out_sock_release;
}
EXPORT_SYMBOL(__sock_create);

int sock_create(int family, int type, int protocol, struct socket **res)
{
	return __sock_create(current->nsproxy->net_ns, family, type, protocol, res, 0);
}
EXPORT_SYMBOL(sock_create);

int sock_create_kern(int family, int type, int protocol, struct socket **res)
{
	return __sock_create(&init_net, family, type, protocol, res, 1);
}
EXPORT_SYMBOL(sock_create_kern);

SYSCALL_DEFINE3(socket, int, family, int, type, int, protocol)
{
	int retval;
	struct socket *sock;
	int flags;

	/* Check the SOCK_* constants for consistency. */
	BUILD_BUG_ON(SOCK_CLOEXEC != O_CLOEXEC);
	BUILD_BUG_ON((SOCK_MAX | SOCK_TYPE_MASK) != SOCK_TYPE_MASK);
	BUILD_BUG_ON(SOCK_CLOEXEC & SOCK_TYPE_MASK);
	BUILD_BUG_ON(SOCK_NONBLOCK & SOCK_TYPE_MASK);

	flags = type & ~SOCK_TYPE_MASK;
	if (flags & ~(SOCK_CLOEXEC | SOCK_NONBLOCK))
		return -EINVAL;
	type &= SOCK_TYPE_MASK;

	if (SOCK_NONBLOCK != O_NONBLOCK && (flags & SOCK_NONBLOCK))
		flags = (flags & ~SOCK_NONBLOCK) | O_NONBLOCK;

	retval = sock_create(family, type, protocol, &sock);
	if (retval < 0)
		goto out;

	retval = sock_map_fd(sock, flags & (O_CLOEXEC | O_NONBLOCK));
	if (retval < 0)
		goto out_release;

out:
	/* It may be already another descriptor 8) Not kernel problem. */
	return retval;

out_release:
	sock_release(sock);
	return retval;
}

/*
 * Create a pair of connected sockets.
 */

SYSCALL_DEFINE4(socketpair, int, family, int, type, int, protocol,
		int __user *, usockvec)
{
	struct socket *sock1, *sock2;
	int fd1, fd2, err;
	struct file *newfile1, *newfile2;
	int flags;

	flags = type & ~SOCK_TYPE_MASK;
	if (flags & ~(SOCK_CLOEXEC | SOCK_NONBLOCK))
		return -EINVAL;
	type &= SOCK_TYPE_MASK;

	if (SOCK_NONBLOCK != O_NONBLOCK && (flags & SOCK_NONBLOCK))
		flags = (flags & ~SOCK_NONBLOCK) | O_NONBLOCK;

	/*
 * Obtain the first socket and check if the underlying protocol
 * supports the socketpair call.
 */

	err = sock_create(family, type, protocol, &sock1);
	if (err < 0)
		goto out;

	err = sock_create(family, type, protocol, &sock2);
	if (err < 0)
		goto out_release_1;

	err = sock1->ops->socketpair(sock1, sock2);
	if (err < 0)
		goto out_release_both;

	fd1 = get_unused_fd_flags(flags);
	if (unlikely(fd1 < 0)) {
		err = fd1;
		goto out_release_both;
	}
	fd2 = get_unused_fd_flags(flags);
	if (unlikely(fd2 < 0)) {
		err = fd2;
		put_unused_fd(fd1);
		goto out_release_both;
	}

	newfile1 = sock_alloc_file(sock1, flags, NULL);
	if (unlikely(IS_ERR(newfile1))) {
		err = PTR_ERR(newfile1);
		put_unused_fd(fd1);
		put_unused_fd(fd2);
		goto out_release_both;
	}

	newfile2 = sock_alloc_file(sock2, flags, NULL);
	if (IS_ERR(newfile2)) {
		err = PTR_ERR(newfile2);
		fput(newfile1);
		put_unused_fd(fd1);
		put_unused_fd(fd2);
		sock_release(sock2);
		goto out;
	}

	audit_fd_pair(fd1, fd2);
	fd_install(fd1, newfile1);
	fd_install(fd2, newfile2);
	/* fd1 and fd2 may be already another descriptors.
 * Not kernel problem.
 */

	err = put_user(fd1, &usockvec[0]);
	if (!err)
		err = put_user(fd2, &usockvec[1]);
	if (!err)
		return 0;

	sys_close(fd2);
	sys_close(fd1);
	return err;

out_release_both:
	sock_release(sock2);
out_release_1:
	sock_release(sock1);
out:
	return err;
}

/*
 * Bind a name to a socket. Nothing much to do here since it's
 * the protocol's responsibility to handle the local address.
 *
 * We move the socket address to kernel space before we call
 * the protocol layer (having also checked the address is ok).
 */

SYSCALL_DEFINE3(bind, int, fd, struct sockaddr __user *, umyaddr, int, addrlen)
{
	struct socket *sock;
	struct sockaddr_storage address;
	int err, fput_needed;

	sock = sockfd_lookup_light(fd, &err, &fput_needed);
	if (sock) {
		err = move_addr_to_kernel(umyaddr, addrlen, &address);
		if (err >= 0) {
			err = security_socket_bind(sock,
						   (struct sockaddr *)&address,
						   addrlen);
			if (!err)
				err = sock->ops->bind(sock,
						      (struct sockaddr *)
						      &address, addrlen);
		}
		fput_light(sock->file, fput_needed);
	}
	return err;
}

/*
 * Perform a listen. Basically, we allow the protocol to do anything
 * necessary for a listen, and if that works, we mark the socket as
 * ready for listening.
 */

SYSCALL_DEFINE2(listen, int, fd, int, backlog)
{
	struct socket *sock;
	int err, fput_needed;
	int somaxconn;

	sock = sockfd_lookup_light(fd, &err, &fput_needed);
	if (sock) {
		somaxconn = sock_net(sock->sk)->core.sysctl_somaxconn;
		if ((unsigned int)backlog > somaxconn)
			backlog = somaxconn;

		err = security_socket_listen(sock, backlog);
		if (!err)
			err = sock->ops->listen(sock, backlog);

		fput_light(sock->file, fput_needed);
	}
	return err;
}

/*
 * For accept, we attempt to create a new socket, set up the link
 * with the client, wake up the client, then return the new
 * connected fd. We collect the address of the connector in kernel
 * space and move it to user at the very end. This is unclean because
 * we open the socket then return an error.
 *
 * 1003.1g adds the ability to recvmsg() to query connection pending
 * status to recvmsg. We need to add that support in a way thats
 * clean when we restucture accept also.
 */

SYSCALL_DEFINE4(accept4, int, fd, struct sockaddr __user *, upeer_sockaddr,
		int __user *, upeer_addrlen, int, flags)
{
	struct socket *sock, *newsock;
	struct file *newfile;
	int err, len, newfd, fput_needed;
	struct sockaddr_storage address;

	if (flags & ~(SOCK_CLOEXEC | SOCK_NONBLOCK))
		return -EINVAL;

	if (SOCK_NONBLOCK != O_NONBLOCK && (flags & SOCK_NONBLOCK))
		flags = (flags & ~SOCK_NONBLOCK) | O_NONBLOCK;

	sock = sockfd_lookup_light(fd, &err, &fput_needed);
	if (!sock)
		goto out;

	err = -ENFILE;
	newsock = sock_alloc();
	if (!newsock)
		goto out_put;

	newsock->type = sock->type;
	newsock->ops = sock->ops;

	/*
 * We don't need try_module_get here, as the listening socket (sock)
 * has the protocol module (sock->ops->owner) held.
 */
	__module_get(newsock->ops->owner);

	newfd = get_unused_fd_flags(flags);
	if (unlikely(newfd < 0)) {
		err = newfd;
		sock_release(newsock);
		goto out_put;
	}
	newfile = sock_alloc_file(newsock, flags, sock->sk->sk_prot_creator->name);
	if (unlikely(IS_ERR(newfile))) {
		err = PTR_ERR(newfile);
		put_unused_fd(newfd);
		sock_release(newsock);
		goto out_put;
	}

	err = security_socket_accept(sock, newsock);
	if (err)
		goto out_fd;

	err = sock->ops->accept(sock, newsock, sock->file->f_flags);
	if (err < 0)
		goto out_fd;

	if (upeer_sockaddr) {
		if (newsock->ops->getname(newsock, (struct sockaddr *)&address,
					  &len, 2) < 0) {
			err = -ECONNABORTED;
			goto out_fd;
		}
		err = move_addr_to_user(&address,
					len, upeer_sockaddr, upeer_addrlen);
		if (err < 0)
			goto out_fd;
	}

	/* File flags are not inherited via accept() unlike another OSes. */

	fd_install(newfd, newfile);
	err = newfd;

out_put:
	fput_light(sock->file, fput_needed);
out:
	return err;
out_fd:
	fput(newfile);
	put_unused_fd(newfd);
	goto out_put;
}

SYSCALL_DEFINE3(accept, int, fd, struct sockaddr __user *, upeer_sockaddr,
		int __user *, upeer_addrlen)
{
	return sys_accept4(fd, upeer_sockaddr, upeer_addrlen, 0);
}

/*
 * Attempt to connect to a socket with the server address. The address
 * is in user space so we verify it is OK and move it to kernel space.
 *
 * For 1003.1g we need to add clean support for a bind to AF_UNSPEC to
 * break bindings
 *
 * NOTE: 1003.1g draft 6.3 is broken with respect to AX.25/NetROM and
 * other SEQPACKET protocols that take time to connect() as it doesn't
 * include the -EINPROGRESS status for such sockets.
 */

SYSCALL_DEFINE3(connect, int, fd, struct sockaddr __user *, uservaddr,
		int, addrlen)
{
	struct socket *sock;
	struct sockaddr_storage address;
	int err, fput_needed;

	sock = sockfd_lookup_light(fd, &err, &fput_needed);
	if (!sock)
		goto out;
	err = move_addr_to_kernel(uservaddr, addrlen, &address);
	if (err < 0)
		goto out_put;

	err =
	    security_socket_connect(sock, (struct sockaddr *)&address, addrlen);
	if (err)
		goto out_put;

	err = sock->ops->connect(sock, (struct sockaddr *)&address, addrlen,
				 sock->file->f_flags);
out_put:
	fput_light(sock->file, fput_needed);
out:
	return err;
}

/*
 * Get the local address ('name') of a socket object. Move the obtained
 * name to user space.
 */

SYSCALL_DEFINE3(getsockname, int, fd, struct sockaddr __user *, usockaddr,
		int __user *, usockaddr_len)
{
	struct socket *sock;
	struct sockaddr_storage address;
	int len, err, fput_needed;

	sock = sockfd_lookup_light(fd, &err, &fput_needed);
	if (!sock)
		goto out;

	err = security_socket_getsockname(sock);
	if (err)
		goto out_put;

	err = sock->ops->getname(sock, (struct sockaddr *)&address, &len, 0);
	if (err)
		goto out_put;
	err = move_addr_to_user(&address, len, usockaddr, usockaddr_len);

out_put:
	fput_light(sock->file, fput_needed);
out:
	return err;
}

/*
 * Get the remote address ('name') of a socket object. Move the obtained
 * name to user space.
 */

SYSCALL_DEFINE3(getpeername, int, fd, struct sockaddr __user *, usockaddr,
		int __user *, usockaddr_len)
{
	struct socket *sock;
	struct sockaddr_storage address;
	int len, err, fput_needed;

	sock = sockfd_lookup_light(fd, &err, &fput_needed);
	if (sock != NULL) {
		err = security_socket_getpeername(sock);
		if (err) {
			fput_light(sock->file, fput_needed);
			return err;
		}

		err =
		    sock->ops->getname(sock, (struct sockaddr *)&address, &len,
				       1);
		if (!err)
			err = move_addr_to_user(&address, len, usockaddr,
						usockaddr_len);
		fput_light(sock->file, fput_needed);
	}
	return err;
}

/*
 * Send a datagram to a given address. We move the address into kernel
 * space and check the user space data area is readable before invoking
 * the protocol.
 */

SYSCALL_DEFINE6(sendto, int, fd, void __user *, buff, size_t, len,
		unsigned int, flags, struct sockaddr __user *, addr,
		int, addr_len)
{
	struct socket *sock;
	struct sockaddr_storage address;
	int err;
	struct msghdr msg;
	struct iovec iov;
	int fput_needed;

	if (len > INT_MAX)
		len = INT_MAX;
	sock = sockfd_lookup_light(fd, &err, &fput_needed);
	if (!sock)
		goto out;

	iov.iov_base = buff;
	iov.iov_len = len;
	msg.msg_name = NULL;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_namelen = 0;
	if (addr) {
		err = move_addr_to_kernel(addr, addr_len, &address);
		if (err < 0)
			goto out_put;
		msg.msg_name = (struct sockaddr *)&address;
		msg.msg_namelen = addr_len;
	}
	if (sock->file->f_flags & O_NONBLOCK)
		flags |= MSG_DONTWAIT;
	msg.msg_flags = flags;
	err = sock_sendmsg(sock, &msg, len);

out_put:
	fput_light(sock->file, fput_needed);
out:
	return err;
}

/*
 * Send a datagram down a socket.
 */

SYSCALL_DEFINE4(send, int, fd, void __user *, buff, size_t, len,
		unsigned int, flags)
{
	return sys_sendto(fd, buff, len, flags, NULL, 0);
}

/*
 * Receive a frame from the socket and optionally record the address of the
 * sender. We verify the buffers are writable and if needed move the
 * sender address from kernel to user space.
 */

SYSCALL_DEFINE6(recvfrom, int, fd, void __user *, ubuf, size_t, size,
		unsigned int, flags, struct sockaddr __user *, addr,
		int __user *, addr_len)
{
	struct socket *sock;
	struct iovec iov;
	struct msghdr msg;
	struct sockaddr_storage address;
	int err, err2;
	int fput_needed;

	if (size > INT_MAX)
		size = INT_MAX;
	sock = sockfd_lookup_light(fd, &err, &fput_needed);
	if (!sock)
		goto out;

	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_iovlen = 1;
	msg.msg_iov = &iov;
	iov.iov_len = size;
	iov.iov_base = ubuf;
	msg.msg_name = (struct sockaddr *)&address;
	msg.msg_namelen = sizeof(address);
	if (sock->file->f_flags & O_NONBLOCK)
		flags |= MSG_DONTWAIT;
	err = sock_recvmsg(sock, &msg, size, flags);

	if (err >= 0 && addr != NULL) {
		err2 = move_addr_to_user(&address,
					 msg.msg_namelen, addr, addr_len);
		if (err2 < 0)
			err = err2;
	}

	fput_light(sock->file, fput_needed);
out:
	return err;
}

/*
 * Receive a datagram from a socket.
 */

asmlinkage long sys_recv(int fd, void __user *ubuf, size_t size,
			 unsigned int flags)
{
	return sys_recvfrom(fd, ubuf, size, flags, NULL, NULL);
}

/*
 * Set a socket option. Because we don't know the option lengths we have
 * to pass the user mode parameter for the protocols to sort out.
 */

SYSCALL_DEFINE5(setsockopt, int, fd, int, level, int, optname,
		char __user *, optval, int, optlen)
{
	int err, fput_needed;
	struct socket *sock;

	if (optlen < 0)
		return -EINVAL;

	sock = sockfd_lookup_light(fd, &err, &fput_needed);
	if (sock != NULL) {
		err = security_socket_setsockopt(sock, level, optname);
		if (err)
			goto out_put;

		if (level == SOL_SOCKET)
			err =
			    sock_setsockopt(sock, level, optname, optval,
					    optlen);
		else
			err =
			    sock->ops->setsockopt(sock, level, optname, optval,
						  optlen);
out_put:
		fput_light(sock->file, fput_needed);
	}
	return err;
}

/*
 * Get a socket option. Because we don't know the option lengths we have
 * to pass a user mode parameter for the protocols to sort out.
 */

SYSCALL_DEFINE5(getsockopt, int, fd, int, level, int, optname,
		char __user *, optval, int __user *, optlen)
{
	int err, fput_needed;
	struct socket *sock;

	sock = sockfd_lookup_light(fd, &err, &fput_needed);
	if (sock != NULL) {
		err = security_socket_getsockopt(sock, level, optname);
		if (err)
			goto out_put;

		if (level == SOL_SOCKET)
			err =
			    sock_getsockopt(sock, level, optname, optval,
					    optlen);
		else
			err =
			    sock->ops->getsockopt(sock, level, optname, optval,
						  optlen);
out_put:
		fput_light(sock->file, fput_needed);
	}
	return err;
}

/*
 * Shutdown a socket.
 */

SYSCALL_DEFINE2(shutdown, int, fd, int, how)
{
	int err, fput_needed;
	struct socket *sock;

	sock = sockfd_lookup_light(fd, &err, &fput_needed);
	if (sock != NULL) {
		err = security_socket_shutdown(sock, how);
		if (!err)
			err = sock->ops->shutdown(sock, how);
		fput_light(sock->file, fput_needed);
	}
	return err;
}

/* A couple of helpful macros for getting the address of the 32/64 bit
 * fields which are the same type (int / unsigned) on our platforms.
 */
#define COMPAT_MSG(msg, member) ((MSG_CMSG_COMPAT & flags) ? &msg##_compat->member : &msg->member)
#define COMPAT_NAMELEN(msg) COMPAT_MSG(msg, msg_namelen)
#define COMPAT_FLAGS(msg) COMPAT_MSG(msg, msg_flags)

struct used_address {
	struct sockaddr_storage name;
	unsigned int name_len;
};

static int copy_msghdr_from_user(struct msghdr *kmsg,
				 struct msghdr __user *umsg)
{
	if (copy_from_user(kmsg, umsg, sizeof(struct msghdr)))
		return -EFAULT;
	if (kmsg->msg_namelen > sizeof(struct sockaddr_storage))
		return -EINVAL;
	return 0;
}

static int ___sys_sendmsg(struct socket *sock, struct msghdr __user *msg,
			 struct msghdr *msg_sys, unsigned int flags,
			 struct used_address *used_address)
{
	struct compat_msghdr __user *msg_compat =
	    (struct compat_msghdr __user *)msg;
	struct sockaddr_storage address;
	struct iovec iovstack[UIO_FASTIOV], *iov = iovstack;
	unsigned char ctl[sizeof(struct cmsghdr) + 20]
	    __attribute__ ((aligned(sizeof(__kernel_size_t))));
	/* 20 is size of ipv6_pktinfo */
	unsigned char *ctl_buf = ctl;
	int err, ctl_len, total_len;

	err = -EFAULT;
	if (MSG_CMSG_COMPAT & flags) {
		if (get_compat_msghdr(msg_sys, msg_compat))
			return -EFAULT;
	} else {
		err = copy_msghdr_from_user(msg_sys, msg);
		if (err)
			return err;
	}

	if (msg_sys->msg_iovlen > UIO_FASTIOV) {
		err = -EMSGSIZE;
		if (msg_sys->msg_iovlen > UIO_MAXIOV)
			goto out;
		err = -ENOMEM;
		iov = kmalloc(msg_sys->msg_iovlen * sizeof(struct iovec),
			      GFP_KERNEL);
		if (!iov)
			goto out;
	}

	/* This will also move the address data into kernel space */
	if (MSG_CMSG_COMPAT & flags) {
		err = verify_compat_iovec(msg_sys, iov, &address, VERIFY_READ);
	} else
		err = verify_iovec(msg_sys, iov, &address, VERIFY_READ);
	if (err < 0)
		goto out_freeiov;
	total_len = err;

	err = -ENOBUFS;

	if (msg_sys->msg_controllen > INT_MAX)
		goto out_freeiov;
	ctl_len = msg_sys->msg_controllen;
	if ((MSG_CMSG_COMPAT & flags) && ctl_len) {
		err =
		    cmsghdr_from_user_compat_to_kern(msg_sys, sock->sk, ctl,
						     sizeof(ctl));
		if (err)
			goto out_freeiov;
		ctl_buf = msg_sys->msg_control;
		ctl_len = msg_sys->msg_controllen;
	} else if (ctl_len) {
		if (ctl_len > sizeof(ctl)) {
			ctl_buf = sock_kmalloc(sock->sk, ctl_len, GFP_KERNEL);
			if (ctl_buf == NULL)
				goto out_freeiov;
		}
		err = -EFAULT;
		/*
 * Careful! Before this, msg_sys->msg_control contains a user pointer.
 * Afterwards, it will be a kernel pointer. Thus the compiler-assisted
 * checking falls down on this.
 */
		if (copy_from_user(ctl_buf,
				   (void __user __force *)msg_sys->msg_control,
				   ctl_len))
			goto out_freectl;
		msg_sys->msg_control = ctl_buf;
	}
	msg_sys->msg_flags = flags;

	if (sock->file->f_flags & O_NONBLOCK)
		msg_sys->msg_flags |= MSG_DONTWAIT;
	/*
 * If this is sendmmsg() and current destination address is same as
 * previously succeeded address, omit asking LSM's decision.
 * used_address->name_len is initialized to UINT_MAX so that the first
 * destination address never matches.
 */
	if (used_address && msg_sys->msg_name &&
	    used_address->name_len == msg_sys->msg_namelen &&
	    !memcmp(&used_address->name, msg_sys->msg_name,
		    used_address->name_len)) {
		err = sock_sendmsg_nosec(sock, msg_sys, total_len);
		goto out_freectl;
	}
	err = sock_sendmsg(sock, msg_sys, total_len);
	/*
 * If this is sendmmsg() and sending to current destination address was
 * successful, remember it.
 */
	if (used_address && err >= 0) {
		used_address->name_len = msg_sys->msg_namelen;
		if (msg_sys->msg_name)
			memcpy(&used_address->name, msg_sys->msg_name,
			       used_address->name_len);
	}

out_freectl:
	if (ctl_buf != ctl)
		sock_kfree_s(sock->sk, ctl_buf, ctl_len);
out_freeiov:
	if (iov != iovstack)
		kfree(iov);
out:
	return err;
}

/*
 * BSD sendmsg interface
 */

long __sys_sendmsg(int fd, struct msghdr __user *msg, unsigned flags)
{
	int fput_needed, err;
	struct msghdr msg_sys;
	struct socket *sock;

	sock = sockfd_lookup_light(fd, &err, &fput_needed);
	if (!sock)
		goto out;

	err = ___sys_sendmsg(sock, msg, &msg_sys, flags, NULL);

	fput_light(sock->file, fput_needed);
out:
	return err;
}

SYSCALL_DEFINE3(sendmsg, int, fd, struct msghdr __user *, msg, unsigned int, flags)
{
	if (flags & MSG_CMSG_COMPAT)
		return -EINVAL;
	return __sys_sendmsg(fd, msg, flags);
}

/*
 * Linux sendmmsg interface
 */

int __sys_sendmmsg(int fd, struct mmsghdr __user *mmsg, unsigned int vlen,
		   unsigned int flags)
{
	int fput_needed, err, datagrams;
	struct socket *sock;
	struct mmsghdr __user *entry;
	struct compat_mmsghdr __user *compat_entry;
	struct msghdr msg_sys;
	struct used_address used_address;

	if (vlen > UIO_MAXIOV)
		vlen = UIO_MAXIOV;

	datagrams = 0;

	sock = sockfd_lookup_light(fd, &err, &fput_needed);
	if (!sock)
		return err;

	used_address.name_len = UINT_MAX;
	entry = mmsg;
	compat_entry = (struct compat_mmsghdr __user *)mmsg;
	err = 0;

	while (datagrams < vlen) {
		if (MSG_CMSG_COMPAT & flags) {
			err = ___sys_sendmsg(sock, (struct msghdr __user *)compat_entry,
					     &msg_sys, flags, &used_address);
			if (err < 0)
				break;
			err = __put_user(err, &compat_entry->msg_len);
			++compat_entry;
		} else {
			err = ___sys_sendmsg(sock,
					     (struct msghdr __user *)entry,
					     &msg_sys, flags, &used_address);
			if (err < 0)
				break;
			err = put_user(err, &entry->msg_len);
			++entry;
		}

		if (err)
			break;
		++datagrams;
	}

	fput_light(sock->file, fput_needed);

	/* We only return an error if no datagrams were able to be sent */
	if (datagrams != 0)
		return datagrams;

	return err;
}

SYSCALL_DEFINE4(sendmmsg, int, fd, struct mmsghdr __user *, mmsg,
		unsigned int, vlen, unsigned int, flags)
{
	if (flags & MSG_CMSG_COMPAT)
		return -EINVAL;
	return __sys_sendmmsg(fd, mmsg, vlen, flags);
}

static int ___sys_recvmsg(struct socket *sock, struct msghdr __user *msg,
			 struct msghdr *msg_sys, unsigned int flags, int nosec)
{
	struct compat_msghdr __user *msg_compat =
	    (struct compat_msghdr __user *)msg;
	struct iovec iovstack[UIO_FASTIOV];
	struct iovec *iov = iovstack;
	unsigned long cmsg_ptr;
	int err, total_len, len;

	/* kernel mode address */
	struct sockaddr_storage addr;

	/* user mode address pointers */
	struct sockaddr __user *uaddr;
	int __user *uaddr_len;

	if (MSG_CMSG_COMPAT & flags) {
		if (get_compat_msghdr(msg_sys, msg_compat))
			return -EFAULT;
	} else {
		err = copy_msghdr_from_user(msg_sys, msg);
		if (err)
			return err;
	}

	if (msg_sys->msg_iovlen > UIO_FASTIOV) {
		err = -EMSGSIZE;
		if (msg_sys->msg_iovlen > UIO_MAXIOV)
			goto out;
		err = -ENOMEM;
		iov = kmalloc(msg_sys->msg_iovlen * sizeof(struct iovec),
			      GFP_KERNEL);
		if (!iov)
			goto out;
	}

	/*
 * Save the user-mode address (verify_iovec will change the
 * kernel msghdr to use the kernel address space)
 */

	uaddr = (__force void __user *)msg_sys->msg_name;
	uaddr_len = COMPAT_NAMELEN(msg);
	if (MSG_CMSG_COMPAT & flags) {
		err = verify_compat_iovec(msg_sys, iov, &addr, VERIFY_WRITE);
	} else
		err = verify_iovec(msg_sys, iov, &addr, VERIFY_WRITE);
	if (err < 0)
		goto out_freeiov;
	total_len = err;

	cmsg_ptr = (unsigned long)msg_sys->msg_control;
	msg_sys->msg_flags = flags & (MSG_CMSG_CLOEXEC|MSG_CMSG_COMPAT);

	if (sock->file->f_flags & O_NONBLOCK)
		flags |= MSG_DONTWAIT;
	err = (nosec ? sock_recvmsg_nosec : sock_recvmsg)(sock, msg_sys,
							  total_len, flags);
	if (err < 0)
		goto out_freeiov;
	len = err;

	if (uaddr != NULL) {
		err = move_addr_to_user(&addr,
					msg_sys->msg_namelen, uaddr,
					uaddr_len);
		if (err < 0)
			goto out_freeiov;
	}
	err = __put_user((msg_sys->msg_flags & ~MSG_CMSG_COMPAT),
			 COMPAT_FLAGS(msg));
	if (err)
		goto out_freeiov;
	if (MSG_CMSG_COMPAT & flags)
		err = __put_user((unsigned long)msg_sys->msg_control - cmsg_ptr,
				 &msg_compat->msg_controllen);
	else
		err = __put_user((unsigned long)msg_sys->msg_control - cmsg_ptr,
				 &msg->msg_controllen);
	if (err)
		goto out_freeiov;
	err = len;

out_freeiov:
	if (iov != iovstack)
		kfree(iov);
out:
	return err;
}

/*
 * BSD recvmsg interface
 */

long __sys_recvmsg(int fd, struct msghdr __user *msg, unsigned flags)
{
	int fput_needed, err;
	struct msghdr msg_sys;
	struct socket *sock;

	sock = sockfd_lookup_light(fd, &err, &fput_needed);
	if (!sock)
		goto out;

	err = ___sys_recvmsg(sock, msg, &msg_sys, flags, 0);

	fput_light(sock->file, fput_needed);
out:
	return err;
}

SYSCALL_DEFINE3(recvmsg, int, fd, struct msghdr __user *, msg,
		unsigned int, flags)
{
	if (flags & MSG_CMSG_COMPAT)
		return -EINVAL;
	return __sys_recvmsg(fd, msg, flags);
}

/*
 * Linux recvmmsg interface
 */

int __sys_recvmmsg(int fd, struct mmsghdr __user *mmsg, unsigned int vlen,
		   unsigned int flags, struct timespec *timeout)
{
	int fput_needed, err, datagrams;
	struct socket *sock;
	struct mmsghdr __user *entry;
	struct compat_mmsghdr __user *compat_entry;
	struct msghdr msg_sys;
	struct timespec end_time;

	if (timeout &&
	    poll_select_set_timeout(&end_time, timeout->tv_sec,
				    timeout->tv_nsec))
		return -EINVAL;

	datagrams = 0;

	sock = sockfd_lookup_light(fd, &err, &fput_needed);
	if (!sock)
		return err;

	err = sock_error(sock->sk);
	if (err)
		goto out_put;

	entry = mmsg;
	compat_entry = (struct compat_mmsghdr __user *)mmsg;

	while (datagrams < vlen) {
		/*
 * No need to ask LSM for more than the first datagram.
 */
		if (MSG_CMSG_COMPAT & flags) {
			err = ___sys_recvmsg(sock, (struct msghdr __user *)compat_entry,
					     &msg_sys, flags & ~MSG_WAITFORONE,
					     datagrams);
			if (err < 0)
				break;
			err = __put_user(err, &compat_entry->msg_len);
			++compat_entry;
		} else {
			err = ___sys_recvmsg(sock,
					     (struct msghdr __user *)entry,
					     &msg_sys, flags & ~MSG_WAITFORONE,
					     datagrams);
			if (err < 0)
				break;
			err = put_user(err, &entry->msg_len);
			++entry;
		}

		if (err)
			break;
		++datagrams;

		/* MSG_WAITFORONE turns on MSG_DONTWAIT after one packet */
		if (flags & MSG_WAITFORONE)
			flags |= MSG_DONTWAIT;

		if (timeout) {
			ktime_get_ts(timeout);
			*timeout = timespec_sub(end_time, *timeout);
			if (timeout->tv_sec < 0) {
				timeout->tv_sec = timeout->tv_nsec = 0;
				break;
			}

			/* Timeout, return less than vlen datagrams */
			if (timeout->tv_nsec == 0 && timeout->tv_sec == 0)
				break;
		}

		/* Out of band data, return right away */
		if (msg_sys.msg_flags & MSG_OOB)
			break;
	}

out_put:
	fput_light(sock->file, fput_needed);

	if (err == 0)
		return datagrams;

	if (datagrams != 0) {
		/*
 * We may return less entries than requested (vlen) if the
 * sock is non block and there aren't enough datagrams...
 */
		if (err != -EAGAIN) {
			/*
 * ... or if recvmsg returns an error after we
 * received some datagrams, where we record the
 * error to return on the next call or if the
 * app asks about it using getsockopt(SO_ERROR).
 */
			sock->sk->sk_err = -err;
		}

		return datagrams;
	}

	return err;
}

SYSCALL_DEFINE5(recvmmsg, int, fd, struct mmsghdr __user *, mmsg,
		unsigned int, vlen, unsigned int, flags,
		struct timespec __user *, timeout)
{
	int datagrams;
	struct timespec timeout_sys;

	if (flags & MSG_CMSG_COMPAT)
		return -EINVAL;

	if (!timeout)
		return __sys_recvmmsg(fd, mmsg, vlen, flags, NULL);

	if (copy_from_user(&timeout_sys, timeout, sizeof(timeout_sys)))
		return -EFAULT;

	datagrams = __sys_recvmmsg(fd, mmsg, vlen, flags, &timeout_sys);

	if (datagrams > 0 &&
	    copy_to_user(timeout, &timeout_sys, sizeof(timeout_sys)))
		datagrams = -EFAULT;

	return datagrams;
}

#ifdef __ARCH_WANT_SYS_SOCKETCALL
/* Argument list sizes for sys_socketcall */
#define AL(x) ((x) * sizeof(unsigned long))
static const unsigned char nargs[21] = {
	AL(0), AL(3), AL(3), AL(3), AL(2), AL(3),
	AL(3), AL(3), AL(4), AL(4), AL(4), AL(6),
	AL(6), AL(2), AL(5), AL(5), AL(3), AL(3),
	AL(4), AL(5), AL(4)
};

#undef AL

/*
 * System call vectors.
 *
 * Argument checking cleaned up. Saved 20% in size.
 * This function doesn't need to set the kernel lock because
 * it is set by the callees.
 */

SYSCALL_DEFINE2(socketcall, int, call, unsigned long __user *, args)
{
	unsigned long a[AUDITSC_ARGS];
	unsigned long a0, a1;
	int err;
	unsigned int len;

	if (call < 1 || call > SYS_SENDMMSG)
		return -EINVAL;

	len = nargs[call];
	if (len > sizeof(a))
		return -EINVAL;

	/* copy_from_user should be SMP safe. */
	if (copy_from_user(a, args, len))
		return -EFAULT;

	err = audit_socketcall(nargs[call] / sizeof(unsigned long), a);
	if (err)
		return err;

	a0 = a[0];
	a1 = a[1];

	switch (call) {
	case SYS_SOCKET:
		err = sys_socket(a0, a1, a[2]);
		break;
	case SYS_BIND:
		err = sys_bind(a0, (struct sockaddr __user *)a1, a[2]);
		break;
	case SYS_CONNECT:
		err = sys_connect(a0, (struct sockaddr __user *)a1, a[2]);
		break;
	case SYS_LISTEN:
		err = sys_listen(a0, a1);
		break;
	case SYS_ACCEPT:
		err = sys_accept4(a0, (struct sockaddr __user *)a1,
				  (int __user *)a[2], 0);
		break;
	case SYS_GETSOCKNAME:
		err =
		    sys_getsockname(a0, (struct sockaddr __user *)a1,
				    (int __user *)a[2]);
		break;
	case SYS_GETPEERNAME:
		err =
		    sys_getpeername(a0, (struct sockaddr __user *)a1,
				    (int __user *)a[2]);
		break;
	case SYS_SOCKETPAIR:
		err = sys_socketpair(a0, a1, a[2], (int __user *)a[3]);
		break;
	case SYS_SEND:
		err = sys_send(a0, (void __user *)a1, a[2], a[3]);
		break;
	case SYS_SENDTO:
		err = sys_sendto(a0, (void __user *)a1, a[2], a[3],
				 (struct sockaddr __user *)a[4], a[5]);
		break;
	case SYS_RECV:
		err = sys_recv(a0, (void __user *)a1, a[2], a[3]);
		break;
	case SYS_RECVFROM:
		err = sys_recvfrom(a0, (void __user *)a1, a[2], a[3],
				   (struct sockaddr __user *)a[4],
				   (int __user *)a[5]);
		break;
	case SYS_SHUTDOWN:
		err = sys_shutdown(a0, a1);
		break;
	case SYS_SETSOCKOPT:
		err = sys_setsockopt(a0, a1, a[2], (char __user *)a[3], a[4]);
		break;
	case SYS_GETSOCKOPT:
		err =
		    sys_getsockopt(a0, a1, a[2], (char __user *)a[3],
				   (int __user *)a[4]);
		break;
	case SYS_SENDMSG:
		err = sys_sendmsg(a0, (struct msghdr __user *)a1, a[2]);
		break;
	case SYS_SENDMMSG:
		err = sys_sendmmsg(a0, (struct mmsghdr __user *)a1, a[2], a[3]);
		break;
	case SYS_RECVMSG:
		err = sys_recvmsg(a0, (struct msghdr __user *)a1, a[2]);
		break;
	case SYS_RECVMMSG:
		err = sys_recvmmsg(a0, (struct mmsghdr __user *)a1, a[2], a[3],
				   (struct timespec __user *)a[4]);
		break;
	case SYS_ACCEPT4:
		err = sys_accept4(a0, (struct sockaddr __user *)a1,
				  (int __user *)a[2], a[3]);
		break;
	default:
		err = -EINVAL;
		break;
	}
	return err;
}

#endif				/* __ARCH_WANT_SYS_SOCKETCALL */

/**
 * sock_register - add a socket protocol handler
 * @ops: description of protocol
 *
 * This function is called by a protocol handler that wants to
 * advertise its address family, and have it linked into the
 * socket interface. The value ops->family coresponds to the
 * socket system call protocol family.
 */
int sock_register(const struct net_proto_family *ops)
{
	int err;

	if (ops->family >= NPROTO) {
		printk(KERN_CRIT "protocol %d >= NPROTO(%d)\n", ops->family,
		       NPROTO);
		return -ENOBUFS;
	}

	spin_lock(&net_family_lock);
	if (rcu_dereference_protected(net_families[ops->family],
				      lockdep_is_held(&net_family_lock)))
		err = -EEXIST;
	else {
		rcu_assign_pointer(net_families[ops->family], ops);
		err = 0;
	}
	spin_unlock(&net_family_lock);

	printk(KERN_INFO "NET: Registered protocol family %d\n", ops->family);
	return err;
}
EXPORT_SYMBOL(sock_register);

/**
 * sock_unregister - remove a protocol handler
 * @family: protocol family to remove
 *
 * This function is called by a protocol handler that wants to
 * remove its address family, and have it unlinked from the
 * new socket creation.
 *
 * If protocol handler is a module, then it can use module reference
 * counts to protect against new references. If protocol handler is not
 * a module then it needs to provide its own protection in
 * the ops->create routine.
 */
void sock_unregister(int family)
{
	BUG_ON(family < 0 || family >= NPROTO);

	spin_lock(&net_family_lock);
	RCU_INIT_POINTER(net_families[family], NULL);
	spin_unlock(&net_family_lock);

	synchronize_rcu();

	printk(KERN_INFO "NET: Unregistered protocol family %d\n", family);
}
EXPORT_SYMBOL(sock_unregister);

static int __init sock_init(void)
{
	int err;
	/*
 * Initialize the network sysctl infrastructure.
 */
	err = net_sysctl_init();
	if (err)
		goto out;

	/*
 * Initialize skbuff SLAB cache
 */
	skb_init();

	/*
 * Initialize the protocols module.
 */

	init_inodecache();

	err = register_filesystem(&sock_fs_type);
	if (err)
		goto out_fs;
	sock_mnt = kern_mount(&sock_fs_type);
	if (IS_ERR(sock_mnt)) {
		err = PTR_ERR(sock_mnt);
		goto out_mount;
	}

	/* The real protocol initialization is performed in later initcalls.
 */

#ifdef CONFIG_NETFILTER
	err = netfilter_init();
	if (err)
		goto out;
#endif

#ifdef CONFIG_NETWORK_PHY_TIMESTAMPING
	skb_timestamping_init();
#endif

out:
	return err;

out_mount:
	unregister_filesystem(&sock_fs_type);
out_fs:
	goto out;
}

core_initcall(sock_init);	/* early initcall */

#ifdef CONFIG_PROC_FS
void socket_seq_show(struct seq_file *seq)
{
	int cpu;
	int counter = 0;

	for_each_possible_cpu(cpu)
	    counter += per_cpu(sockets_in_use, cpu);

	/* It can be negative, by the way. 8) */
	if (counter < 0)
		counter = 0;

	seq_printf(seq, "sockets: used %d\n", counter);
}
#endif				/* CONFIG_PROC_FS */

#ifdef CONFIG_COMPAT
static int do_siocgstamp(struct net *net, struct socket *sock,
			 unsigned int cmd, void __user *up)
{
	mm_segment_t old_fs = get_fs();
	struct timeval ktv;
	int err;

	set_fs(KERNEL_DS);
	err = sock_do_ioctl(net, sock, cmd, (unsigned long)&ktv);
	set_fs(old_fs);
	if (!err)
		err = compat_put_timeval(&ktv, up);

	return err;
}

static int do_siocgstampns(struct net *net, struct socket *sock,
			   unsigned int cmd, void __user *up)
{
	mm_segment_t old_fs = get_fs();
	struct timespec kts;
	int err;

	set_fs(KERNEL_DS);
	err = sock_do_ioctl(net, sock, cmd, (unsigned long)&kts);
	set_fs(old_fs);
	if (!err)
		err = compat_put_timespec(&kts, up);

	return err;
}

static int dev_ifname32(struct net *net, struct compat_ifreq __user *uifr32)
{
	struct ifreq __user *uifr;
	int err;

	uifr = compat_alloc_user_space(sizeof(struct ifreq));
	if (copy_in_user(uifr, uifr32, sizeof(struct compat_ifreq)))
		return -EFAULT;

	err = dev_ioctl(net, SIOCGIFNAME, uifr);
	if (err)
		return err;

	if (copy_in_user(uifr32, uifr, sizeof(struct compat_ifreq)))
		return -EFAULT;

	return 0;
}

static int dev_ifconf(struct net *net, struct compat_ifconf __user *uifc32)
{
	struct compat_ifconf ifc32;
	struct ifconf ifc;
	struct ifconf __user *uifc;
	struct compat_ifreq __user *ifr32;
	struct ifreq __user *ifr;
	unsigned int i, j;
	int err;

	if (copy_from_user(&ifc32, uifc32, sizeof(struct compat_ifconf)))
		return -EFAULT;

	memset(&ifc, 0, sizeof(ifc));
	if (ifc32.ifcbuf == 0) {
		ifc32.ifc_len = 0;
		ifc.ifc_len = 0;
		ifc.ifc_req = NULL;
		uifc = compat_alloc_user_space(sizeof(struct ifconf));
	} else {
		size_t len = ((ifc32.ifc_len / sizeof(struct compat_ifreq)) + 1) *
			sizeof(struct ifreq);
		uifc = compat_alloc_user_space(sizeof(struct ifconf) + len);
		ifc.ifc_len = len;
		ifr = ifc.ifc_req = (void __user *)(uifc + 1);
		ifr32 = compat_ptr(ifc32.ifcbuf);
		for (i = 0; i < ifc32.ifc_len; i += sizeof(struct compat_ifreq)) {
			if (copy_in_user(ifr, ifr32, sizeof(struct compat_ifreq)))
				return -EFAULT;
			ifr++;
			ifr32++;
		}
	}
	if (copy_to_user(uifc, &ifc, sizeof(struct ifconf)))
		return -EFAULT;

	err = dev_ioctl(net, SIOCGIFCONF, uifc);
	if (err)
		return err;

	if (copy_from_user(&ifc, uifc, sizeof(struct ifconf)))
		return -EFAULT;

	ifr = ifc.ifc_req;
	ifr32 = compat_ptr(ifc32.ifcbuf);
	for (i = 0, j = 0;
	     i + sizeof(struct compat_ifreq) <= ifc32.ifc_len && j < ifc.ifc_len;
	     i += sizeof(struct compat_ifreq), j += sizeof(struct ifreq)) {
		if (copy_in_user(ifr32, ifr, sizeof(struct compat_ifreq)))
			return -EFAULT;
		ifr32++;
		ifr++;
	}

	if (ifc32.ifcbuf == 0) {
		/* Translate from 64-bit structure multiple to
 * a 32-bit one.
 */
		i = ifc.ifc_len;
		i = ((i / sizeof(struct ifreq)) * sizeof(struct compat_ifreq));
		ifc32.ifc_len = i;
	} else {
		ifc32.ifc_len = i;
	}
	if (copy_to_user(uifc32, &ifc32, sizeof(struct compat_ifconf)))
		return -EFAULT;

	return 0;
}

static int ethtool_ioctl(struct net *net, struct compat_ifreq __user *ifr32)
{
	struct compat_ethtool_rxnfc __user *compat_rxnfc;
	bool convert_in = false, convert_out = false;
	size_t buf_size = ALIGN(sizeof(struct ifreq), 8);
	struct ethtool_rxnfc __user *rxnfc;
	struct ifreq __user *ifr;
	u32 rule_cnt = 0, actual_rule_cnt;
	u32 ethcmd;
	u32 data;
	int ret;

	if (get_user(data, &ifr32->ifr_ifru.ifru_data))
		return -EFAULT;

	compat_rxnfc = compat_ptr(data);

	if (get_user(ethcmd, &compat_rxnfc->cmd))
		return -EFAULT;

	/* Most ethtool structures are defined without padding.
 * Unfortunately struct ethtool_rxnfc is an exception.
 */
	switch (ethcmd) {
	default:
		break;
	case ETHTOOL_GRXCLSRLALL:
		/* Buffer size is variable */
		if (get_user(rule_cnt, &compat_rxnfc->rule_cnt))
			return -EFAULT;
		if (rule_cnt > KMALLOC_MAX_SIZE / sizeof(u32))
			return -ENOMEM;
		buf_size += rule_cnt * sizeof(u32);
		/* fall through */
	case ETHTOOL_GRXRINGS:
	case ETHTOOL_GRXCLSRLCNT:
	case ETHTOOL_GRXCLSRULE:
	case ETHTOOL_SRXCLSRLINS:
		convert_out = true;
		/* fall through */
	case ETHTOOL_SRXCLSRLDEL:
		buf_size += sizeof(struct ethtool_rxnfc);
		convert_in = true;
		break;
	}

	ifr = compat_alloc_user_space(buf_size);
	rxnfc = (void __user *)ifr + ALIGN(sizeof(struct ifreq), 8);

	if (copy_in_user(&ifr->ifr_name, &ifr32->ifr_name, IFNAMSIZ))
		return -EFAULT;

	if (put_user(convert_in ? rxnfc : compat_ptr(data),
		     &ifr->ifr_ifru.ifru_data))
		return -EFAULT;

	if (convert_in) {
		/* We expect there to be holes between fs.m_ext and
 * fs.ring_cookie and at the end of fs, but nowhere else.
 */
		BUILD_BUG_ON(offsetof(struct compat_ethtool_rxnfc, fs.m_ext) +
			     sizeof(compat_rxnfc->fs.m_ext) !=
			     offsetof(struct ethtool_rxnfc, fs.m_ext) +
			     sizeof(rxnfc->fs.m_ext));
		BUILD_BUG_ON(
			offsetof(struct compat_ethtool_rxnfc, fs.location) -
			offsetof(struct compat_ethtool_rxnfc, fs.ring_cookie) !=
			offsetof(struct ethtool_rxnfc, fs.location) -
			offsetof(struct ethtool_rxnfc, fs.ring_cookie));

		if (copy_in_user(rxnfc, compat_rxnfc,
				 (void __user *)(&rxnfc->fs.m_ext + 1) -
				 (void __user *)rxnfc) ||
		    copy_in_user(&rxnfc->fs.ring_cookie,
				 &compat_rxnfc->fs.ring_cookie,
				 (void __user *)(&rxnfc->fs.location + 1) -
				 (void __user *)&rxnfc->fs.ring_cookie) ||
		    copy_in_user(&rxnfc->rule_cnt, &compat_rxnfc->rule_cnt,
				 sizeof(rxnfc->rule_cnt)))
			return -EFAULT;
	}

	ret = dev_ioctl(net, SIOCETHTOOL, ifr);
	if (ret)
		return ret;

	if (convert_out) {
		if (copy_in_user(compat_rxnfc, rxnfc,
				 (const void __user *)(&rxnfc->fs.m_ext + 1) -
				 (const void __user *)rxnfc) ||
		    copy_in_user(&compat_rxnfc->fs.ring_cookie,
				 &rxnfc->fs.ring_cookie,
				 (const void __user *)(&rxnfc->fs.location + 1) -
				 (const void __user *)&rxnfc->fs.ring_cookie) ||
		    copy_in_user(&compat_rxnfc->rule_cnt, &rxnfc->rule_cnt,
				 sizeof(rxnfc->rule_cnt)))
			return -EFAULT;

		if (ethcmd == ETHTOOL_GRXCLSRLALL) {
			/* As an optimisation, we only copy the actual
 * number of rules that the underlying
 * function returned. Since Mallory might
 * change the rule count in user memory, we
 * check that it is less than the rule count
 * originally given (as the user buffer size),
 * which has been range-checked.
 */
			if (get_user(actual_rule_cnt, &rxnfc->rule_cnt))
				return -EFAULT;
			if (actual_rule_cnt < rule_cnt)
				rule_cnt = actual_rule_cnt;
			if (copy_in_user(&compat_rxnfc->rule_locs[0],
					 &rxnfc->rule_locs[0],
					 rule_cnt * sizeof(u32)))
				return -EFAULT;
		}
	}

	return 0;
}

static int compat_siocwandev(struct net *net, struct compat_ifreq __user *uifr32)
{
	void __user *uptr;
	compat_uptr_t uptr32;
	struct ifreq __user *uifr;

	uifr = compat_alloc_user_space(sizeof(*uifr));
	if (copy_in_user(uifr, uifr32, sizeof(struct compat_ifreq)))
		return -EFAULT;

	if (get_user(uptr32, &uifr32->ifr_settings.ifs_ifsu))
		return -EFAULT;

	uptr = compat_ptr(uptr32);

	if (put_user(uptr, &uifr->ifr_settings.ifs_ifsu.raw_hdlc))
		return -EFAULT;

	return dev_ioctl(net, SIOCWANDEV, uifr);
}

static int bond_ioctl(struct net *net, unsigned int cmd,
			 struct compat_ifreq __user *ifr32)
{
	struct ifreq kifr;
	struct ifreq __user *uifr;
	mm_segment_t old_fs;
	int err;
	u32 data;
	void __user *datap;

	switch (cmd) {
	case SIOCBONDENSLAVE:
	case SIOCBONDRELEASE:
	case SIOCBONDSETHWADDR:
	case SIOCBONDCHANGEACTIVE:
		if (copy_from_user(&kifr, ifr32, sizeof(struct compat_ifreq)))
			return -EFAULT;

		old_fs = get_fs();
		set_fs(KERNEL_DS);
		err = dev_ioctl(net, cmd,
				(struct ifreq __user __force *) &kifr);
		set_fs(old_fs);

		return err;
	case SIOCBONDSLAVEINFOQUERY:
	case SIOCBONDINFOQUERY:
		uifr = compat_alloc_user_space(sizeof(*uifr));
		if (copy_in_user(&uifr->ifr_name, &ifr32->ifr_name, IFNAMSIZ))
			return -EFAULT;

		if (get_user(data, &ifr32->ifr_ifru.ifru_data))
			return -EFAULT;

		datap = compat_ptr(data);
		if (put_user(datap, &uifr->ifr_ifru.ifru_data))
			return -EFAULT;

		return dev_ioctl(net, cmd, uifr);
	default:
		return -ENOIOCTLCMD;
	}
}

static int siocdevprivate_ioctl(struct net *net, unsigned int cmd,
				 struct compat_ifreq __user *u_ifreq32)
{
	struct ifreq __user *u_ifreq64;
	char tmp_buf[IFNAMSIZ];
	void __user *data64;
	u32 data32;

	if (copy_from_user(&tmp_buf[0], &(u_ifreq32->ifr_ifrn.ifrn_name[0]),
			   IFNAMSIZ))
		return -EFAULT;
	if (__get_user(data32, &u_ifreq32->ifr_ifru.ifru_data))
		return -EFAULT;
	data64 = compat_ptr(data32);

	u_ifreq64 = compat_alloc_user_space(sizeof(*u_ifreq64));

	/* Don't check these user accesses, just let that get trapped
 * in the ioctl handler instead.
 */
	if (copy_to_user(&u_ifreq64->ifr_ifrn.ifrn_name[0], &tmp_buf[0],
			 IFNAMSIZ))
		return -EFAULT;
	if (__put_user(data64, &u_ifreq64->ifr_ifru.ifru_data))
		return -EFAULT;

	return dev_ioctl(net, cmd, u_ifreq64);
}

static int dev_ifsioc(struct net *net, struct socket *sock,
			 unsigned int cmd, struct compat_ifreq __user *uifr32)
{
	struct ifreq __user *uifr;
	int err;

	uifr = compat_alloc_user_space(sizeof(*uifr));
	if (copy_in_user(uifr, uifr32, sizeof(*uifr32)))
		return -EFAULT;

	err = sock_do_ioctl(net, sock, cmd, (unsigned long)uifr);

	if (!err) {
		switch (cmd) {
		case SIOCGIFFLAGS:
		case SIOCGIFMETRIC:
		case SIOCGIFMTU:
		case SIOCGIFMEM:
		case SIOCGIFHWADDR:
		case SIOCGIFINDEX:
		case SIOCGIFADDR:
		case SIOCGIFBRDADDR:
		case SIOCGIFDSTADDR:
		case SIOCGIFNETMASK:
		case SIOCGIFPFLAGS:
		case SIOCGIFTXQLEN:
		case SIOCGMIIPHY:
		case SIOCGMIIREG:
			if (copy_in_user(uifr32, uifr, sizeof(*uifr32)))
				err = -EFAULT;
			break;
		}
	}
	return err;
}

static int compat_sioc_ifmap(struct net *net, unsigned int cmd,
			struct compat_ifreq __user *uifr32)
{
	struct ifreq ifr;
	struct compat_ifmap __user *uifmap32;
	mm_segment_t old_fs;
	int err;

	uifmap32 = &uifr32->ifr_ifru.ifru_map;
	err = copy_from_user(&ifr, uifr32, sizeof(ifr.ifr_name));
	err |= get_user(ifr.ifr_map.mem_start, &uifmap32->mem_start);
	err |= get_user(ifr.ifr_map.mem_end, &uifmap32->mem_end);
	err |= get_user(ifr.ifr_map.base_addr, &uifmap32->base_addr);
	err |= get_user(ifr.ifr_map.irq, &uifmap32->irq);
	err |= get_user(ifr.ifr_map.dma, &uifmap32->dma);
	err |= get_user(ifr.ifr_map.port, &uifmap32->port);
	if (err)
		return -EFAULT;

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	err = dev_ioctl(net, cmd, (void  __user __force *)&ifr);
	set_fs(old_fs);

	if (cmd == SIOCGIFMAP && !err) {
		err = copy_to_user(uifr32, &ifr, sizeof(ifr.ifr_name));
		err |= put_user(ifr.ifr_map.mem_start, &uifmap32->mem_start);
		err |= put_user(ifr.ifr_map.mem_end, &uifmap32->mem_end);
		err |= put_user(ifr.ifr_map.base_addr, &uifmap32->base_addr);
		err |= put_user(ifr.ifr_map.irq, &uifmap32->irq);
		err |= put_user(ifr.ifr_map.dma, &uifmap32->dma);
		err |= put_user(ifr.ifr_map.port, &uifmap32->port);
		if (err)
			err = -EFAULT;
	}
	return err;
}

static int compat_siocshwtstamp(struct net *net, struct compat_ifreq __user *uifr32)
{
	void __user *uptr;
	compat_uptr_t uptr32;
	struct ifreq __user *uifr;

	uifr = compat_alloc_user_space(sizeof(*uifr));
	if (copy_in_user(uifr, uifr32, sizeof(struct compat_ifreq)))
		return -EFAULT;

	if (get_user(uptr32, &uifr32->ifr_data))
		return -EFAULT;

	uptr = compat_ptr(uptr32);

	if (put_user(uptr, &uifr->ifr_data))
		return -EFAULT;

	return dev_ioctl(net, SIOCSHWTSTAMP, uifr);
}

struct rtentry32 {
	u32		rt_pad1;
	struct sockaddr rt_dst;         /* target address */
	struct sockaddr rt_gateway;     /* gateway addr (RTF_GATEWAY) */
	struct sockaddr rt_genmask;     /* target network mask (IP) */
	unsigned short	rt_flags;
	short		rt_pad2;
	u32		rt_pad3;
	unsigned char	rt_tos;
	unsigned char	rt_class;
	short		rt_pad4;
	short		rt_metric;      /* +1 for binary compatibility! */
	/* char * */ u32 rt_dev;        /* forcing the device at add */
	u32		rt_mtu;         /* per route MTU/Window */
	u32		rt_window;      /* Window clamping */
	unsigned short  rt_irtt;        /* Initial RTT */
};

struct in6_rtmsg32 {
	struct in6_addr		rtmsg_dst;
	struct in6_addr		rtmsg_src;
	struct in6_addr		rtmsg_gateway;
	u32			rtmsg_type;
	u16			rtmsg_dst_len;
	u16			rtmsg_src_len;
	u32			rtmsg_metric;
	u32			rtmsg_info;
	u32			rtmsg_flags;
	s32			rtmsg_ifindex;
};

static int routing_ioctl(struct net *net, struct socket *sock,
			 unsigned int cmd, void __user *argp)
{
	int ret;
	void *r = NULL;
	struct in6_rtmsg r6;
	struct rtentry r4;
	char devname[16];
	u32 rtdev;
	mm_segment_t old_fs = get_fs();

	if (sock && sock->sk && sock->sk->sk_family == AF_INET6) { /* ipv6 */
		struct in6_rtmsg32 __user *ur6 = argp;
		ret = copy_from_user(&r6.rtmsg_dst, &(ur6->rtmsg_dst),
			3 * sizeof(struct in6_addr));
		ret |= get_user(r6.rtmsg_type, &(ur6->rtmsg_type));
		ret |= get_user(r6.rtmsg_dst_len, &(ur6->rtmsg_dst_len));
		ret |= get_user(r6.rtmsg_src_len, &(ur6->rtmsg_src_len));
		ret |= get_user(r6.rtmsg_metric, &(ur6->rtmsg_metric));
		ret |= get_user(r6.rtmsg_info, &(ur6->rtmsg_info));
		ret |= get_user(r6.rtmsg_flags, &(ur6->rtmsg_flags));
		ret |= get_user(r6.rtmsg_ifindex, &(ur6->rtmsg_ifindex));

		r = (void *) &r6;
	} else { /* ipv4 */
		struct rtentry32 __user *ur4 = argp;
		ret = copy_from_user(&r4.rt_dst, &(ur4->rt_dst),
					3 * sizeof(struct sockaddr));
		ret |= get_user(r4.rt_flags, &(ur4->rt_flags));
		ret |= get_user(r4.rt_metric, &(ur4->rt_metric));
		ret |= get_user(r4.rt_mtu, &(ur4->rt_mtu));
		ret |= get_user(r4.rt_window, &(ur4->rt_window));
		ret |= get_user(r4.rt_irtt, &(ur4->rt_irtt));
		ret |= get_user(rtdev, &(ur4->rt_dev));
		if (rtdev) {
			ret |= copy_from_user(devname, compat_ptr(rtdev), 15);
			r4.rt_dev = (char __user __force *)devname;
			devname[15] = 0;
		} else
			r4.rt_dev = NULL;

		r = (void *) &r4;
	}

	if (ret) {
		ret = -EFAULT;
		goto out;
	}

	set_fs(KERNEL_DS);
	ret = sock_do_ioctl(net, sock, cmd, (unsigned long) r);
	set_fs(old_fs);

out:
	return ret;
}

/* Since old style bridge ioctl's endup using SIOCDEVPRIVATE
 * for some operations; this forces use of the newer bridge-utils that
 * use compatible ioctls
 */
static int old_bridge_ioctl(compat_ulong_t __user *argp)
{
	compat_ulong_t tmp;

	if (get_user(tmp, argp))
		return -EFAULT;
	if (tmp == BRCTL_GET_VERSION)
		return BRCTL_VERSION + 1;
	return -EINVAL;
}

static int compat_sock_ioctl_trans(struct file *file, struct socket *sock,
			 unsigned int cmd, unsigned long arg)
{
	void __user *argp = compat_ptr(arg);
	struct sock *sk = sock->sk;
	struct net *net = sock_net(sk);

	if (cmd >= SIOCDEVPRIVATE && cmd <= (SIOCDEVPRIVATE + 15))
		return siocdevprivate_ioctl(net, cmd, argp);

	switch (cmd) {
	case SIOCSIFBR:
	case SIOCGIFBR:
		return old_bridge_ioctl(argp);
	case SIOCGIFNAME:
		return dev_ifname32(net, argp);
	case SIOCGIFCONF:
		return dev_ifconf(net, argp);
	case SIOCETHTOOL:
		return ethtool_ioctl(net, argp);
	case SIOCWANDEV:
		return compat_siocwandev(net, argp);
	case SIOCGIFMAP:
	case SIOCSIFMAP:
		return compat_sioc_ifmap(net, cmd, argp);
	case SIOCBONDENSLAVE:
	case SIOCBONDRELEASE:
	case SIOCBONDSETHWADDR:
	case SIOCBONDSLAVEINFOQUERY:
	case SIOCBONDINFOQUERY:
	case SIOCBONDCHANGEACTIVE:
		return bond_ioctl(net, cmd, argp);
	case SIOCADDRT:
	case SIOCDELRT:
		return routing_ioctl(net, sock, cmd, argp);
	case SIOCGSTAMP:
		return do_siocgstamp(net, sock, cmd, argp);
	case SIOCGSTAMPNS:
		return do_siocgstampns(net, sock, cmd, argp);
	case SIOCSHWTSTAMP:
		return compat_siocshwtstamp(net, argp);

	case FIOSETOWN:
	case SIOCSPGRP:
	case FIOGETOWN:
	case SIOCGPGRP:
	case SIOCBRADDBR:
	case SIOCBRDELBR:
	case SIOCGIFVLAN:
	case SIOCSIFVLAN:
	case SIOCADDDLCI:
	case SIOCDELDLCI:
		return sock_ioctl(file, cmd, arg);

	case SIOCGIFFLAGS:
	case SIOCSIFFLAGS:
	case SIOCGIFMETRIC:
	case SIOCSIFMETRIC:
	case SIOCGIFMTU:
	case SIOCSIFMTU:
	case SIOCGIFMEM:
	case SIOCSIFMEM:
	case SIOCGIFHWADDR:
	case SIOCSIFHWADDR:
	case SIOCADDMULTI:
	case SIOCDELMULTI:
	case SIOCGIFINDEX:
	case SIOCGIFADDR:
	case SIOCSIFADDR:
	case SIOCSIFHWBROADCAST:
	case SIOCDIFADDR:
	case SIOCGIFBRDADDR:
	case SIOCSIFBRDADDR:
	case SIOCGIFDSTADDR:
	case SIOCSIFDSTADDR:
	case SIOCGIFNETMASK:
	case SIOCSIFNETMASK:
	case SIOCSIFPFLAGS:
	case SIOCGIFPFLAGS:
	case SIOCGIFTXQLEN:
	case SIOCSIFTXQLEN:
	case SIOCBRADDIF:
	case SIOCBRDELIF:
	case SIOCSIFNAME:
	case SIOCGMIIPHY:
	case SIOCGMIIREG:
	case SIOCSMIIREG:
		return dev_ifsioc(net, sock, cmd, argp);

	case SIOCSARP:
	case SIOCGARP:
	case SIOCDARP:
	case SIOCATMARK:
		return sock_do_ioctl(net, sock, cmd, arg);
	}

	return -ENOIOCTLCMD;
}

static long compat_sock_ioctl(struct file *file, unsigned int cmd,
			      unsigned long arg)
{
	struct socket *sock = file->private_data;
	int ret = -ENOIOCTLCMD;
	struct sock *sk;
	struct net *net;

	sk = sock->sk;
	net = sock_net(sk);

	if (sock->ops->compat_ioctl)
		ret = sock->ops->compat_ioctl(sock, cmd, arg);

	if (ret == -ENOIOCTLCMD &&
	    (cmd >= SIOCIWFIRST && cmd <= SIOCIWLAST))
		ret = compat_wext_handle_ioctl(net, cmd, arg);

	if (ret == -ENOIOCTLCMD)
		ret = compat_sock_ioctl_trans(file, sock, cmd, arg);

	return ret;
}
#endif

int kernel_bind(struct socket *sock, struct sockaddr *addr, int addrlen)
{
	return sock->ops->bind(sock, addr, addrlen);
}
EXPORT_SYMBOL(kernel_bind);

int kernel_listen(struct socket *sock, int backlog)
{
	return sock->ops->listen(sock, backlog);
}
EXPORT_SYMBOL(kernel_listen);

int kernel_accept(struct socket *sock, struct socket **newsock, int flags)
{
	struct sock *sk = sock->sk;
	int err;

	err = sock_create_lite(sk->sk_family, sk->sk_type, sk->sk_protocol,
			       newsock);
	if (err < 0)
		goto done;

	err = sock->ops->accept(sock, *newsock, flags);
	if (err < 0) {
		sock_release(*newsock);
		*newsock = NULL;
		goto done;
	}

	(*newsock)->ops = sock->ops;
	__module_get((*newsock)->ops->owner);

done:
	return err;
}
EXPORT_SYMBOL(kernel_accept);

int kernel_connect(struct socket *sock, struct sockaddr *addr, int addrlen,
		   int flags)
{
	return sock->ops->connect(sock, addr, addrlen, flags);
}
EXPORT_SYMBOL(kernel_connect);

int kernel_getsockname(struct socket *sock, struct sockaddr *addr,
			 int *addrlen)
{
	return sock->ops->getname(sock, addr, addrlen, 0);
}
EXPORT_SYMBOL(kernel_getsockname);

int kernel_getpeername(struct socket *sock, struct sockaddr *addr,
			 int *addrlen)
{
	return sock->ops->getname(sock, addr, addrlen, 1);
}
EXPORT_SYMBOL(kernel_getpeername);

int kernel_getsockopt(struct socket *sock, int level, int optname,
			char *optval, int *optlen)
{
	mm_segment_t oldfs = get_fs();
	char __user *uoptval;
	int __user *uoptlen;
	int err;

	uoptval = (char __user __force *) optval;
	uoptlen = (int __user __force *) optlen;

	set_fs(KERNEL_DS);
	if (level == SOL_SOCKET)
		err = sock_getsockopt(sock, level, optname, uoptval, uoptlen);
	else
		err = sock->ops->getsockopt(sock, level, optname, uoptval,
					    uoptlen);
	set_fs(oldfs);
	return err;
}
EXPORT_SYMBOL(kernel_getsockopt);

int kernel_setsockopt(struct socket *sock, int level, int optname,
			char *optval, unsigned int optlen)
{
	mm_segment_t oldfs = get_fs();
	char __user *uoptval;
	int err;

	uoptval = (char __user __force *) optval;

	set_fs(KERNEL_DS);
	if (level == SOL_SOCKET)
		err = sock_setsockopt(sock, level, optname, uoptval, optlen);
	else
		err = sock->ops->setsockopt(sock, level, optname, uoptval,
					    optlen);
	set_fs(oldfs);
	return err;
}
EXPORT_SYMBOL(kernel_setsockopt);

int kernel_sendpage(struct socket *sock, struct page *page, int offset,
		    size_t size, int flags)
{
	if (sock->ops->sendpage)
		return sock->ops->sendpage(sock, page, offset, size, flags);

	return sock_no_sendpage(sock, page, offset, size, flags);
}
EXPORT_SYMBOL(kernel_sendpage);

int kernel_sock_ioctl(struct socket *sock, int cmd, unsigned long arg)
{
	mm_segment_t oldfs = get_fs();
	int err;

	set_fs(KERNEL_DS);
	err = sock->ops->ioctl(sock, cmd, arg);
	set_fs(oldfs);

	return err;
}
EXPORT_SYMBOL(kernel_sock_ioctl);

int kernel_sock_shutdown(struct socket *sock, enum sock_shutdown_cmd how)
{
	return sock->ops->shutdown(sock, how);
}
EXPORT_SYMBOL(kernel_sock_shutdown);

/*
 * net/tipc/socket.c: TIPC socket API
 *
 * Copyright (c) 2001-2007, 2012 Ericsson AB
 * Copyright (c) 2004-2008, 2010-2013, Wind River Systems
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the names of the copyright holders nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "core.h"
#include "port.h"

#include <linux/export.h>
#include <net/sock.h>

#define SS_LISTENING -1	/* socket is listening */
#define SS_READY -2	/* socket is connectionless */

#define CONN_TIMEOUT_DEFAULT 8000	/* default connect timeout = 8s */

struct tipc_sock {
	struct sock sk;
	struct tipc_port *p;
	struct tipc_portid peer_name;
	unsigned int conn_timeout;
};

#define tipc_sk(sk) ((struct tipc_sock *)(sk))
#define tipc_sk_port(sk) (tipc_sk(sk)->p)

#define tipc_rx_ready(sock) (!skb_queue_empty(&sock->sk->sk_receive_queue) || \
 (sock->state == SS_DISCONNECTING))

static int backlog_rcv(struct sock *sk, struct sk_buff *skb);
static u32 dispatch(struct tipc_port *tport, struct sk_buff *buf);
static void wakeupdispatch(struct tipc_port *tport);
static void tipc_data_ready(struct sock *sk, int len);
static void tipc_write_space(struct sock *sk);
static int release(struct socket *sock);
static int accept(struct socket *sock, struct socket *new_sock, int flags);

static const struct proto_ops packet_ops;
static const struct proto_ops stream_ops;
static const struct proto_ops msg_ops;

static struct proto tipc_proto;
static struct proto tipc_proto_kern;

static int sockets_enabled;

/*
 * Revised TIPC socket locking policy:
 *
 * Most socket operations take the standard socket lock when they start
 * and hold it until they finish (or until they need to sleep). Acquiring
 * this lock grants the owner exclusive access to the fields of the socket
 * data structures, with the exception of the backlog queue. A few socket
 * operations can be done without taking the socket lock because they only
 * read socket information that never changes during the life of the socket.
 *
 * Socket operations may acquire the lock for the associated TIPC port if they
 * need to perform an operation on the port. If any routine needs to acquire
 * both the socket lock and the port lock it must take the socket lock first
 * to avoid the risk of deadlock.
 *
 * The dispatcher handling incoming messages cannot grab the socket lock in
 * the standard fashion, since invoked it runs at the BH level and cannot block.
 * Instead, it checks to see if the socket lock is currently owned by someone,
 * and either handles the message itself or adds it to the socket's backlog
 * queue; in the latter case the queued message is processed once the process
 * owning the socket lock releases it.
 *
 * NOTE: Releasing the socket lock while an operation is sleeping overcomes
 * the problem of a blocked socket operation preventing any other operations
 * from occurring. However, applications must be careful if they have
 * multiple threads trying to send (or receive) on the same socket, as these
 * operations might interfere with each other. For example, doing a connect
 * and a receive at the same time might allow the receive to consume the
 * ACK message meant for the connect. While additional work could be done
 * to try and overcome this, it doesn't seem to be worthwhile at the present.
 *
 * NOTE: Releasing the socket lock while an operation is sleeping also ensures
 * that another operation that must be performed in a non-blocking manner is
 * not delayed for very long because the lock has already been taken.
 *
 * NOTE: This code assumes that certain fields of a port/socket pair are
 * constant over its lifetime; such fields can be examined without taking
 * the socket lock and/or port lock, and do not need to be re-read even
 * after resuming processing after waiting. These fields include:
 * - socket type
 * - pointer to socket sk structure (aka tipc_sock structure)
 * - pointer to port structure
 * - port reference
 */

/**
 * advance_rx_queue - discard first buffer in socket receive queue
 *
 * Caller must hold socket lock
 */
static void advance_rx_queue(struct sock *sk)
{
	kfree_skb(__skb_dequeue(&sk->sk_receive_queue));
}

/**
 * reject_rx_queue - reject all buffers in socket receive queue
 *
 * Caller must hold socket lock
 */
static void reject_rx_queue(struct sock *sk)
{
	struct sk_buff *buf;

	while ((buf = __skb_dequeue(&sk->sk_receive_queue)))
		tipc_reject_msg(buf, TIPC_ERR_NO_PORT);
}

/**
 * tipc_sk_create - create a TIPC socket
 * @net: network namespace (must be default network)
 * @sock: pre-allocated socket structure
 * @protocol: protocol indicator (must be 0)
 * @kern: caused by kernel or by userspace?
 *
 * This routine creates additional data structures used by the TIPC socket,
 * initializes them, and links them together.
 *
 * Returns 0 on success, errno otherwise
 */
static int tipc_sk_create(struct net *net, struct socket *sock, int protocol,
			  int kern)
{
	const struct proto_ops *ops;
	socket_state state;
	struct sock *sk;
	struct tipc_port *tp_ptr;

	/* Validate arguments */
	if (unlikely(protocol != 0))
		return -EPROTONOSUPPORT;

	switch (sock->type) {
	case SOCK_STREAM:
		ops = &stream_ops;
		state = SS_UNCONNECTED;
		break;
	case SOCK_SEQPACKET:
		ops = &packet_ops;
		state = SS_UNCONNECTED;
		break;
	case SOCK_DGRAM:
	case SOCK_RDM:
		ops = &msg_ops;
		state = SS_READY;
		break;
	default:
		return -EPROTOTYPE;
	}

	/* Allocate socket's protocol area */
	if (!kern)
		sk = sk_alloc(net, AF_TIPC, GFP_KERNEL, &tipc_proto);
	else
		sk = sk_alloc(net, AF_TIPC, GFP_KERNEL, &tipc_proto_kern);

	if (sk == NULL)
		return -ENOMEM;

	/* Allocate TIPC port for socket to use */
	tp_ptr = tipc_createport(sk, &dispatch, &wakeupdispatch,
				 TIPC_LOW_IMPORTANCE);
	if (unlikely(!tp_ptr)) {
		sk_free(sk);
		return -ENOMEM;
	}

	/* Finish initializing socket data structures */
	sock->ops = ops;
	sock->state = state;

	sock_init_data(sock, sk);
	sk->sk_backlog_rcv = backlog_rcv;
	sk->sk_rcvbuf = sysctl_tipc_rmem[1];
	sk->sk_data_ready = tipc_data_ready;
	sk->sk_write_space = tipc_write_space;
	tipc_sk(sk)->p = tp_ptr;
	tipc_sk(sk)->conn_timeout = CONN_TIMEOUT_DEFAULT;

	spin_unlock_bh(tp_ptr->lock);

	if (sock->state == SS_READY) {
		tipc_set_portunreturnable(tp_ptr->ref, 1);
		if (sock->type == SOCK_DGRAM)
			tipc_set_portunreliable(tp_ptr->ref, 1);
	}

	return 0;
}

/**
 * tipc_sock_create_local - create TIPC socket from inside TIPC module
 * @type: socket type - SOCK_RDM or SOCK_SEQPACKET
 *
 * We cannot use sock_creat_kern here because it bumps module user count.
 * Since socket owner and creator is the same module we must make sure
 * that module count remains zero for module local sockets, otherwise
 * we cannot do rmmod.
 *
 * Returns 0 on success, errno otherwise
 */
int tipc_sock_create_local(int type, struct socket **res)
{
	int rc;
	struct sock *sk;

	rc = sock_create_lite(AF_TIPC, type, 0, res);
	if (rc < 0) {
		pr_err("Failed to create kernel socket\n");
		return rc;
	}
	tipc_sk_create(&init_net, *res, 0, 1);

	sk = (*res)->sk;

	return 0;
}

/**
 * tipc_sock_release_local - release socket created by tipc_sock_create_local
 * @sock: the socket to be released.
 *
 * Module reference count is not incremented when such sockets are created,
 * so we must keep it from being decremented when they are released.
 */
void tipc_sock_release_local(struct socket *sock)
{
	release(sock);
	sock->ops = NULL;
	sock_release(sock);
}

/**
 * tipc_sock_accept_local - accept a connection on a socket created
 * with tipc_sock_create_local. Use this function to avoid that
 * module reference count is inadvertently incremented.
 *
 * @sock: the accepting socket
 * @newsock: reference to the new socket to be created
 * @flags: socket flags
 */

int tipc_sock_accept_local(struct socket *sock, struct socket **newsock,
			   int flags)
{
	struct sock *sk = sock->sk;
	int ret;

	ret = sock_create_lite(sk->sk_family, sk->sk_type,
			       sk->sk_protocol, newsock);
	if (ret < 0)
		return ret;

	ret = accept(sock, *newsock, flags);
	if (ret < 0) {
		sock_release(*newsock);
		return ret;
	}
	(*newsock)->ops = sock->ops;
	return ret;
}

/**
 * release - destroy a TIPC socket
 * @sock: socket to destroy
 *
 * This routine cleans up any messages that are still queued on the socket.
 * For DGRAM and RDM socket types, all queued messages are rejected.
 * For SEQPACKET and STREAM socket types, the first message is rejected
 * and any others are discarded. (If the first message on a STREAM socket
 * is partially-read, it is discarded and the next one is rejected instead.)
 *
 * NOTE: Rejected messages are not necessarily returned to the sender! They
 * are returned or discarded according to the "destination droppable" setting
 * specified for the message by the sender.
 *
 * Returns 0 on success, errno otherwise
 */
static int release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct tipc_port *tport;
	struct sk_buff *buf;
	int res;

	/*
 * Exit if socket isn't fully initialized (occurs when a failed accept()
 * releases a pre-allocated child socket that was never used)
 */
	if (sk == NULL)
		return 0;

	tport = tipc_sk_port(sk);
	lock_sock(sk);

	/*
 * Reject all unreceived messages, except on an active connection
 * (which disconnects locally & sends a 'FIN+' to peer)
 */
	while (sock->state != SS_DISCONNECTING) {
		buf = __skb_dequeue(&sk->sk_receive_queue);
		if (buf == NULL)
			break;
		if (TIPC_SKB_CB(buf)->handle != NULL)
			kfree_skb(buf);
		else {
			if ((sock->state == SS_CONNECTING) ||
			    (sock->state == SS_CONNECTED)) {
				sock->state = SS_DISCONNECTING;
				tipc_disconnect(tport->ref);
			}
			tipc_reject_msg(buf, TIPC_ERR_NO_PORT);
		}
	}

	/*
 * Delete TIPC port; this ensures no more messages are queued
 * (also disconnects an active connection & sends a 'FIN-' to peer)
 */
	res = tipc_deleteport(tport->ref);

	/* Discard any remaining (connection-based) messages in receive queue */
	__skb_queue_purge(&sk->sk_receive_queue);

	/* Reject any messages that accumulated in backlog queue */
	sock->state = SS_DISCONNECTING;
	release_sock(sk);

	sock_put(sk);
	sock->sk = NULL;

	return res;
}

/**
 * bind - associate or disassocate TIPC name(s) with a socket
 * @sock: socket structure
 * @uaddr: socket address describing name(s) and desired operation
 * @uaddr_len: size of socket address data structure
 *
 * Name and name sequence binding is indicated using a positive scope value;
 * a negative scope value unbinds the specified name. Specifying no name
 * (i.e. a socket address length of 0) unbinds all names from the socket.
 *
 * Returns 0 on success, errno otherwise
 *
 * NOTE: This routine doesn't need to take the socket lock since it doesn't
 * access any non-constant socket information.
 */
static int bind(struct socket *sock, struct sockaddr *uaddr, int uaddr_len)
{
	struct sockaddr_tipc *addr = (struct sockaddr_tipc *)uaddr;
	u32 portref = tipc_sk_port(sock->sk)->ref;

	if (unlikely(!uaddr_len))
		return tipc_withdraw(portref, 0, NULL);

	if (uaddr_len < sizeof(struct sockaddr_tipc))
		return -EINVAL;
	if (addr->family != AF_TIPC)
		return -EAFNOSUPPORT;

	if (addr->addrtype == TIPC_ADDR_NAME)
		addr->addr.nameseq.upper = addr->addr.nameseq.lower;
	else if (addr->addrtype != TIPC_ADDR_NAMESEQ)
		return -EAFNOSUPPORT;

	if ((addr->addr.nameseq.type < TIPC_RESERVED_TYPES) &&
	    (addr->addr.nameseq.type != TIPC_TOP_SRV) &&
	    (addr->addr.nameseq.type != TIPC_CFG_SRV))
		return -EACCES;

	return (addr->scope > 0) ?
		tipc_publish(portref, addr->scope, &addr->addr.nameseq) :
		tipc_withdraw(portref, -addr->scope, &addr->addr.nameseq);
}

/**
 * get_name - get port ID of socket or peer socket
 * @sock: socket structure
 * @uaddr: area for returned socket address
 * @uaddr_len: area for returned length of socket address
 * @peer: 0 = own ID, 1 = current peer ID, 2 = current/former peer ID
 *
 * Returns 0 on success, errno otherwise
 *
 * NOTE: This routine doesn't need to take the socket lock since it only
 * accesses socket information that is unchanging (or which changes in
 * a completely predictable manner).
 */
static int get_name(struct socket *sock, struct sockaddr *uaddr,
		    int *uaddr_len, int peer)
{
	struct sockaddr_tipc *addr = (struct sockaddr_tipc *)uaddr;
	struct tipc_sock *tsock = tipc_sk(sock->sk);

	memset(addr, 0, sizeof(*addr));
	if (peer) {
		if ((sock->state != SS_CONNECTED) &&
			((peer != 2) || (sock->state != SS_DISCONNECTING)))
			return -ENOTCONN;
		addr->addr.id.ref = tsock->peer_name.ref;
		addr->addr.id.node = tsock->peer_name.node;
	} else {
		addr->addr.id.ref = tsock->p->ref;
		addr->addr.id.node = tipc_own_addr;
	}

	*uaddr_len = sizeof(*addr);
	addr->addrtype = TIPC_ADDR_ID;
	addr->family = AF_TIPC;
	addr->scope = 0;
	addr->addr.name.domain = 0;

	return 0;
}

/**
 * poll - read and possibly block on pollmask
 * @file: file structure associated with the socket
 * @sock: socket for which to calculate the poll bits
 * @wait: ???
 *
 * Returns pollmask value
 *
 * COMMENTARY:
 * It appears that the usual socket locking mechanisms are not useful here
 * since the pollmask info is potentially out-of-date the moment this routine
 * exits. TCP and other protocols seem to rely on higher level poll routines
 * to handle any preventable race conditions, so TIPC will do the same ...
 *
 * TIPC sets the returned events as follows:
 *
 * socket state flags set
 * ------------ ---------
 * unconnected no read flags
 * POLLOUT if port is not congested
 *
 * connecting POLLIN/POLLRDNORM if ACK/NACK in rx queue
 * no write flags
 *
 * connected POLLIN/POLLRDNORM if data in rx queue
 * POLLOUT if port is not congested
 *
 * disconnecting POLLIN/POLLRDNORM/POLLHUP
 * no write flags
 *
 * listening POLLIN if SYN in rx queue
 * no write flags
 *
 * ready POLLIN/POLLRDNORM if data in rx queue
 * [connectionless] POLLOUT (since port cannot be congested)
 *
 * IMPORTANT: The fact that a read or write operation is indicated does NOT
 * imply that the operation will succeed, merely that it should be performed
 * and will not block.
 */
static unsigned int poll(struct file *file, struct socket *sock,
			 poll_table *wait)
{
	struct sock *sk = sock->sk;
	u32 mask = 0;

	sock_poll_wait(file, sk_sleep(sk), wait);

	switch ((int)sock->state) {
	case SS_UNCONNECTED:
		if (!tipc_sk_port(sk)->congested)
			mask |= POLLOUT;
		break;
	case SS_READY:
	case SS_CONNECTED:
		if (!tipc_sk_port(sk)->congested)
			mask |= POLLOUT;
		/* fall thru' */
	case SS_CONNECTING:
	case SS_LISTENING:
		if (!skb_queue_empty(&sk->sk_receive_queue))
			mask |= (POLLIN | POLLRDNORM);
		break;
	case SS_DISCONNECTING:
		mask = (POLLIN | POLLRDNORM | POLLHUP);
		break;
	}

	return mask;
}

/**
 * dest_name_check - verify user is permitted to send to specified port name
 * @dest: destination address
 * @m: descriptor for message to be sent
 *
 * Prevents restricted configuration commands from being issued by
 * unauthorized users.
 *
 * Returns 0 if permission is granted, otherwise errno
 */
static int dest_name_check(struct sockaddr_tipc *dest, struct msghdr *m)
{
	struct tipc_cfg_msg_hdr hdr;

	if (likely(dest->addr.name.name.type >= TIPC_RESERVED_TYPES))
		return 0;
	if (likely(dest->addr.name.name.type == TIPC_TOP_SRV))
		return 0;
	if (likely(dest->addr.name.name.type != TIPC_CFG_SRV))
		return -EACCES;

	if (!m->msg_iovlen || (m->msg_iov[0].iov_len < sizeof(hdr)))
		return -EMSGSIZE;
	if (copy_from_user(&hdr, m->msg_iov[0].iov_base, sizeof(hdr)))
		return -EFAULT;
	if ((ntohs(hdr.tcm_type) & 0xC000) && (!capable(CAP_NET_ADMIN)))
		return -EACCES;

	return 0;
}

/**
 * send_msg - send message in connectionless manner
 * @iocb: if NULL, indicates that socket lock is already held
 * @sock: socket structure
 * @m: message to send
 * @total_len: length of message
 *
 * Message must have an destination specified explicitly.
 * Used for SOCK_RDM and SOCK_DGRAM messages,
 * and for 'SYN' messages on SOCK_SEQPACKET and SOCK_STREAM connections.
 * (Note: 'SYN+' is prohibited on SOCK_STREAM.)
 *
 * Returns the number of bytes sent on success, or errno otherwise
 */
static int send_msg(struct kiocb *iocb, struct socket *sock,
		    struct msghdr *m, size_t total_len)
{
	struct sock *sk = sock->sk;
	struct tipc_port *tport = tipc_sk_port(sk);
	struct sockaddr_tipc *dest = (struct sockaddr_tipc *)m->msg_name;
	int needs_conn;
	long timeout_val;
	int res = -EINVAL;

	if (unlikely(!dest))
		return -EDESTADDRREQ;
	if (unlikely((m->msg_namelen < sizeof(*dest)) ||
		     (dest->family != AF_TIPC)))
		return -EINVAL;
	if (total_len > TIPC_MAX_USER_MSG_SIZE)
		return -EMSGSIZE;

	if (iocb)
		lock_sock(sk);

	needs_conn = (sock->state != SS_READY);
	if (unlikely(needs_conn)) {
		if (sock->state == SS_LISTENING) {
			res = -EPIPE;
			goto exit;
		}
		if (sock->state != SS_UNCONNECTED) {
			res = -EISCONN;
			goto exit;
		}
		if (tport->published) {
			res = -EOPNOTSUPP;
			goto exit;
		}
		if (dest->addrtype == TIPC_ADDR_NAME) {
			tport->conn_type = dest->addr.name.name.type;
			tport->conn_instance = dest->addr.name.name.instance;
		}

		/* Abort any pending connection attempts (very unlikely) */
		reject_rx_queue(sk);
	}

	timeout_val = sock_sndtimeo(sk, m->msg_flags & MSG_DONTWAIT);

	do {
		if (dest->addrtype == TIPC_ADDR_NAME) {
			res = dest_name_check(dest, m);
			if (res)
				break;
			res = tipc_send2name(tport->ref,
					     &dest->addr.name.name,
					     dest->addr.name.domain,
					     m->msg_iov,
					     total_len);
		} else if (dest->addrtype == TIPC_ADDR_ID) {
			res = tipc_send2port(tport->ref,
					     &dest->addr.id,
					     m->msg_iov,
					     total_len);
		} else if (dest->addrtype == TIPC_ADDR_MCAST) {
			if (needs_conn) {
				res = -EOPNOTSUPP;
				break;
			}
			res = dest_name_check(dest, m);
			if (res)
				break;
			res = tipc_multicast(tport->ref,
					     &dest->addr.nameseq,
					     m->msg_iov,
					     total_len);
		}
		if (likely(res != -ELINKCONG)) {
			if (needs_conn && (res >= 0))
				sock->state = SS_CONNECTING;
			break;
		}
		if (timeout_val <= 0L) {
			res = timeout_val ? timeout_val : -EWOULDBLOCK;
			break;
		}
		release_sock(sk);
		timeout_val = wait_event_interruptible_timeout(*sk_sleep(sk),
					       !tport->congested, timeout_val);
		lock_sock(sk);
	} while (1);

exit:
	if (iocb)
		release_sock(sk);
	return res;
}

/**
 * send_packet - send a connection-oriented message
 * @iocb: if NULL, indicates that socket lock is already held
 * @sock: socket structure
 * @m: message to send
 * @total_len: length of message
 *
 * Used for SOCK_SEQPACKET messages and SOCK_STREAM data.
 *
 * Returns the number of bytes sent on success, or errno otherwise
 */
static int send_packet(struct kiocb *iocb, struct socket *sock,
		       struct msghdr *m, size_t total_len)
{
	struct sock *sk = sock->sk;
	struct tipc_port *tport = tipc_sk_port(sk);
	struct sockaddr_tipc *dest = (struct sockaddr_tipc *)m->msg_name;
	long timeout_val;
	int res;

	/* Handle implied connection establishment */
	if (unlikely(dest))
		return send_msg(iocb, sock, m, total_len);

	if (total_len > TIPC_MAX_USER_MSG_SIZE)
		return -EMSGSIZE;

	if (iocb)
		lock_sock(sk);

	timeout_val = sock_sndtimeo(sk, m->msg_flags & MSG_DONTWAIT);

	do {
		if (unlikely(sock->state != SS_CONNECTED)) {
			if (sock->state == SS_DISCONNECTING)
				res = -EPIPE;
			else
				res = -ENOTCONN;
			break;
		}

		res = tipc_send(tport->ref, m->msg_iov, total_len);
		if (likely(res != -ELINKCONG))
			break;
		if (timeout_val <= 0L) {
			res = timeout_val ? timeout_val : -EWOULDBLOCK;
			break;
		}
		release_sock(sk);
		timeout_val = wait_event_interruptible_timeout(*sk_sleep(sk),
			(!tport->congested || !tport->connected), timeout_val);
		lock_sock(sk);
	} while (1);

	if (iocb)
		release_sock(sk);
	return res;
}

/**
 * send_stream - send stream-oriented data
 * @iocb: (unused)
 * @sock: socket structure
 * @m: data to send
 * @total_len: total length of data to be sent
 *
 * Used for SOCK_STREAM data.
 *
 * Returns the number of bytes sent on success (or partial success),
 * or errno if no data sent
 */
static int send_stream(struct kiocb *iocb, struct socket *sock,
		       struct msghdr *m, size_t total_len)
{
	struct sock *sk = sock->sk;
	struct tipc_port *tport = tipc_sk_port(sk);
	struct msghdr my_msg;
	struct iovec my_iov;
	struct iovec *curr_iov;
	int curr_iovlen;
	char __user *curr_start;
	u32 hdr_size;
	int curr_left;
	int bytes_to_send;
	int bytes_sent;
	int res;

	lock_sock(sk);

	/* Handle special cases where there is no connection */
	if (unlikely(sock->state != SS_CONNECTED)) {
		if (sock->state == SS_UNCONNECTED) {
			res = send_packet(NULL, sock, m, total_len);
			goto exit;
		} else if (sock->state == SS_DISCONNECTING) {
			res = -EPIPE;
			goto exit;
		} else {
			res = -ENOTCONN;
			goto exit;
		}
	}

	if (unlikely(m->msg_name)) {
		res = -EISCONN;
		goto exit;
	}

	if (total_len > (unsigned int)INT_MAX) {
		res = -EMSGSIZE;
		goto exit;
	}

	/*
 * Send each iovec entry using one or more messages
 *
 * Note: This algorithm is good for the most likely case
 * (i.e. one large iovec entry), but could be improved to pass sets
 * of small iovec entries into send_packet().
 */
	curr_iov = m->msg_iov;
	curr_iovlen = m->msg_iovlen;
	my_msg.msg_iov = &my_iov;
	my_msg.msg_iovlen = 1;
	my_msg.msg_flags = m->msg_flags;
	my_msg.msg_name = NULL;
	bytes_sent = 0;

	hdr_size = msg_hdr_sz(&tport->phdr);

	while (curr_iovlen--) {
		curr_start = curr_iov->iov_base;
		curr_left = curr_iov->iov_len;

		while (curr_left) {
			bytes_to_send = tport->max_pkt - hdr_size;
			if (bytes_to_send > TIPC_MAX_USER_MSG_SIZE)
				bytes_to_send = TIPC_MAX_USER_MSG_SIZE;
			if (curr_left < bytes_to_send)
				bytes_to_send = curr_left;
			my_iov.iov_base = curr_start;
			my_iov.iov_len = bytes_to_send;
			res = send_packet(NULL, sock, &my_msg, bytes_to_send);
			if (res < 0) {
				if (bytes_sent)
					res = bytes_sent;
				goto exit;
			}
			curr_left -= bytes_to_send;
			curr_start += bytes_to_send;
			bytes_sent += bytes_to_send;
		}

		curr_iov++;
	}
	res = bytes_sent;
exit:
	release_sock(sk);
	return res;
}

/**
 * auto_connect - complete connection setup to a remote port
 * @sock: socket structure
 * @msg: peer's response message
 *
 * Returns 0 on success, errno otherwise
 */
static int auto_connect(struct socket *sock, struct tipc_msg *msg)
{
	struct tipc_sock *tsock = tipc_sk(sock->sk);
	struct tipc_port *p_ptr;

	tsock->peer_name.ref = msg_origport(msg);
	tsock->peer_name.node = msg_orignode(msg);
	p_ptr = tipc_port_deref(tsock->p->ref);
	if (!p_ptr)
		return -EINVAL;

	__tipc_connect(tsock->p->ref, p_ptr, &tsock->peer_name);

	if (msg_importance(msg) > TIPC_CRITICAL_IMPORTANCE)
		return -EINVAL;
	msg_set_importance(&p_ptr->phdr, (u32)msg_importance(msg));
	sock->state = SS_CONNECTED;
	return 0;
}

/**
 * set_orig_addr - capture sender's address for received message
 * @m: descriptor for message info
 * @msg: received message header
 *
 * Note: Address is not captured if not requested by receiver.
 */
static void set_orig_addr(struct msghdr *m, struct tipc_msg *msg)
{
	struct sockaddr_tipc *addr = (struct sockaddr_tipc *)m->msg_name;

	if (addr) {
		addr->family = AF_TIPC;
		addr->addrtype = TIPC_ADDR_ID;
		memset(&addr->addr, 0, sizeof(addr->addr));
		addr->addr.id.ref = msg_origport(msg);
		addr->addr.id.node = msg_orignode(msg);
		addr->addr.name.domain = 0;	/* could leave uninitialized */
		addr->scope = 0;		/* could leave uninitialized */
		m->msg_namelen = sizeof(struct sockaddr_tipc);
	}
}

/**
 * anc_data_recv - optionally capture ancillary data for received message
 * @m: descriptor for message info
 * @msg: received message header
 * @tport: TIPC port associated with message
 *
 * Note: Ancillary data is not captured if not requested by receiver.
 *
 * Returns 0 if successful, otherwise errno
 */
static int anc_data_recv(struct msghdr *m, struct tipc_msg *msg,
			 struct tipc_port *tport)
{
	u32 anc_data[3];
	u32 err;
	u32 dest_type;
	int has_name;
	int res;

	if (likely(m->msg_controllen == 0))
		return 0;

	/* Optionally capture errored message object(s) */
	err = msg ? msg_errcode(msg) : 0;
	if (unlikely(err)) {
		anc_data[0] = err;
		anc_data[1] = msg_data_sz(msg);
		res = put_cmsg(m, SOL_TIPC, TIPC_ERRINFO, 8, anc_data);
		if (res)
			return res;
		if (anc_data[1]) {
			res = put_cmsg(m, SOL_TIPC, TIPC_RETDATA, anc_data[1],
				       msg_data(msg));
			if (res)
				return res;
		}
	}

	/* Optionally capture message destination object */
	dest_type = msg ? msg_type(msg) : TIPC_DIRECT_MSG;
	switch (dest_type) {
	case TIPC_NAMED_MSG:
		has_name = 1;
		anc_data[0] = msg_nametype(msg);
		anc_data[1] = msg_namelower(msg);
		anc_data[2] = msg_namelower(msg);
		break;
	case TIPC_MCAST_MSG:
		has_name = 1;
		anc_data[0] = msg_nametype(msg);
		anc_data[1] = msg_namelower(msg);
		anc_data[2] = msg_nameupper(msg);
		break;
	case TIPC_CONN_MSG:
		has_name = (tport->conn_type != 0);
		anc_data[0] = tport->conn_type;
		anc_data[1] = tport->conn_instance;
		anc_data[2] = tport->conn_instance;
		break;
	default:
		has_name = 0;
	}
	if (has_name) {
		res = put_cmsg(m, SOL_TIPC, TIPC_DESTNAME, 12, anc_data);
		if (res)
			return res;
	}

	return 0;
}

/**
 * recv_msg - receive packet-oriented message
 * @iocb: (unused)
 * @m: descriptor for message info
 * @buf_len: total size of user buffer area
 * @flags: receive flags
 *
 * Used for SOCK_DGRAM, SOCK_RDM, and SOCK_SEQPACKET messages.
 * If the complete message doesn't fit in user area, truncate it.
 *
 * Returns size of returned message data, errno otherwise
 */
static int recv_msg(struct kiocb *iocb, struct socket *sock,
		    struct msghdr *m, size_t buf_len, int flags)
{
	struct sock *sk = sock->sk;
	struct tipc_port *tport = tipc_sk_port(sk);
	struct sk_buff *buf;
	struct tipc_msg *msg;
	long timeout;
	unsigned int sz;
	u32 err;
	int res;

	/* Catch invalid receive requests */
	if (unlikely(!buf_len))
		return -EINVAL;

	lock_sock(sk);

	if (unlikely(sock->state == SS_UNCONNECTED)) {
		res = -ENOTCONN;
		goto exit;
	}

	/* will be updated in set_orig_addr() if needed */
	m->msg_namelen = 0;

	timeout = sock_rcvtimeo(sk, flags & MSG_DONTWAIT);
restart:

	/* Look for a message in receive queue; wait if necessary */
	while (skb_queue_empty(&sk->sk_receive_queue)) {
		if (sock->state == SS_DISCONNECTING) {
			res = -ENOTCONN;
			goto exit;
		}
		if (timeout <= 0L) {
			res = timeout ? timeout : -EWOULDBLOCK;
			goto exit;
		}
		release_sock(sk);
		timeout = wait_event_interruptible_timeout(*sk_sleep(sk),
							   tipc_rx_ready(sock),
							   timeout);
		lock_sock(sk);
	}

	/* Look at first message in receive queue */
	buf = skb_peek(&sk->sk_receive_queue);
	msg = buf_msg(buf);
	sz = msg_data_sz(msg);
	err = msg_errcode(msg);

	/* Discard an empty non-errored message & try again */
	if ((!sz) && (!err)) {
		advance_rx_queue(sk);
		goto restart;
	}

	/* Capture sender's address (optional) */
	set_orig_addr(m, msg);

	/* Capture ancillary data (optional) */
	res = anc_data_recv(m, msg, tport);
	if (res)
		goto exit;

	/* Capture message data (if valid) & compute return value (always) */
	if (!err) {
		if (unlikely(buf_len < sz)) {
			sz = buf_len;
			m->msg_flags |= MSG_TRUNC;
		}
		res = skb_copy_datagram_iovec(buf, msg_hdr_sz(msg),
					      m->msg_iov, sz);
		if (res)
			goto exit;
		res = sz;
	} else {
		if ((sock->state == SS_READY) ||
		    ((err == TIPC_CONN_SHUTDOWN) || m->msg_control))
			res = 0;
		else
			res = -ECONNRESET;
	}

	/* Consume received message (optional) */
	if (likely(!(flags & MSG_PEEK))) {
		if ((sock->state != SS_READY) &&
		    (++tport->conn_unacked >= TIPC_FLOW_CONTROL_WIN))
			tipc_acknowledge(tport->ref, tport->conn_unacked);
		advance_rx_queue(sk);
	}
exit:
	release_sock(sk);
	return res;
}

/**
 * recv_stream - receive stream-oriented data
 * @iocb: (unused)
 * @m: descriptor for message info
 * @buf_len: total size of user buffer area
 * @flags: receive flags
 *
 * Used for SOCK_STREAM messages only. If not enough data is available
 * will optionally wait for more; never truncates data.
 *
 * Returns size of returned message data, errno otherwise
 */
static int recv_stream(struct kiocb *iocb, struct socket *sock,
		       struct msghdr *m, size_t buf_len, int flags)
{
	struct sock *sk = sock->sk;
	struct tipc_port *tport = tipc_sk_port(sk);
	struct sk_buff *buf;
	struct tipc_msg *msg;
	long timeout;
	unsigned int sz;
	int sz_to_copy, target, needed;
	int sz_copied = 0;
	u32 err;
	int res = 0;

	/* Catch invalid receive attempts */
	if (unlikely(!buf_len))
		return -EINVAL;

	lock_sock(sk);

	if (unlikely((sock->state == SS_UNCONNECTED))) {
		res = -ENOTCONN;
		goto exit;
	}

	/* will be updated in set_orig_addr() if needed */
	m->msg_namelen = 0;

	target = sock_rcvlowat(sk, flags & MSG_WAITALL, buf_len);
	timeout = sock_rcvtimeo(sk, flags & MSG_DONTWAIT);

restart:
	/* Look for a message in receive queue; wait if necessary */
	while (skb_queue_empty(&sk->sk_receive_queue)) {
		if (sock->state == SS_DISCONNECTING) {
			res = -ENOTCONN;
			goto exit;
		}
		if (timeout <= 0L) {
			res = timeout ? timeout : -EWOULDBLOCK;
			goto exit;
		}
		release_sock(sk);
		timeout = wait_event_interruptible_timeout(*sk_sleep(sk),
							   tipc_rx_ready(sock),
							   timeout);
		lock_sock(sk);
	}

	/* Look at first message in receive queue */
	buf = skb_peek(&sk->sk_receive_queue);
	msg = buf_msg(buf);
	sz = msg_data_sz(msg);
	err = msg_errcode(msg);

	/* Discard an empty non-errored message & try again */
	if ((!sz) && (!err)) {
		advance_rx_queue(sk);
		goto restart;
	}

	/* Optionally capture sender's address & ancillary data of first msg */
	if (sz_copied == 0) {
		set_orig_addr(m, msg);
		res = anc_data_recv(m, msg, tport);
		if (res)
			goto exit;
	}

	/* Capture message data (if valid) & compute return value (always) */
	if (!err) {
		u32 offset = (u32)(unsigned long)(TIPC_SKB_CB(buf)->handle);

		sz -= offset;
		needed = (buf_len - sz_copied);
		sz_to_copy = (sz <= needed) ? sz : needed;

		res = skb_copy_datagram_iovec(buf, msg_hdr_sz(msg) + offset,
					      m->msg_iov, sz_to_copy);
		if (res)
			goto exit;

		sz_copied += sz_to_copy;

		if (sz_to_copy < sz) {
			if (!(flags & MSG_PEEK))
				TIPC_SKB_CB(buf)->handle =
				(void *)(unsigned long)(offset + sz_to_copy);
			goto exit;
		}
	} else {
		if (sz_copied != 0)
			goto exit; /* can't add error msg to valid data */

		if ((err == TIPC_CONN_SHUTDOWN) || m->msg_control)
			res = 0;
		else
			res = -ECONNRESET;
	}

	/* Consume received message (optional) */
	if (likely(!(flags & MSG_PEEK))) {
		if (unlikely(++tport->conn_unacked >= TIPC_FLOW_CONTROL_WIN))
			tipc_acknowledge(tport->ref, tport->conn_unacked);
		advance_rx_queue(sk);
	}

	/* Loop around if more data is required */
	if ((sz_copied < buf_len) &&	/* didn't get all requested data */
	    (!skb_queue_empty(&sk->sk_receive_queue) ||
	    (sz_copied < target)) &&	/* and more is ready or required */
	    (!(flags & MSG_PEEK)) &&	/* and aren't just peeking at data */
	    (!err))			/* and haven't reached a FIN */
		goto restart;

exit:
	release_sock(sk);
	return sz_copied ? sz_copied : res;
}

/**
 * tipc_write_space - wake up thread if port congestion is released
 * @sk: socket
 */
static void tipc_write_space(struct sock *sk)
{
	struct socket_wq *wq;

	rcu_read_lock();
	wq = rcu_dereference(sk->sk_wq);
	if (wq_has_sleeper(wq))
		wake_up_interruptible_sync_poll(&wq->wait, POLLOUT |
						POLLWRNORM | POLLWRBAND);
	rcu_read_unlock();
}

/**
 * tipc_data_ready - wake up threads to indicate messages have been received
 * @sk: socket
 * @len: the length of messages
 */
static void tipc_data_ready(struct sock *sk, int len)
{
	struct socket_wq *wq;

	rcu_read_lock();
	wq = rcu_dereference(sk->sk_wq);
	if (wq_has_sleeper(wq))
		wake_up_interruptible_sync_poll(&wq->wait, POLLIN |
						POLLRDNORM | POLLRDBAND);
	rcu_read_unlock();
}

/**
 * filter_connect - Handle all incoming messages for a connection-based socket
 * @tsock: TIPC socket
 * @msg: message
 *
 * Returns TIPC error status code and socket error status code
 * once it encounters some errors
 */
static u32 filter_connect(struct tipc_sock *tsock, struct sk_buff **buf)
{
	struct socket *sock = tsock->sk.sk_socket;
	struct tipc_msg *msg = buf_msg(*buf);
	struct sock *sk = &tsock->sk;
	u32 retval = TIPC_ERR_NO_PORT;
	int res;

	if (msg_mcast(msg))
		return retval;

	switch ((int)sock->state) {
	case SS_CONNECTED:
		/* Accept only connection-based messages sent by peer */
		if (msg_connected(msg) && tipc_port_peer_msg(tsock->p, msg)) {
			if (unlikely(msg_errcode(msg))) {
				sock->state = SS_DISCONNECTING;
				__tipc_disconnect(tsock->p);
			}
			retval = TIPC_OK;
		}
		break;
	case SS_CONNECTING:
		/* Accept only ACK or NACK message */
		if (unlikely(msg_errcode(msg))) {
			sock->state = SS_DISCONNECTING;
			sk->sk_err = ECONNREFUSED;
			retval = TIPC_OK;
			break;
		}

		if (unlikely(!msg_connected(msg)))
			break;

		res = auto_connect(sock, msg);
		if (res) {
			sock->state = SS_DISCONNECTING;
			sk->sk_err = -res;
			retval = TIPC_OK;
			break;
		}

		/* If an incoming message is an 'ACK-', it should be
 * discarded here because it doesn't contain useful
 * data. In addition, we should try to wake up
 * connect() routine if sleeping.
 */
		if (msg_data_sz(msg) == 0) {
			kfree_skb(*buf);
			*buf = NULL;
			if (waitqueue_active(sk_sleep(sk)))
				wake_up_interruptible(sk_sleep(sk));
		}
		retval = TIPC_OK;
		break;
	case SS_LISTENING:
	case SS_UNCONNECTED:
		/* Accept only SYN message */
		if (!msg_connected(msg) && !(msg_errcode(msg)))
			retval = TIPC_OK;
		break;
	case SS_DISCONNECTING:
		break;
	default:
		pr_err("Unknown socket state %u\n", sock->state);
	}
	return retval;
}

/**
 * rcvbuf_limit - get proper overload limit of socket receive queue
 * @sk: socket
 * @buf: message
 *
 * For all connection oriented messages, irrespective of importance,
 * the default overload value (i.e. 67MB) is set as limit.
 *
 * For all connectionless messages, by default new queue limits are
 * as belows:
 *
 * TIPC_LOW_IMPORTANCE (4 MB)
 * TIPC_MEDIUM_IMPORTANCE (8 MB)
 * TIPC_HIGH_IMPORTANCE (16 MB)
 * TIPC_CRITICAL_IMPORTANCE (32 MB)
 *
 * Returns overload limit according to corresponding message importance
 */
static unsigned int rcvbuf_limit(struct sock *sk, struct sk_buff *buf)
{
	struct tipc_msg *msg = buf_msg(buf);
	unsigned int limit;

	if (msg_connected(msg))
		limit = sysctl_tipc_rmem[2];
	else
		limit = sk->sk_rcvbuf >> TIPC_CRITICAL_IMPORTANCE <<
			msg_importance(msg);
	return limit;
}

/**
 * filter_rcv - validate incoming message
 * @sk: socket
 * @buf: message
 *
 * Enqueues message on receive queue if acceptable; optionally handles
 * disconnect indication for a connected socket.
 *
 * Called with socket lock already taken; port lock may also be taken.
 *
 * Returns TIPC error status code (TIPC_OK if message is not to be rejected)
 */
static u32 filter_rcv(struct sock *sk, struct sk_buff *buf)
{
	struct socket *sock = sk->sk_socket;
	struct tipc_msg *msg = buf_msg(buf);
	unsigned int limit = rcvbuf_limit(sk, buf);
	u32 res = TIPC_OK;

	/* Reject message if it is wrong sort of message for socket */
	if (msg_type(msg) > TIPC_DIRECT_MSG)
		return TIPC_ERR_NO_PORT;

	if (sock->state == SS_READY) {
		if (msg_connected(msg))
			return TIPC_ERR_NO_PORT;
	} else {
		res = filter_connect(tipc_sk(sk), &buf);
		if (res != TIPC_OK || buf == NULL)
			return res;
	}

	/* Reject message if there isn't room to queue it */
	if (sk_rmem_alloc_get(sk) + buf->truesize >= limit)
		return TIPC_ERR_OVERLOAD;

	/* Enqueue message */
	TIPC_SKB_CB(buf)->handle = NULL;
	__skb_queue_tail(&sk->sk_receive_queue, buf);
	skb_set_owner_r(buf, sk);

	sk->sk_data_ready(sk, 0);
	return TIPC_OK;
}

/**
 * backlog_rcv - handle incoming message from backlog queue
 * @sk: socket
 * @buf: message
 *
 * Caller must hold socket lock, but not port lock.
 *
 * Returns 0
 */
static int backlog_rcv(struct sock *sk, struct sk_buff *buf)
{
	u32 res;

	res = filter_rcv(sk, buf);
	if (res)
		tipc_reject_msg(buf, res);
	return 0;
}

/**
 * dispatch - handle incoming message
 * @tport: TIPC port that received message
 * @buf: message
 *
 * Called with port lock already taken.
 *
 * Returns TIPC error status code (TIPC_OK if message is not to be rejected)
 */
static u32 dispatch(struct tipc_port *tport, struct sk_buff *buf)
{
	struct sock *sk = tport->sk;
	u32 res;

	/*
 * Process message if socket is unlocked; otherwise add to backlog queue
 *
 * This code is based on sk_receive_skb(), but must be distinct from it
 * since a TIPC-specific filter/reject mechanism is utilized
 */
	bh_lock_sock(sk);
	if (!sock_owned_by_user(sk)) {
		res = filter_rcv(sk, buf);
	} else {
		if (sk_add_backlog(sk, buf, rcvbuf_limit(sk, buf)))
			res = TIPC_ERR_OVERLOAD;
		else
			res = TIPC_OK;
	}
	bh_unlock_sock(sk);

	return res;
}

/**
 * wakeupdispatch - wake up port after congestion
 * @tport: port to wakeup
 *
 * Called with port lock already taken.
 */
static void wakeupdispatch(struct tipc_port *tport)
{
	struct sock *sk = tport->sk;

	sk->sk_write_space(sk);
}

/**
 * connect - establish a connection to another TIPC port
 * @sock: socket structure
 * @dest: socket address for destination port
 * @destlen: size of socket address data structure
 * @flags: file-related flags associated with socket
 *
 * Returns 0 on success, errno otherwise
 */
static int connect(struct socket *sock, struct sockaddr *dest, int destlen,
		   int flags)
{
	struct sock *sk = sock->sk;
	struct sockaddr_tipc *dst = (struct sockaddr_tipc *)dest;
	struct msghdr m = {NULL,};
	unsigned int timeout;
	int res;

	lock_sock(sk);

	/* For now, TIPC does not allow use of connect() with DGRAM/RDM types */
	if (sock->state == SS_READY) {
		res = -EOPNOTSUPP;
		goto exit;
	}

	/*
 * Reject connection attempt using multicast address
 *
 * Note: send_msg() validates the rest of the address fields,
 * so there's no need to do it here
 */
	if (dst->addrtype == TIPC_ADDR_MCAST) {
		res = -EINVAL;
		goto exit;
	}

	timeout = (flags & O_NONBLOCK) ? 0 : tipc_sk(sk)->conn_timeout;

	switch (sock->state) {
	case SS_UNCONNECTED:
		/* Send a 'SYN-' to destination */
		m.msg_name = dest;
		m.msg_namelen = destlen;

		/* If connect is in non-blocking case, set MSG_DONTWAIT to
 * indicate send_msg() is never blocked.
 */
		if (!timeout)
			m.msg_flags = MSG_DONTWAIT;

		res = send_msg(NULL, sock, &m, 0);
		if ((res < 0) && (res != -EWOULDBLOCK))
			goto exit;

		/* Just entered SS_CONNECTING state; the only
 * difference is that return value in non-blocking
 * case is EINPROGRESS, rather than EALREADY.
 */
		res = -EINPROGRESS;
		break;
	case SS_CONNECTING:
		res = -EALREADY;
		break;
	case SS_CONNECTED:
		res = -EISCONN;
		break;
	default:
		res = -EINVAL;
		goto exit;
	}

	if (sock->state == SS_CONNECTING) {
		if (!timeout)
			goto exit;

		/* Wait until an 'ACK' or 'RST' arrives, or a timeout occurs */
		release_sock(sk);
		res = wait_event_interruptible_timeout(*sk_sleep(sk),
				sock->state != SS_CONNECTING,
				timeout ? (long)msecs_to_jiffies(timeout)
					: MAX_SCHEDULE_TIMEOUT);
		lock_sock(sk);
		if (res <= 0) {
			if (res == 0)
				res = -ETIMEDOUT;
			else
				; /* leave "res" unchanged */
			goto exit;
		}
	}

	if (unlikely(sock->state == SS_DISCONNECTING))
		res = sock_error(sk);
	else
		res = 0;

exit:
	release_sock(sk);
	return res;
}

/**
 * listen - allow socket to listen for incoming connections
 * @sock: socket structure
 * @len: (unused)
 *
 * Returns 0 on success, errno otherwise
 */
static int listen(struct socket *sock, int len)
{
	struct sock *sk = sock->sk;
	int res;

	lock_sock(sk);

	if (sock->state != SS_UNCONNECTED)
		res = -EINVAL;
	else {
		sock->state = SS_LISTENING;
		res = 0;
	}

	release_sock(sk);
	return res;
}

/**
 * accept - wait for connection request
 * @sock: listening socket
 * @newsock: new socket that is to be connected
 * @flags: file-related flags associated with socket
 *
 * Returns 0 on success, errno otherwise
 */
static int accept(struct socket *sock, struct socket *new_sock, int flags)
{
	struct sock *new_sk, *sk = sock->sk;
	struct sk_buff *buf;
	struct tipc_sock *new_tsock;
	struct tipc_port *new_tport;
	struct tipc_msg *msg;
	u32 new_ref;

	int res;

	lock_sock(sk);

	if (sock->state != SS_LISTENING) {
		res = -EINVAL;
		goto exit;
	}

	while (skb_queue_empty(&sk->sk_receive_queue)) {
		if (flags & O_NONBLOCK) {
			res = -EWOULDBLOCK;
			goto exit;
		}
		release_sock(sk);
		res = wait_event_interruptible(*sk_sleep(sk),
				(!skb_queue_empty(&sk->sk_receive_queue)));
		lock_sock(sk);
		if (res)
			goto exit;
	}

	buf = skb_peek(&sk->sk_receive_queue);

	res = tipc_sk_create(sock_net(sock->sk), new_sock, 0, 1);
	if (res)
		goto exit;

	new_sk = new_sock->sk;
	new_tsock = tipc_sk(new_sk);
	new_tport = new_tsock->p;
	new_ref = new_tport->ref;
	msg = buf_msg(buf);

	/* we lock on new_sk; but lockdep sees the lock on sk */
	lock_sock_nested(new_sk, SINGLE_DEPTH_NESTING);

	/*
 * Reject any stray messages received by new socket
 * before the socket lock was taken (very, very unlikely)
 */
	reject_rx_queue(new_sk);

	/* Connect new socket to it's peer */
	new_tsock->peer_name.ref = msg_origport(msg);
	new_tsock->peer_name.node = msg_orignode(msg);
	tipc_connect(new_ref, &new_tsock->peer_name);
	new_sock->state = SS_CONNECTED;

	tipc_set_portimportance(new_ref, msg_importance(msg));
	if (msg_named(msg)) {
		new_tport->conn_type = msg_nametype(msg);
		new_tport->conn_instance = msg_nameinst(msg);
	}

	/*
 * Respond to 'SYN-' by discarding it & returning 'ACK'-.
 * Respond to 'SYN+' by queuing it on new socket.
 */
	if (!msg_data_sz(msg)) {
		struct msghdr m = {NULL,};

		advance_rx_queue(sk);
		send_packet(NULL, new_sock, &m, 0);
	} else {
		__skb_dequeue(&sk->sk_receive_queue);
		__skb_queue_head(&new_sk->sk_receive_queue, buf);
		skb_set_owner_r(buf, new_sk);
	}
	release_sock(new_sk);

exit:
	release_sock(sk);
	return res;
}

/**
 * shutdown - shutdown socket connection
 * @sock: socket structure
 * @how: direction to close (must be SHUT_RDWR)
 *
 * Terminates connection (if necessary), then purges socket's receive queue.
 *
 * Returns 0 on success, errno otherwise
 */
static int shutdown(struct socket *sock, int how)
{
	struct sock *sk = sock->sk;
	struct tipc_port *tport = tipc_sk_port(sk);
	struct sk_buff *buf;
	int res;

	if (how != SHUT_RDWR)
		return -EINVAL;

	lock_sock(sk);

	switch (sock->state) {
	case SS_CONNECTING:
	case SS_CONNECTED:

restart:
		/* Disconnect and send a 'FIN+' or 'FIN-' message to peer */
		buf = __skb_dequeue(&sk->sk_receive_queue);
		if (buf) {
			if (TIPC_SKB_CB(buf)->handle != NULL) {
				kfree_skb(buf);
				goto restart;
			}
			tipc_disconnect(tport->ref);
			tipc_reject_msg(buf, TIPC_CONN_SHUTDOWN);
		} else {
			tipc_shutdown(tport->ref);
		}

		sock->state = SS_DISCONNECTING;

		/* fall through */

	case SS_DISCONNECTING:

		/* Discard any unreceived messages */
		__skb_queue_purge(&sk->sk_receive_queue);

		/* Wake up anyone sleeping in poll */
		sk->sk_state_change(sk);
		res = 0;
		break;

	default:
		res = -ENOTCONN;
	}

	release_sock(sk);
	return res;
}

/**
 * setsockopt - set socket option
 * @sock: socket structure
 * @lvl: option level
 * @opt: option identifier
 * @ov: pointer to new option value
 * @ol: length of option value
 *
 * For stream sockets only, accepts and ignores all IPPROTO_TCP options
 * (to ease compatibility).
 *
 * Returns 0 on success, errno otherwise
 */
static int setsockopt(struct socket *sock, int lvl, int opt, char __user *ov,
		      unsigned int ol)
{
	struct sock *sk = sock->sk;
	struct tipc_port *tport = tipc_sk_port(sk);
	u32 value;
	int res;

	if ((lvl == IPPROTO_TCP) && (sock->type == SOCK_STREAM))
		return 0;
	if (lvl != SOL_TIPC)
		return -ENOPROTOOPT;
	if (ol < sizeof(value))
		return -EINVAL;
	res = get_user(value, (u32 __user *)ov);
	if (res)
		return res;

	lock_sock(sk);

	switch (opt) {
	case TIPC_IMPORTANCE:
		res = tipc_set_portimportance(tport->ref, value);
		break;
	case TIPC_SRC_DROPPABLE:
		if (sock->type != SOCK_STREAM)
			res = tipc_set_portunreliable(tport->ref, value);
		else
			res = -ENOPROTOOPT;
		break;
	case TIPC_DEST_DROPPABLE:
		res = tipc_set_portunreturnable(tport->ref, value);
		break;
	case TIPC_CONN_TIMEOUT:
		tipc_sk(sk)->conn_timeout = value;
		/* no need to set "res", since already 0 at this point */
		break;
	default:
		res = -EINVAL;
	}

	release_sock(sk);

	return res;
}

/**
 * getsockopt - get socket option
 * @sock: socket structure
 * @lvl: option level
 * @opt: option identifier
 * @ov: receptacle for option value
 * @ol: receptacle for length of option value
 *
 * For stream sockets only, returns 0 length result for all IPPROTO_TCP options
 * (to ease compatibility).
 *
 * Returns 0 on success, errno otherwise
 */
static int getsockopt(struct socket *sock, int lvl, int opt, char __user *ov,
		      int __user *ol)
{
	struct sock *sk = sock->sk;
	struct tipc_port *tport = tipc_sk_port(sk);
	int len;
	u32 value;
	int res;

	if ((lvl == IPPROTO_TCP) && (sock->type == SOCK_STREAM))
		return put_user(0, ol);
	if (lvl != SOL_TIPC)
		return -ENOPROTOOPT;
	res = get_user(len, ol);
	if (res)
		return res;

	lock_sock(sk);

	switch (opt) {
	case TIPC_IMPORTANCE:
		res = tipc_portimportance(tport->ref, &value);
		break;
	case TIPC_SRC_DROPPABLE:
		res = tipc_portunreliable(tport->ref, &value);
		break;
	case TIPC_DEST_DROPPABLE:
		res = tipc_portunreturnable(tport->ref, &value);
		break;
	case TIPC_CONN_TIMEOUT:
		value = tipc_sk(sk)->conn_timeout;
		/* no need to set "res", since already 0 at this point */
		break;
	case TIPC_NODE_RECVQ_DEPTH:
		value = 0; /* was tipc_queue_size, now obsolete */
		break;
	case TIPC_SOCK_RECVQ_DEPTH:
		value = skb_queue_len(&sk->sk_receive_queue);
		break;
	default:
		res = -EINVAL;
	}

	release_sock(sk);

	if (res)
		return res;	/* "get" failed */

	if (len < sizeof(value))
		return -EINVAL;

	if (copy_to_user(ov, &value, sizeof(value)))
		return -EFAULT;

	return put_user(sizeof(value), ol);
}

/* Protocol switches for the various types of TIPC sockets */

static const struct proto_ops msg_ops = {
	.owner		= THIS_MODULE,
	.family		= AF_TIPC,
	.release	= release,
	.bind		= bind,
	.connect	= connect,
	.socketpair	= sock_no_socketpair,
	.accept		= sock_no_accept,
	.getname	= get_name,
	.poll		= poll,
	.ioctl		= sock_no_ioctl,
	.listen		= sock_no_listen,
	.shutdown	= shutdown,
	.setsockopt	= setsockopt,
	.getsockopt	= getsockopt,
	.sendmsg	= send_msg,
	.recvmsg	= recv_msg,
	.mmap		= sock_no_mmap,
	.sendpage	= sock_no_sendpage
};

static const struct proto_ops packet_ops = {
	.owner		= THIS_MODULE,
	.family		= AF_TIPC,
	.release	= release,
	.bind		= bind,
	.connect	= connect,
	.socketpair	= sock_no_socketpair,
	.accept		= accept,
	.getname	= get_name,
	.poll		= poll,
	.ioctl		= sock_no_ioctl,
	.listen		= listen,
	.shutdown	= shutdown,
	.setsockopt	= setsockopt,
	.getsockopt	= getsockopt,
	.sendmsg	= send_packet,
	.recvmsg	= recv_msg,
	.mmap		= sock_no_mmap,
	.sendpage	= sock_no_sendpage
};

static const struct proto_ops stream_ops = {
	.owner		= THIS_MODULE,
	.family		= AF_TIPC,
	.release	= release,
	.bind		= bind,
	.connect	= connect,
	.socketpair	= sock_no_socketpair,
	.accept		= accept,
	.getname	= get_name,
	.poll		= poll,
	.ioctl		= sock_no_ioctl,
	.listen		= listen,
	.shutdown	= shutdown,
	.setsockopt	= setsockopt,
	.getsockopt	= getsockopt,
	.sendmsg	= send_stream,
	.recvmsg	= recv_stream,
	.mmap		= sock_no_mmap,
	.sendpage	= sock_no_sendpage
};

static const struct net_proto_family tipc_family_ops = {
	.owner		= THIS_MODULE,
	.family		= AF_TIPC,
	.create		= tipc_sk_create
};

static struct proto tipc_proto = {
	.name		= "TIPC",
	.owner		= THIS_MODULE,
	.obj_size	= sizeof(struct tipc_sock),
	.sysctl_rmem	= sysctl_tipc_rmem
};

static struct proto tipc_proto_kern = {
	.name		= "TIPC",
	.obj_size	= sizeof(struct tipc_sock),
	.sysctl_rmem	= sysctl_tipc_rmem
};

/**
 * tipc_socket_init - initialize TIPC socket interface
 *
 * Returns 0 on success, errno otherwise
 */
int tipc_socket_init(void)
{
	int res;

	res = proto_register(&tipc_proto, 1);
	if (res) {
		pr_err("Failed to register TIPC protocol type\n");
		goto out;
	}

	res = sock_register(&tipc_family_ops);
	if (res) {
		pr_err("Failed to register TIPC socket type\n");
		proto_unregister(&tipc_proto);
		goto out;
	}

	sockets_enabled = 1;
 out:
	return res;
}

/**
 * tipc_socket_stop - stop TIPC socket interface
 */
void tipc_socket_stop(void)
{
	if (!sockets_enabled)
		return;

	sockets_enabled = 0;
	sock_unregister(tipc_family_ops.family);
	proto_unregister(&tipc_proto);
}