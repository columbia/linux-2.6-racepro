/*
 * Copyright (C) 2010 Oren Laadan <orenl@cs.columbia.edu>
 * Copyright (C) 2010 Nicolas Viennot <nicolas@viennot.biz>
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of the Linux
 *  distribution for more details.
 */

#include <linux/scribe.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <net/sock.h>
#include <linux/syscalls.h>

static int scribe_release(struct socket *sock)
{
	return sock->real_ops->release(sock);
}

static int scribe_bind(struct socket *sock, struct sockaddr *myaddr,
		       int sockaddr_len)
{
	return sock->real_ops->bind(sock, myaddr, sockaddr_len);
}

static int scribe_connect(struct socket *sock, struct sockaddr *vaddr,
			  int sockaddr_len, int flags)
{
	struct scribe_ps *scribe = current->scribe;

	if (scribe_need_syscall_ret(scribe))
		return -ENOMEM;

	if (is_replaying(scribe) && sock->real_ops->family != PF_UNIX) {
		/* Faking the connection */
		return scribe->orig_ret;
	}

	return sock->real_ops->connect(sock, vaddr, sockaddr_len, flags);
}

static int scribe_socketpair(struct socket *sock1, struct socket *sock2)
{
	return sock1->real_ops->socketpair(sock1, sock2);
}

static int scribe_accept(struct socket *sock, struct socket *newsock, int flags)
{
	struct scribe_ps *scribe = current->scribe;

	if (is_replaying(scribe)) {
		/* Faking the accept. newsock will stay unconnected */
		/* TODO do we have to do newsock->state SS_CONNECTED ? */
		return 0;
	}

	return sock->real_ops->accept(sock, newsock, flags);
}

static int scribe_getname(struct socket *sock, struct sockaddr *addr,
			  int *sockaddr_len, int peer)
{
	struct scribe_ps *scribe = current->scribe;
	int ret;

	if (scribe_need_syscall_ret(scribe))
		return -ENOMEM;

	if (is_replaying(scribe)) {
		ret = scribe->orig_ret;
		if (ret < 0)
			return ret;

		if (scribe_interpose_value_replay(scribe,
					  sockaddr_len, sizeof(*sockaddr_len)))
			scribe_emergency_stop(scribe->ctx, ERR_PTR(-EDIVERGE));

		else if (scribe_interpose_value_replay(scribe,
					  addr, *sockaddr_len))
			scribe_emergency_stop(scribe->ctx, ERR_PTR(-EDIVERGE));
	} else {
		ret = sock->real_ops->getname(sock, addr, sockaddr_len, peer);
		if (scribe_interpose_value_record(scribe,
					  sockaddr_len, sizeof(*sockaddr_len)))
			ret = -ENOMEM;

		else if (scribe_interpose_value_record(scribe,
					  addr, *sockaddr_len))
			ret = -ENOMEM;
	}

	return ret;
}

static unsigned int scribe_poll(struct file *file, struct socket *sock,
				struct poll_table_struct *wait)
{
	return sock->real_ops->poll(file, sock, wait);
}

static int scribe_ioctl(struct socket *sock, unsigned int cmd,
			unsigned long arg)
{
	int ret;
	scribe_data_non_det();
	ret = sock->real_ops->ioctl(sock, cmd, arg);
	scribe_data_pop_flags();
	return ret;
}

#ifdef CONFIG_COMPAT
static int scribe_compat_ioctl(struct socket *sock, unsigned int cmd,
			       unsigned long arg)
{
	if (!sock->real_ops->compat_ioctl)
		return -ENOIOCTLCMD;
	return sock->real_ops->compat_ioctl(sock, cmd, arg);
}
#endif

static int scribe_listen(struct socket *sock, int len)
{
	return sock->real_ops->listen(sock, len);
}

static int scribe_shutdown(struct socket *sock, int flags)
{
	return sock->real_ops->shutdown(sock, flags);
}

static int scribe_setsockopt(struct socket *sock, int level,
			     int optname, char __user *optval,
			     unsigned int optlen)
{
	return sock->real_ops->setsockopt(sock, level, optname, optval, optlen);
}

static int scribe_getsockopt(struct socket *sock, int level,
			     int optname, char __user *optval,
			     int __user *optlen)
{
	return sock->real_ops->getsockopt(sock, level, optname, optval, optlen);
}

#ifdef CONFIG_COMPAT
static int scribe_compat_setsockopt(struct socket *sock, int level,
				    int optname, char __user *optval,
				    unsigned int optlen)
{
	return sock->real_ops->setsockopt(sock, level, optname, optval, optlen);
}

static int scribe_compat_getsockopt(struct socket *sock, int level,
				    int optname, char __user *optval,
				    int __user *optlen)
{
	return sock->real_ops->getsockopt(sock, level, optname, optval, optlen);
}
#endif

static int scribe_sendmsg(struct kiocb *iocb, struct socket *sock,
			  struct msghdr *m, size_t total_len)
{
	struct scribe_ps *scribe = current->scribe;
	int ret;

	/*
	 * FIXME For now we'll use the syscall return value even though it's
	 * incorrect.
	 */
	if (scribe_need_syscall_ret(scribe))
		return -ENOMEM;

	scribe_data_need_info();

	if (is_replaying(scribe)) {
		ret = scribe->orig_ret;
		if (ret <= 0)
			goto out;

		ret = scribe_emul_copy_from_user(scribe, NULL, ret);
	} else
		ret = sock->real_ops->sendmsg(iocb, sock, m, total_len);

out:
	scribe_data_pop_flags();
	return ret;
}

static int scribe_recvmsg(struct kiocb *iocb, struct socket *sock,
			  struct msghdr *m, size_t total_len,
			  int flags)
{
	struct scribe_ps *scribe = current->scribe;
	int ret;

	/*
	 * FIXME For now we'll use the syscall return value even though it's
	 * incorrect.
	 */
	if (scribe_need_syscall_ret(scribe))
		return -ENOMEM;

	scribe_data_non_det_need_info();

	if (is_replaying(scribe)) {
		ret = scribe->orig_ret;
		if (ret <= 0)
			goto out;

		ret = scribe_emul_copy_to_user(scribe, NULL, ret);
		if (scribe_interpose_value_replay(scribe,
					  &m->msg_namelen, sizeof(m->msg_namelen)))
			scribe_emergency_stop(scribe->ctx, ERR_PTR(-EDIVERGE));
		else if (scribe_interpose_value_replay(scribe,
						  m->msg_name, m->msg_namelen))
			scribe_emergency_stop(scribe->ctx, ERR_PTR(-EDIVERGE));
	} else {
		ret = sock->real_ops->recvmsg(iocb, sock, m, total_len, flags);

		if (ret > 0) {
			if (scribe_interpose_value_record(scribe,
						  &m->msg_namelen, sizeof(m->msg_namelen)))
				ret = -ENOMEM;
			else if (scribe_interpose_value_record(scribe,
							  m->msg_name, m->msg_namelen))
				ret = -ENOMEM;
		}
	}

out:
	scribe_data_pop_flags();
	return ret;
}

static int scribe_mmap(struct file *file, struct socket *sock,
		       struct vm_area_struct * vma)
{
	return sock_no_mmap(file, sock, vma);
}

static ssize_t scribe_sendpage(struct socket *sock, struct page *page,
			       int offset, size_t size, int flags)
{
	if (!sock->real_ops->sendpage)
		sock_no_sendpage(sock, page, offset, size, flags);
	return sock->real_ops->sendpage(sock, page, offset, size, flags);
}

static ssize_t scribe_splice_read(struct socket *sock,  loff_t *ppos,
				  struct pipe_inode_info *pipe, size_t len,
				  unsigned int flags)
{
	if (unlikely(!sock->real_ops->splice_read))
		return -EINVAL;
	return sock->real_ops->splice_read(sock, ppos, pipe, len, flags);
}


const struct proto_ops scribe_ops = {
	.family            = PF_UNSPEC,
	.owner             = THIS_MODULE,
	.release           = scribe_release,
	.bind              = scribe_bind,
	.connect           = scribe_connect,
	.socketpair        = scribe_socketpair,
	.accept            = scribe_accept,
	.getname           = scribe_getname,
	.poll              = scribe_poll,
	.ioctl             = scribe_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl      = scribe_compat_ioctl,
#endif
	.listen            = scribe_listen,
	.shutdown          = scribe_shutdown,
	.getsockopt        = scribe_getsockopt,
	.setsockopt        = scribe_setsockopt,
#ifdef CONFIG_COMPAT
	.compat_setsockopt = scribe_compat_setsockopt,
	.compat_getsockopt = scribe_compat_getsockopt,
#endif
	.sendmsg           = scribe_sendmsg,
	.recvmsg           = scribe_recvmsg,
	.mmap              = scribe_mmap,
	.sendpage          = scribe_sendpage,
	.splice_read       = scribe_splice_read,
};

int scribe_interpose_socket(struct socket *sock)
{
	struct scribe_ps *scribe = current->scribe;

	if (!is_scribed(scribe))
		return 0;

	sock->real_ops = sock->ops;
	sock->ops = &scribe_ops;

	return 0;
}
