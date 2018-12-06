

#include <linux/mount.h>
#include <linux/seq_file.h>
#include <linux/poll.h>
#include <linux/ns_common.h>
#include <linux/fs_pin.h>

struct mnt_namespace {
	atomic_t		count;
	struct ns_common	ns;
	struct mount *	root;
	struct list_head	list;
	struct user_namespace	*user_ns;
	struct ucounts		*ucounts;
	u64			seq;	/* Sequence number to prevent loops */
	wait_queue_head_t poll;
	u64 event;
};

struct mnt_pcp {
	int mnt_count;
	int mnt_writers;
};

struct mountpoint {
	struct hlist_node m_hash;
	struct dentry *m_dentry;
	struct hlist_head m_list;
	int m_count;
};

struct mount {
	struct hlist_node mnt_hash;
	struct mount *mnt_parent;
	struct dentry *mnt_mountpoint;
	struct vfsmount mnt;
	union {
		struct rcu_head mnt_rcu;
		struct llist_node mnt_llist;
	};
#ifdef CONFIG_SMP
	struct mnt_pcp __percpu *mnt_pcp;
#else
	int mnt_count;
	int mnt_writers;
#endif
	struct list_head mnt_mounts;	/* list of children, anchored here */
	struct list_head mnt_child;	/* and going through their mnt_child */
	struct list_head mnt_instance;	/* mount instance on sb->s_mounts */
	const char *mnt_devname;	/* Name of device e.g. /dev/dsk/hda1 */
	struct list_head mnt_list;
	struct list_head mnt_expire;	/* link in fs-specific expiry list */
	struct list_head mnt_share;	/* circular list of shared mounts */
	struct list_head mnt_slave_list;/* list of slave mounts */
	struct list_head mnt_slave;	/* slave list entry */
	struct mount *mnt_master;	/* slave is on master->mnt_slave_list */
	struct mnt_namespace *mnt_ns;	/* containing namespace */
	struct mountpoint *mnt_mp;	/* where is it mounted */
	struct hlist_node mnt_mp_list;	/* list mounts with the same mountpoint */
#ifdef CONFIG_FSNOTIFY
	struct hlist_head mnt_fsnotify_marks;
	__u32 mnt_fsnotify_mask;
#endif
	int mnt_id;			/* mount identifier */
	int mnt_group_id;		/* peer group identifier */
	int mnt_expiry_mark;		/* true if marked for expiry */
	struct hlist_head mnt_pins;
	struct fs_pin mnt_umount;
	struct dentry *mnt_ex_mountpoint;
};

#define MNT_NS_INTERNAL ERR_PTR(-EINVAL) /* distinct from any mnt_namespace */

static inline struct mount *real_mount(struct vfsmount *mnt)
{
	return container_of(mnt, struct mount, mnt);
}

static inline int mnt_has_parent(struct mount *mnt)
{
	return mnt != mnt->mnt_parent;
}

static inline int is_mounted(struct vfsmount *mnt)
{
	/* neither detached nor internal? */
	return !IS_ERR_OR_NULL(real_mount(mnt)->mnt_ns);
}

extern struct mount *__lookup_mnt(struct vfsmount *, struct dentry *);
extern struct mount *__lookup_mnt_last(struct vfsmount *, struct dentry *);

extern int __legitimize_mnt(struct vfsmount *, unsigned);
extern bool legitimize_mnt(struct vfsmount *, unsigned);

extern void __detach_mounts(struct dentry *dentry);

static inline void detach_mounts(struct dentry *dentry)
{
	if (!d_mountpoint(dentry))
		return;
	__detach_mounts(dentry);
}

static inline void get_mnt_ns(struct mnt_namespace *ns)
{
	atomic_inc(&ns->count);
}

extern seqlock_t mount_lock;

static inline void lock_mount_hash(void)
{
	write_seqlock(&mount_lock);
}

static inline void unlock_mount_hash(void)
{
	write_sequnlock(&mount_lock);
}

struct proc_mounts {
	struct mnt_namespace *ns;
	struct path root;
	int (*show)(struct seq_file *, struct vfsmount *);
	void *cached_mount;
	u64 cached_event;
	loff_t cached_index;
};

extern const struct seq_operations mounts_op;

extern bool __is_local_mountpoint(struct dentry *dentry);
static inline bool is_local_mountpoint(struct dentry *dentry)
{
	if (!d_mountpoint(dentry))
		return false;

	return __is_local_mountpoint(dentry);
}

/*
 *
 * Definitions for mount interface. This describes the in the kernel build 
 * linkedlist with mounted filesystems.
 *
 * Author: Marco van Wieringen <mvw@planets.elm.net>
 *
 */
#ifndef _LINUX_MOUNT_H
#define _LINUX_MOUNT_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/nodemask.h>
#include <linux/spinlock.h>
#include <linux/seqlock.h>
#include <linux/atomic.h>

struct super_block;
struct vfsmount;
struct dentry;
struct mnt_namespace;

#define MNT_NOSUID 0x01
#define MNT_NODEV 0x02
#define MNT_NOEXEC 0x04
#define MNT_NOATIME 0x08
#define MNT_NODIRATIME 0x10
#define MNT_RELATIME 0x20
#define MNT_READONLY 0x40	/* does the user want this to be r/o? */

#define MNT_SHRINKABLE 0x100
#define MNT_WRITE_HOLD 0x200

#define MNT_SHARED 0x1000	/* if the vfsmount is a shared mount */
#define MNT_UNBINDABLE 0x2000	/* if the vfsmount is a unbindable mount */
/*
 * MNT_SHARED_MASK is the set of flags that should be cleared when a
 * mount becomes shared. Currently, this is only the flag that says a
 * mount cannot be bind mounted, since this is how we create a mount
 * that shares events with another mount. If you add a new MNT_*
 * flag, consider how it interacts with shared mounts.
 */
#define MNT_SHARED_MASK (MNT_UNBINDABLE)
#define MNT_USER_SETTABLE_MASK (MNT_NOSUID | MNT_NODEV | MNT_NOEXEC \
 | MNT_NOATIME | MNT_NODIRATIME | MNT_RELATIME \
 | MNT_READONLY)
#define MNT_ATIME_MASK (MNT_NOATIME | MNT_NODIRATIME | MNT_RELATIME )

#define MNT_INTERNAL_FLAGS (MNT_SHARED | MNT_WRITE_HOLD | MNT_INTERNAL | \
 MNT_DOOMED | MNT_SYNC_UMOUNT | MNT_MARKED)

#define MNT_INTERNAL 0x4000

#define MNT_LOCK_ATIME 0x040000
#define MNT_LOCK_NOEXEC 0x080000
#define MNT_LOCK_NOSUID 0x100000
#define MNT_LOCK_NODEV 0x200000
#define MNT_LOCK_READONLY 0x400000
#define MNT_LOCKED 0x800000
#define MNT_DOOMED 0x1000000
#define MNT_SYNC_UMOUNT 0x2000000
#define MNT_MARKED 0x4000000
#define MNT_UMOUNT 0x8000000

struct vfsmount {
	struct dentry *mnt_root;	/* root of the mounted tree */
	struct super_block *mnt_sb;	/* pointer to superblock */
	int mnt_flags;
};

struct file; /* forward dec */
struct path;

extern int mnt_want_write(struct vfsmount *mnt);
extern int mnt_want_write_file(struct file *file);
extern int mnt_clone_write(struct vfsmount *mnt);
extern void mnt_drop_write(struct vfsmount *mnt);
extern void mnt_drop_write_file(struct file *file);
extern void mntput(struct vfsmount *mnt);
extern struct vfsmount *mntget(struct vfsmount *mnt);
extern struct vfsmount *mnt_clone_internal(struct path *path);
extern int __mnt_is_readonly(struct vfsmount *mnt);
extern bool mnt_may_suid(struct vfsmount *mnt);

struct path;
extern struct vfsmount *clone_private_mount(struct path *path);

struct file_system_type;
extern struct vfsmount *vfs_kern_mount(struct file_system_type *type,
				      int flags, const char *name,
				      void *data);

extern void mnt_set_expiry(struct vfsmount *mnt, struct list_head *expiry_list);
extern void mark_mounts_for_expiry(struct list_head *mounts);

extern dev_t name_to_dev_t(const char *name);

#endif /* _LINUX_MOUNT_H */