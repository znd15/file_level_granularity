

#ifndef _ASM_IA64_COMPAT_H
#define _ASM_IA64_COMPAT_H
/*
 * Architecture specific compatibility types
 */
#include <linux/types.h>

#define COMPAT_USER_HZ 100
#define COMPAT_UTS_MACHINE	"i686\0\0\0"

typedef u32		compat_size_t;
typedef s32		compat_ssize_t;
typedef s32		compat_time_t;
typedef s32		compat_clock_t;
typedef s32		compat_key_t;
typedef s32		compat_pid_t;
typedef u16		__compat_uid_t;
typedef u16		__compat_gid_t;
typedef u32		__compat_uid32_t;
typedef u32		__compat_gid32_t;
typedef u16		compat_mode_t;
typedef u32		compat_ino_t;
typedef u16		compat_dev_t;
typedef s32		compat_off_t;
typedef s64		compat_loff_t;
typedef u16		compat_nlink_t;
typedef u16		compat_ipc_pid_t;
typedef s32		compat_daddr_t;
typedef u32		compat_caddr_t;
typedef __kernel_fsid_t	compat_fsid_t;
typedef s32		compat_timer_t;

typedef s32		compat_int_t;
typedef s32		compat_long_t;
typedef s64 __attribute__((aligned(4))) compat_s64;
typedef u32		compat_uint_t;
typedef u32		compat_ulong_t;
typedef u64 __attribute__((aligned(4))) compat_u64;

struct compat_timespec {
	compat_time_t	tv_sec;
	s32		tv_nsec;
};

struct compat_timeval {
	compat_time_t	tv_sec;
	s32		tv_usec;
};

struct compat_stat {
	compat_dev_t	st_dev;
	u16		__pad1;
	compat_ino_t	st_ino;
	compat_mode_t	st_mode;
	compat_nlink_t	st_nlink;
	__compat_uid_t	st_uid;
	__compat_gid_t	st_gid;
	compat_dev_t	st_rdev;
	u16		__pad2;
	u32		st_size;
	u32		st_blksize;
	u32		st_blocks;
	u32		st_atime;
	u32		st_atime_nsec;
	u32		st_mtime;
	u32		st_mtime_nsec;
	u32		st_ctime;
	u32		st_ctime_nsec;
	u32		__unused4;
	u32		__unused5;
};

struct compat_flock {
	short		l_type;
	short		l_whence;
	compat_off_t	l_start;
	compat_off_t	l_len;
	compat_pid_t	l_pid;
};

#define F_GETLK64 12
#define F_SETLK64 13
#define F_SETLKW64 14

/*
 * IA32 uses 4 byte alignment for 64 bit quantities,
 * so we need to pack this structure.
 */
struct compat_flock64 {
	short		l_type;
	short		l_whence;
	compat_loff_t	l_start;
	compat_loff_t	l_len;
	compat_pid_t	l_pid;
} __attribute__((packed));

struct compat_statfs {
	int		f_type;
	int		f_bsize;
	int		f_blocks;
	int		f_bfree;
	int		f_bavail;
	int		f_files;
	int		f_ffree;
	compat_fsid_t	f_fsid;
	int		f_namelen;	/* SunOS ignores this field. */
	int		f_frsize;
	int		f_spare[5];
};

#define COMPAT_RLIM_OLD_INFINITY 0x7fffffff
#define COMPAT_RLIM_INFINITY 0xffffffff

typedef u32		compat_old_sigset_t;	/* at least 32 bits */

#define _COMPAT_NSIG 64
#define _COMPAT_NSIG_BPW 32

typedef u32		compat_sigset_word;

#define COMPAT_OFF_T_MAX 0x7fffffff
#define COMPAT_LOFF_T_MAX 0x7fffffffffffffffL

struct compat_ipc64_perm {
	compat_key_t key;
	__compat_uid32_t uid;
	__compat_gid32_t gid;
	__compat_uid32_t cuid;
	__compat_gid32_t cgid;
	unsigned short mode;
	unsigned short __pad1;
	unsigned short seq;
	unsigned short __pad2;
	compat_ulong_t unused1;
	compat_ulong_t unused2;
};

struct compat_semid64_ds {
	struct compat_ipc64_perm sem_perm;
	compat_time_t  sem_otime;
	compat_ulong_t __unused1;
	compat_time_t  sem_ctime;
	compat_ulong_t __unused2;
	compat_ulong_t sem_nsems;
	compat_ulong_t __unused3;
	compat_ulong_t __unused4;
};

struct compat_msqid64_ds {
	struct compat_ipc64_perm msg_perm;
	compat_time_t  msg_stime;
	compat_ulong_t __unused1;
	compat_time_t  msg_rtime;
	compat_ulong_t __unused2;
	compat_time_t  msg_ctime;
	compat_ulong_t __unused3;
	compat_ulong_t msg_cbytes;
	compat_ulong_t msg_qnum;
	compat_ulong_t msg_qbytes;
	compat_pid_t   msg_lspid;
	compat_pid_t   msg_lrpid;
	compat_ulong_t __unused4;
	compat_ulong_t __unused5;
};

struct compat_shmid64_ds {
	struct compat_ipc64_perm shm_perm;
	compat_size_t  shm_segsz;
	compat_time_t  shm_atime;
	compat_ulong_t __unused1;
	compat_time_t  shm_dtime;
	compat_ulong_t __unused2;
	compat_time_t  shm_ctime;
	compat_ulong_t __unused3;
	compat_pid_t   shm_cpid;
	compat_pid_t   shm_lpid;
	compat_ulong_t shm_nattch;
	compat_ulong_t __unused4;
	compat_ulong_t __unused5;
};

/*
 * A pointer passed in from user mode. This should not be used for syscall parameters,
 * just declare them as pointers because the syscall entry code will have appropriately
 * converted them already.
 */
typedef	u32		compat_uptr_t;

static inline void __user *
compat_ptr (compat_uptr_t uptr)
{
	return (void __user *) (unsigned long) uptr;
}

static inline compat_uptr_t
ptr_to_compat(void __user *uptr)
{
	return (u32)(unsigned long)uptr;
}

static __inline__ void __user *
compat_alloc_user_space (long len)
{
	struct pt_regs *regs = task_pt_regs(current);
	return (void __user *) (((regs->r12 & 0xffffffff) & -16) - len);
}

#endif /* _ASM_IA64_COMPAT_H */

#ifndef _ASM_COMPAT_H
#define _ASM_COMPAT_H
/*
 * Architecture specific compatibility types
 */
#include <linux/thread_info.h>
#include <linux/types.h>
#include <asm/page.h>
#include <asm/ptrace.h>

#define COMPAT_USER_HZ 100
#define COMPAT_UTS_MACHINE	"mips\0\0\0"

typedef u32		compat_size_t;
typedef s32		compat_ssize_t;
typedef s32		compat_time_t;
typedef s32		compat_clock_t;
typedef s32		compat_suseconds_t;

typedef s32		compat_pid_t;
typedef s32		__compat_uid_t;
typedef s32		__compat_gid_t;
typedef __compat_uid_t	__compat_uid32_t;
typedef __compat_gid_t	__compat_gid32_t;
typedef u32		compat_mode_t;
typedef u32		compat_ino_t;
typedef u32		compat_dev_t;
typedef s32		compat_off_t;
typedef s64		compat_loff_t;
typedef u32		compat_nlink_t;
typedef s32		compat_ipc_pid_t;
typedef s32		compat_daddr_t;
typedef s32		compat_caddr_t;
typedef struct {
	s32	val[2];
} compat_fsid_t;
typedef s32		compat_timer_t;
typedef s32		compat_key_t;

typedef s32		compat_int_t;
typedef s32		compat_long_t;
typedef s64		compat_s64;
typedef u32		compat_uint_t;
typedef u32		compat_ulong_t;
typedef u64		compat_u64;

struct compat_timespec {
	compat_time_t	tv_sec;
	s32		tv_nsec;
};

struct compat_timeval {
	compat_time_t	tv_sec;
	s32		tv_usec;
};

struct compat_stat {
	compat_dev_t	st_dev;
	s32		st_pad1[3];
	compat_ino_t	st_ino;
	compat_mode_t	st_mode;
	compat_nlink_t	st_nlink;
	__compat_uid_t	st_uid;
	__compat_gid_t	st_gid;
	compat_dev_t	st_rdev;
	s32		st_pad2[2];
	compat_off_t	st_size;
	s32		st_pad3;
	compat_time_t	st_atime;
	s32		st_atime_nsec;
	compat_time_t	st_mtime;
	s32		st_mtime_nsec;
	compat_time_t	st_ctime;
	s32		st_ctime_nsec;
	s32		st_blksize;
	s32		st_blocks;
	s32		st_pad4[14];
};

struct compat_flock {
	short		l_type;
	short		l_whence;
	compat_off_t	l_start;
	compat_off_t	l_len;
	s32		l_sysid;
	compat_pid_t	l_pid;
	short		__unused;
	s32		pad[4];
};

#define F_GETLK64 33
#define F_SETLK64 34
#define F_SETLKW64 35

struct compat_flock64 {
	short		l_type;
	short		l_whence;
	compat_loff_t	l_start;
	compat_loff_t	l_len;
	compat_pid_t	l_pid;
};

struct compat_statfs {
	int		f_type;
	int		f_bsize;
	int		f_frsize;
	int		f_blocks;
	int		f_bfree;
	int		f_files;
	int		f_ffree;
	int		f_bavail;
	compat_fsid_t	f_fsid;
	int		f_namelen;
	int		f_spare[6];
};

#define COMPAT_RLIM_INFINITY 0x7fffffffUL

typedef u32		compat_old_sigset_t;	/* at least 32 bits */

#define _COMPAT_NSIG 128		/* Don't ask !$@#% ... */
#define _COMPAT_NSIG_BPW 32

typedef u32		compat_sigset_word;

#define COMPAT_OFF_T_MAX 0x7fffffff
#define COMPAT_LOFF_T_MAX 0x7fffffffffffffffL

/*
 * A pointer passed in from user mode. This should not
 * be used for syscall parameters, just declare them
 * as pointers because the syscall entry code will have
 * appropriately converted them already.
 */
typedef u32		compat_uptr_t;

static inline void __user *compat_ptr(compat_uptr_t uptr)
{
	/* cast to a __user pointer via "unsigned long" makes sparse happy */
	return (void __user *)(unsigned long)(long)uptr;
}

static inline compat_uptr_t ptr_to_compat(void __user *uptr)
{
	return (u32)(unsigned long)uptr;
}

static inline void __user *compat_alloc_user_space(long len)
{
	struct pt_regs *regs = (struct pt_regs *)
		((unsigned long) current_thread_info() + THREAD_SIZE - 32) - 1;

	return (void __user *) (regs->regs[29] - len);
}

struct compat_ipc64_perm {
	compat_key_t key;
	__compat_uid32_t uid;
	__compat_gid32_t gid;
	__compat_uid32_t cuid;
	__compat_gid32_t cgid;
	compat_mode_t mode;
	unsigned short seq;
	unsigned short __pad2;
	compat_ulong_t __unused1;
	compat_ulong_t __unused2;
};

struct compat_semid64_ds {
	struct compat_ipc64_perm sem_perm;
	compat_time_t	sem_otime;
	compat_time_t	sem_ctime;
	compat_ulong_t	sem_nsems;
	compat_ulong_t	__unused1;
	compat_ulong_t	__unused2;
};

struct compat_msqid64_ds {
	struct compat_ipc64_perm msg_perm;
#ifndef CONFIG_CPU_LITTLE_ENDIAN
	compat_ulong_t	__unused1;
#endif
	compat_time_t	msg_stime;
#ifdef CONFIG_CPU_LITTLE_ENDIAN
	compat_ulong_t	__unused1;
#endif
#ifndef CONFIG_CPU_LITTLE_ENDIAN
	compat_ulong_t	__unused2;
#endif
	compat_time_t	msg_rtime;
#ifdef CONFIG_CPU_LITTLE_ENDIAN
	compat_ulong_t	__unused2;
#endif
#ifndef CONFIG_CPU_LITTLE_ENDIAN
	compat_ulong_t	__unused3;
#endif
	compat_time_t	msg_ctime;
#ifdef CONFIG_CPU_LITTLE_ENDIAN
	compat_ulong_t	__unused3;
#endif
	compat_ulong_t	msg_cbytes;
	compat_ulong_t	msg_qnum;
	compat_ulong_t	msg_qbytes;
	compat_pid_t	msg_lspid;
	compat_pid_t	msg_lrpid;
	compat_ulong_t	__unused4;
	compat_ulong_t	__unused5;
};

struct compat_shmid64_ds {
	struct compat_ipc64_perm shm_perm;
	compat_size_t	shm_segsz;
	compat_time_t	shm_atime;
	compat_time_t	shm_dtime;
	compat_time_t	shm_ctime;
	compat_pid_t	shm_cpid;
	compat_pid_t	shm_lpid;
	compat_ulong_t	shm_nattch;
	compat_ulong_t	__unused1;
	compat_ulong_t	__unused2;
};

static inline int is_compat_task(void)
{
	return test_thread_flag(TIF_32BIT);
}

#endif /* _ASM_COMPAT_H */

#ifndef _ASM_PARISC_COMPAT_H
#define _ASM_PARISC_COMPAT_H
/*
 * Architecture specific compatibility types
 */
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/thread_info.h>

#define COMPAT_USER_HZ 100
#define COMPAT_UTS_MACHINE	"parisc\0\0"

typedef u32	compat_size_t;
typedef s32	compat_ssize_t;
typedef s32	compat_time_t;
typedef s32	compat_clock_t;
typedef s32	compat_pid_t;
typedef u32	__compat_uid_t;
typedef u32	__compat_gid_t;
typedef u32	__compat_uid32_t;
typedef u32	__compat_gid32_t;
typedef u16	compat_mode_t;
typedef u32	compat_ino_t;
typedef u32	compat_dev_t;
typedef s32	compat_off_t;
typedef s64	compat_loff_t;
typedef u16	compat_nlink_t;
typedef u16	compat_ipc_pid_t;
typedef s32	compat_daddr_t;
typedef u32	compat_caddr_t;
typedef s32	compat_timer_t;

typedef s32	compat_int_t;
typedef s32	compat_long_t;
typedef s64	compat_s64;
typedef u32	compat_uint_t;
typedef u32	compat_ulong_t;
typedef u64	compat_u64;

struct compat_timespec {
	compat_time_t		tv_sec;
	s32			tv_nsec;
};

struct compat_timeval {
	compat_time_t		tv_sec;
	s32			tv_usec;
};

struct compat_stat {
	compat_dev_t		st_dev;	/* dev_t is 32 bits on parisc */
	compat_ino_t		st_ino;	/* 32 bits */
	compat_mode_t		st_mode;	/* 16 bits */
	compat_nlink_t  	st_nlink;	/* 16 bits */
	u16			st_reserved1;	/* old st_uid */
	u16			st_reserved2;	/* old st_gid */
	compat_dev_t		st_rdev;
	compat_off_t		st_size;
	compat_time_t		st_atime;
	u32			st_atime_nsec;
	compat_time_t		st_mtime;
	u32			st_mtime_nsec;
	compat_time_t		st_ctime;
	u32			st_ctime_nsec;
	s32			st_blksize;
	s32			st_blocks;
	u32			__unused1;	/* ACL stuff */
	compat_dev_t		__unused2;	/* network */
	compat_ino_t		__unused3;	/* network */
	u32			__unused4;	/* cnodes */
	u16			__unused5;	/* netsite */
	short			st_fstype;
	compat_dev_t		st_realdev;
	u16			st_basemode;
	u16			st_spareshort;
	__compat_uid32_t	st_uid;
	__compat_gid32_t	st_gid;
	u32			st_spare4[3];
};

struct compat_flock {
	short			l_type;
	short			l_whence;
	compat_off_t		l_start;
	compat_off_t		l_len;
	compat_pid_t		l_pid;
};

struct compat_flock64 {
	short			l_type;
	short			l_whence;
	compat_loff_t		l_start;
	compat_loff_t		l_len;
	compat_pid_t		l_pid;
};

struct compat_statfs {
	s32		f_type;
	s32		f_bsize;
	s32		f_blocks;
	s32		f_bfree;
	s32		f_bavail;
	s32		f_files;
	s32		f_ffree;
	__kernel_fsid_t	f_fsid;
	s32		f_namelen;
	s32		f_frsize;
	s32		f_spare[5];
};

struct compat_sigcontext {
	compat_int_t sc_flags;
	compat_int_t sc_gr[32]; /* PSW in sc_gr[0] */
	u64 sc_fr[32];
	compat_int_t sc_iasq[2];
	compat_int_t sc_iaoq[2];
	compat_int_t sc_sar; /* cr11 */
};

#define COMPAT_RLIM_INFINITY 0xffffffff

typedef u32		compat_old_sigset_t;	/* at least 32 bits */

#define _COMPAT_NSIG 64
#define _COMPAT_NSIG_BPW 32

typedef u32		compat_sigset_word;

#define COMPAT_OFF_T_MAX 0x7fffffff
#define COMPAT_LOFF_T_MAX 0x7fffffffffffffffL

/*
 * A pointer passed in from user mode. This should not
 * be used for syscall parameters, just declare them
 * as pointers because the syscall entry code will have
 * appropriately converted them already.
 */
typedef	u32		compat_uptr_t;

static inline void __user *compat_ptr(compat_uptr_t uptr)
{
	return (void __user *)(unsigned long)uptr;
}

static inline compat_uptr_t ptr_to_compat(void __user *uptr)
{
	return (u32)(unsigned long)uptr;
}

static __inline__ void __user *compat_alloc_user_space(long len)
{
	struct pt_regs *regs = &current->thread.regs;
	return (void __user *)regs->gr[30];
}

static inline int __is_compat_task(struct task_struct *t)
{
	return test_ti_thread_flag(task_thread_info(t), TIF_32BIT);
}

static inline int is_compat_task(void)
{
	return __is_compat_task(current);
}

#endif /* _ASM_PARISC_COMPAT_H */

#ifndef _ASM_POWERPC_COMPAT_H
#define _ASM_POWERPC_COMPAT_H
#ifdef __KERNEL__
/*
 * Architecture specific compatibility types
 */
#include <linux/types.h>
#include <linux/sched.h>

#define COMPAT_USER_HZ 100
#define COMPAT_UTS_MACHINE	"ppc\0\0"

typedef u32		compat_size_t;
typedef s32		compat_ssize_t;
typedef s32		compat_time_t;
typedef s32		compat_clock_t;
typedef s32		compat_pid_t;
typedef u32		__compat_uid_t;
typedef u32		__compat_gid_t;
typedef u32		__compat_uid32_t;
typedef u32		__compat_gid32_t;
typedef u32		compat_mode_t;
typedef u32		compat_ino_t;
typedef u32		compat_dev_t;
typedef s32		compat_off_t;
typedef s64		compat_loff_t;
typedef s16		compat_nlink_t;
typedef u16		compat_ipc_pid_t;
typedef s32		compat_daddr_t;
typedef u32		compat_caddr_t;
typedef __kernel_fsid_t	compat_fsid_t;
typedef s32		compat_key_t;
typedef s32		compat_timer_t;

typedef s32		compat_int_t;
typedef s32		compat_long_t;
typedef s64		compat_s64;
typedef u32		compat_uint_t;
typedef u32		compat_ulong_t;
typedef u64		compat_u64;

struct compat_timespec {
	compat_time_t	tv_sec;
	s32		tv_nsec;
};

struct compat_timeval {
	compat_time_t	tv_sec;
	s32		tv_usec;
};

struct compat_stat {
	compat_dev_t	st_dev;
	compat_ino_t	st_ino;
	compat_mode_t	st_mode;
	compat_nlink_t	st_nlink;
	__compat_uid32_t	st_uid;
	__compat_gid32_t	st_gid;
	compat_dev_t	st_rdev;
	compat_off_t	st_size;
	compat_off_t	st_blksize;
	compat_off_t	st_blocks;
	compat_time_t	st_atime;
	u32		st_atime_nsec;
	compat_time_t	st_mtime;
	u32		st_mtime_nsec;
	compat_time_t	st_ctime;
	u32		st_ctime_nsec;
	u32		__unused4[2];
};

struct compat_flock {
	short		l_type;
	short		l_whence;
	compat_off_t	l_start;
	compat_off_t	l_len;
	compat_pid_t	l_pid;
};

#define F_GETLK64 12	/* using 'struct flock64' */
#define F_SETLK64 13
#define F_SETLKW64 14

struct compat_flock64 {
	short		l_type;
	short		l_whence;
	compat_loff_t	l_start;
	compat_loff_t	l_len;
	compat_pid_t	l_pid;
};

struct compat_statfs {
	int		f_type;
	int		f_bsize;
	int		f_blocks;
	int		f_bfree;
	int		f_bavail;
	int		f_files;
	int		f_ffree;
	compat_fsid_t	f_fsid;
	int		f_namelen;	/* SunOS ignores this field. */
	int		f_frsize;
	int		f_spare[5];
};

#define COMPAT_RLIM_OLD_INFINITY 0x7fffffff
#define COMPAT_RLIM_INFINITY 0xffffffff

typedef u32		compat_old_sigset_t;

#define _COMPAT_NSIG 64
#define _COMPAT_NSIG_BPW 32

typedef u32		compat_sigset_word;

#define COMPAT_OFF_T_MAX 0x7fffffff
#define COMPAT_LOFF_T_MAX 0x7fffffffffffffffL

/*
 * A pointer passed in from user mode. This should not
 * be used for syscall parameters, just declare them
 * as pointers because the syscall entry code will have
 * appropriately converted them already.
 */
typedef	u32		compat_uptr_t;

static inline void __user *compat_ptr(compat_uptr_t uptr)
{
	return (void __user *)(unsigned long)uptr;
}

static inline compat_uptr_t ptr_to_compat(void __user *uptr)
{
	return (u32)(unsigned long)uptr;
}

static inline void __user *compat_alloc_user_space(long len)
{
	struct pt_regs *regs = current->thread.regs;
	unsigned long usp = regs->gpr[1];

	/*
 * We cant access below the stack pointer in the 32bit ABI and
 * can access 288 bytes in the 64bit ABI
 */
	if (!(test_thread_flag(TIF_32BIT)))
		usp -= 288;

	return (void __user *) (usp - len);
}

/*
 * ipc64_perm is actually 32/64bit clean but since the compat layer refers to
 * it we may as well define it.
 */
struct compat_ipc64_perm {
	compat_key_t key;
	__compat_uid_t uid;
	__compat_gid_t gid;
	__compat_uid_t cuid;
	__compat_gid_t cgid;
	compat_mode_t mode;
	unsigned int seq;
	unsigned int __pad2;
	unsigned long __unused1;	/* yes they really are 64bit pads */
	unsigned long __unused2;
};

struct compat_semid64_ds {
	struct compat_ipc64_perm sem_perm;
	unsigned int __unused1;
	compat_time_t sem_otime;
	unsigned int __unused2;
	compat_time_t sem_ctime;
	compat_ulong_t sem_nsems;
	compat_ulong_t __unused3;
	compat_ulong_t __unused4;
};

struct compat_msqid64_ds {
	struct compat_ipc64_perm msg_perm;
	unsigned int __unused1;
	compat_time_t msg_stime;
	unsigned int __unused2;
	compat_time_t msg_rtime;
	unsigned int __unused3;
	compat_time_t msg_ctime;
	compat_ulong_t msg_cbytes;
	compat_ulong_t msg_qnum;
	compat_ulong_t msg_qbytes;
	compat_pid_t msg_lspid;
	compat_pid_t msg_lrpid;
	compat_ulong_t __unused4;
	compat_ulong_t __unused5;
};

struct compat_shmid64_ds {
	struct compat_ipc64_perm shm_perm;
	unsigned int __unused1;
	compat_time_t shm_atime;
	unsigned int __unused2;
	compat_time_t shm_dtime;
	unsigned int __unused3;
	compat_time_t shm_ctime;
	unsigned int __unused4;
	compat_size_t shm_segsz;
	compat_pid_t shm_cpid;
	compat_pid_t shm_lpid;
	compat_ulong_t shm_nattch;
	compat_ulong_t __unused5;
	compat_ulong_t __unused6;
};

static inline int is_compat_task(void)
{
	return test_thread_flag(TIF_32BIT);
}

#endif /* __KERNEL__ */
#endif /* _ASM_POWERPC_COMPAT_H */

#ifndef _ASM_S390X_COMPAT_H
#define _ASM_S390X_COMPAT_H
/*
 * Architecture specific compatibility types
 */
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/thread_info.h>

#define PSW32_MASK_PER 0x40000000UL
#define PSW32_MASK_DAT 0x04000000UL
#define PSW32_MASK_IO 0x02000000UL
#define PSW32_MASK_EXT 0x01000000UL
#define PSW32_MASK_KEY 0x00F00000UL
#define PSW32_MASK_MCHECK 0x00040000UL
#define PSW32_MASK_WAIT 0x00020000UL
#define PSW32_MASK_PSTATE 0x00010000UL
#define PSW32_MASK_ASC 0x0000C000UL
#define PSW32_MASK_CC 0x00003000UL
#define PSW32_MASK_PM 0x00000f00UL

#define PSW32_ADDR_AMODE31 0x80000000UL
#define PSW32_ADDR_INSN 0x7FFFFFFFUL

#define PSW32_BASE_BITS 0x00080000UL

#define PSW32_ASC_PRIMARY 0x00000000UL
#define PSW32_ASC_ACCREG 0x00004000UL
#define PSW32_ASC_SECONDARY 0x00008000UL
#define PSW32_ASC_HOME 0x0000C000UL

#define PSW32_MASK_MERGE(CURRENT,NEW) \
 (((CURRENT) & ~(PSW32_MASK_CC|PSW32_MASK_PM)) | \
 ((NEW) & (PSW32_MASK_CC|PSW32_MASK_PM)))

extern long psw32_user_bits;

#define COMPAT_USER_HZ 100
#define COMPAT_UTS_MACHINE	"s390\0\0\0\0"

typedef u32		compat_size_t;
typedef s32		compat_ssize_t;
typedef s32		compat_time_t;
typedef s32		compat_clock_t;
typedef s32		compat_pid_t;
typedef u16		__compat_uid_t;
typedef u16		__compat_gid_t;
typedef u32		__compat_uid32_t;
typedef u32		__compat_gid32_t;
typedef u16		compat_mode_t;
typedef u32		compat_ino_t;
typedef u16		compat_dev_t;
typedef s32		compat_off_t;
typedef s64		compat_loff_t;
typedef u16		compat_nlink_t;
typedef u16		compat_ipc_pid_t;
typedef s32		compat_daddr_t;
typedef u32		compat_caddr_t;
typedef __kernel_fsid_t	compat_fsid_t;
typedef s32		compat_key_t;
typedef s32		compat_timer_t;

typedef s32		compat_int_t;
typedef s32		compat_long_t;
typedef s64		compat_s64;
typedef u32		compat_uint_t;
typedef u32		compat_ulong_t;
typedef u64		compat_u64;

struct compat_timespec {
	compat_time_t	tv_sec;
	s32		tv_nsec;
};

struct compat_timeval {
	compat_time_t	tv_sec;
	s32		tv_usec;
};

struct compat_stat {
	compat_dev_t	st_dev;
	u16		__pad1;
	compat_ino_t	st_ino;
	compat_mode_t	st_mode;
	compat_nlink_t	st_nlink;
	__compat_uid_t	st_uid;
	__compat_gid_t	st_gid;
	compat_dev_t	st_rdev;
	u16		__pad2;
	u32		st_size;
	u32		st_blksize;
	u32		st_blocks;
	u32		st_atime;
	u32		st_atime_nsec;
	u32		st_mtime;
	u32		st_mtime_nsec;
	u32		st_ctime;
	u32		st_ctime_nsec;
	u32		__unused4;
	u32		__unused5;
};

struct compat_flock {
	short		l_type;
	short		l_whence;
	compat_off_t	l_start;
	compat_off_t	l_len;
	compat_pid_t	l_pid;
};

#define F_GETLK64 12
#define F_SETLK64 13
#define F_SETLKW64 14 

struct compat_flock64 {
	short		l_type;
	short		l_whence;
	compat_loff_t	l_start;
	compat_loff_t	l_len;
	compat_pid_t	l_pid;
};

struct compat_statfs {
	s32		f_type;
	s32		f_bsize;
	s32		f_blocks;
	s32		f_bfree;
	s32		f_bavail;
	s32		f_files;
	s32		f_ffree;
	compat_fsid_t	f_fsid;
	s32		f_namelen;
	s32		f_frsize;
	s32		f_spare[6];
};

#define COMPAT_RLIM_OLD_INFINITY 0x7fffffff
#define COMPAT_RLIM_INFINITY 0xffffffff

typedef u32		compat_old_sigset_t;	/* at least 32 bits */

#define _COMPAT_NSIG 64
#define _COMPAT_NSIG_BPW 32

typedef u32		compat_sigset_word;

#define COMPAT_OFF_T_MAX 0x7fffffff
#define COMPAT_LOFF_T_MAX 0x7fffffffffffffffL

/*
 * A pointer passed in from user mode. This should not
 * be used for syscall parameters, just declare them
 * as pointers because the syscall entry code will have
 * appropriately converted them already.
 */
typedef	u32		compat_uptr_t;

static inline void __user *compat_ptr(compat_uptr_t uptr)
{
	return (void __user *)(unsigned long)(uptr & 0x7fffffffUL);
}

static inline compat_uptr_t ptr_to_compat(void __user *uptr)
{
	return (u32)(unsigned long)uptr;
}

#ifdef CONFIG_COMPAT

static inline int is_compat_task(void)
{
	return test_thread_flag(TIF_31BIT);
}

#else

static inline int is_compat_task(void)
{
	return 0;
}

#endif

static inline void __user *compat_alloc_user_space(long len)
{
	unsigned long stack;

	stack = KSTK_ESP(current);
	if (is_compat_task())
		stack &= 0x7fffffffUL;
	return (void __user *) (stack - len);
}

struct compat_ipc64_perm {
	compat_key_t key;
	__compat_uid32_t uid;
	__compat_gid32_t gid;
	__compat_uid32_t cuid;
	__compat_gid32_t cgid;
	compat_mode_t mode;
	unsigned short __pad1;
	unsigned short seq;
	unsigned short __pad2;
	unsigned int __unused1;
	unsigned int __unused2;
};

struct compat_semid64_ds {
	struct compat_ipc64_perm sem_perm;
	compat_time_t  sem_otime;
	compat_ulong_t __pad1;
	compat_time_t  sem_ctime;
	compat_ulong_t __pad2;
	compat_ulong_t sem_nsems;
	compat_ulong_t __unused1;
	compat_ulong_t __unused2;
};

struct compat_msqid64_ds {
	struct compat_ipc64_perm msg_perm;
	compat_time_t   msg_stime;
	compat_ulong_t __pad1;
	compat_time_t   msg_rtime;
	compat_ulong_t __pad2;
	compat_time_t   msg_ctime;
	compat_ulong_t __pad3;
	compat_ulong_t msg_cbytes;
	compat_ulong_t msg_qnum;
	compat_ulong_t msg_qbytes;
	compat_pid_t   msg_lspid;
	compat_pid_t   msg_lrpid;
	compat_ulong_t __unused1;
	compat_ulong_t __unused2;
};

struct compat_shmid64_ds {
	struct compat_ipc64_perm shm_perm;
	compat_size_t  shm_segsz;
	compat_time_t  shm_atime;
	compat_ulong_t __pad1;
	compat_time_t  shm_dtime;
	compat_ulong_t __pad2;
	compat_time_t  shm_ctime;
	compat_ulong_t __pad3;
	compat_pid_t   shm_cpid;
	compat_pid_t   shm_lpid;
	compat_ulong_t shm_nattch;
	compat_ulong_t __unused1;
	compat_ulong_t __unused2;
};
#endif /* _ASM_S390X_COMPAT_H */

#ifndef _ASM_SPARC64_COMPAT_H
#define _ASM_SPARC64_COMPAT_H
/*
 * Architecture specific compatibility types
 */
#include <linux/types.h>

#define COMPAT_USER_HZ 100
#define COMPAT_UTS_MACHINE	"sparc\0\0"

typedef u32		compat_size_t;
typedef s32		compat_ssize_t;
typedef s32		compat_time_t;
typedef s32		compat_clock_t;
typedef s32		compat_pid_t;
typedef u16		__compat_uid_t;
typedef u16		__compat_gid_t;
typedef u32		__compat_uid32_t;
typedef u32		__compat_gid32_t;
typedef u16		compat_mode_t;
typedef u32		compat_ino_t;
typedef u16		compat_dev_t;
typedef s32		compat_off_t;
typedef s64		compat_loff_t;
typedef s16		compat_nlink_t;
typedef u16		compat_ipc_pid_t;
typedef s32		compat_daddr_t;
typedef u32		compat_caddr_t;
typedef __kernel_fsid_t	compat_fsid_t;
typedef s32		compat_key_t;
typedef s32		compat_timer_t;

typedef s32		compat_int_t;
typedef s32		compat_long_t;
typedef s64		compat_s64;
typedef u32		compat_uint_t;
typedef u32		compat_ulong_t;
typedef u64		compat_u64;

struct compat_timespec {
	compat_time_t	tv_sec;
	s32		tv_nsec;
};

struct compat_timeval {
	compat_time_t	tv_sec;
	s32		tv_usec;
};

struct compat_stat {
	compat_dev_t	st_dev;
	compat_ino_t	st_ino;
	compat_mode_t	st_mode;
	compat_nlink_t	st_nlink;
	__compat_uid_t	st_uid;
	__compat_gid_t	st_gid;
	compat_dev_t	st_rdev;
	compat_off_t	st_size;
	compat_time_t	st_atime;
	compat_ulong_t	st_atime_nsec;
	compat_time_t	st_mtime;
	compat_ulong_t	st_mtime_nsec;
	compat_time_t	st_ctime;
	compat_ulong_t	st_ctime_nsec;
	compat_off_t	st_blksize;
	compat_off_t	st_blocks;
	u32		__unused4[2];
};

struct compat_stat64 {
	unsigned long long	st_dev;

	unsigned long long	st_ino;

	unsigned int	st_mode;
	unsigned int	st_nlink;

	unsigned int	st_uid;
	unsigned int	st_gid;

	unsigned long long	st_rdev;

	unsigned char	__pad3[8];

	long long	st_size;
	unsigned int	st_blksize;

	unsigned char	__pad4[8];
	unsigned int	st_blocks;

	unsigned int	st_atime;
	unsigned int	st_atime_nsec;

	unsigned int	st_mtime;
	unsigned int	st_mtime_nsec;

	unsigned int	st_ctime;
	unsigned int	st_ctime_nsec;

	unsigned int	__unused4;
	unsigned int	__unused5;
};

struct compat_flock {
	short		l_type;
	short		l_whence;
	compat_off_t	l_start;
	compat_off_t	l_len;
	compat_pid_t	l_pid;
	short		__unused;
};

#define F_GETLK64 12
#define F_SETLK64 13
#define F_SETLKW64 14

struct compat_flock64 {
	short		l_type;
	short		l_whence;
	compat_loff_t	l_start;
	compat_loff_t	l_len;
	compat_pid_t	l_pid;
	short		__unused;
};

struct compat_statfs {
	int		f_type;
	int		f_bsize;
	int		f_blocks;
	int		f_bfree;
	int		f_bavail;
	int		f_files;
	int		f_ffree;
	compat_fsid_t	f_fsid;
	int		f_namelen;	/* SunOS ignores this field. */
	int		f_frsize;
	int		f_spare[5];
};

#define COMPAT_RLIM_INFINITY 0x7fffffff

typedef u32		compat_old_sigset_t;

#define _COMPAT_NSIG 64
#define _COMPAT_NSIG_BPW 32

typedef u32		compat_sigset_word;

#define COMPAT_OFF_T_MAX 0x7fffffff
#define COMPAT_LOFF_T_MAX 0x7fffffffffffffffL

/*
 * A pointer passed in from user mode. This should not
 * be used for syscall parameters, just declare them
 * as pointers because the syscall entry code will have
 * appropriately converted them already.
 */
typedef	u32		compat_uptr_t;

static inline void __user *compat_ptr(compat_uptr_t uptr)
{
	return (void __user *)(unsigned long)uptr;
}

static inline compat_uptr_t ptr_to_compat(void __user *uptr)
{
	return (u32)(unsigned long)uptr;
}

static inline void __user *compat_alloc_user_space(long len)
{
	struct pt_regs *regs = current_thread_info()->kregs;
	unsigned long usp = regs->u_regs[UREG_I6];

	if (!(test_thread_flag(TIF_32BIT)))
		usp += STACK_BIAS;
	else
		usp &= 0xffffffffUL;

	usp -= len;
	usp &= ~0x7UL;

	return (void __user *) usp;
}

struct compat_ipc64_perm {
	compat_key_t key;
	__compat_uid32_t uid;
	__compat_gid32_t gid;
	__compat_uid32_t cuid;
	__compat_gid32_t cgid;
	unsigned short __pad1;
	compat_mode_t mode;
	unsigned short __pad2;
	unsigned short seq;
	unsigned long __unused1;	/* yes they really are 64bit pads */
	unsigned long __unused2;
};

struct compat_semid64_ds {
	struct compat_ipc64_perm sem_perm;
	unsigned int	__pad1;
	compat_time_t	sem_otime;
	unsigned int	__pad2;
	compat_time_t	sem_ctime;
	u32		sem_nsems;
	u32		__unused1;
	u32		__unused2;
};

struct compat_msqid64_ds {
	struct compat_ipc64_perm msg_perm;
	unsigned int	__pad1;
	compat_time_t	msg_stime;
	unsigned int	__pad2;
	compat_time_t	msg_rtime;
	unsigned int	__pad3;
	compat_time_t	msg_ctime;
	unsigned int	msg_cbytes;
	unsigned int	msg_qnum;
	unsigned int	msg_qbytes;
	compat_pid_t	msg_lspid;
	compat_pid_t	msg_lrpid;
	unsigned int	__unused1;
	unsigned int	__unused2;
};

struct compat_shmid64_ds {
	struct compat_ipc64_perm shm_perm;
	unsigned int	__pad1;
	compat_time_t	shm_atime;
	unsigned int	__pad2;
	compat_time_t	shm_dtime;
	unsigned int	__pad3;
	compat_time_t	shm_ctime;
	compat_size_t	shm_segsz;
	compat_pid_t	shm_cpid;
	compat_pid_t	shm_lpid;
	unsigned int	shm_nattch;
	unsigned int	__unused1;
	unsigned int	__unused2;
};

static inline int is_compat_task(void)
{
	return test_thread_flag(TIF_32BIT);
}

#endif /* _ASM_SPARC64_COMPAT_H */

/*
 * Copyright 2010 Tilera Corporation. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE, GOOD TITLE or
 * NON INFRINGEMENT. See the GNU General Public License for
 * more details.
 */

#ifndef _ASM_TILE_COMPAT_H
#define _ASM_TILE_COMPAT_H

/*
 * Architecture specific compatibility types
 */
#include <linux/types.h>
#include <linux/sched.h>

#define COMPAT_USER_HZ 100

/* "long" and pointer-based types are different. */
typedef s32		compat_long_t;
typedef u32		compat_ulong_t;
typedef u32		compat_size_t;
typedef s32		compat_ssize_t;
typedef s32		compat_off_t;
typedef s32		compat_time_t;
typedef s32		compat_clock_t;
typedef u32		compat_ino_t;
typedef u32		compat_caddr_t;
typedef	u32		compat_uptr_t;

/* Many types are "int" or otherwise the same. */
typedef __kernel_pid_t compat_pid_t;
typedef __kernel_uid_t __compat_uid_t;
typedef __kernel_gid_t __compat_gid_t;
typedef __kernel_uid32_t __compat_uid32_t;
typedef __kernel_uid32_t __compat_gid32_t;
typedef __kernel_mode_t compat_mode_t;
typedef __kernel_dev_t compat_dev_t;
typedef __kernel_loff_t compat_loff_t;
typedef __kernel_nlink_t compat_nlink_t;
typedef __kernel_ipc_pid_t compat_ipc_pid_t;
typedef __kernel_daddr_t compat_daddr_t;
typedef __kernel_fsid_t	compat_fsid_t;
typedef __kernel_timer_t compat_timer_t;
typedef __kernel_key_t compat_key_t;
typedef int compat_int_t;
typedef s64 compat_s64;
typedef uint compat_uint_t;
typedef u64 compat_u64;

/* We use the same register dump format in 32-bit images. */
typedef unsigned long compat_elf_greg_t;
#define COMPAT_ELF_NGREG (sizeof(struct pt_regs) / sizeof(compat_elf_greg_t))
typedef compat_elf_greg_t compat_elf_gregset_t[COMPAT_ELF_NGREG];

struct compat_timespec {
	compat_time_t	tv_sec;
	s32		tv_nsec;
};

struct compat_timeval {
	compat_time_t	tv_sec;
	s32		tv_usec;
};

#define compat_stat stat
#define compat_statfs statfs

struct compat_sysctl {
	unsigned int	name;
	int		nlen;
	unsigned int	oldval;
	unsigned int	oldlenp;
	unsigned int	newval;
	unsigned int	newlen;
	unsigned int	__unused[4];
};


struct compat_flock {
	short		l_type;
	short		l_whence;
	compat_off_t	l_start;
	compat_off_t	l_len;
	compat_pid_t	l_pid;
};

#define F_GETLK64 12	/* using 'struct flock64' */
#define F_SETLK64 13
#define F_SETLKW64 14

struct compat_flock64 {
	short		l_type;
	short		l_whence;
	compat_loff_t	l_start;
	compat_loff_t	l_len;
	compat_pid_t	l_pid;
};

#define COMPAT_RLIM_INFINITY 0xffffffff

#define _COMPAT_NSIG 64
#define _COMPAT_NSIG_BPW 32

typedef u32               compat_sigset_word;

#define COMPAT_OFF_T_MAX 0x7fffffff
#define COMPAT_LOFF_T_MAX 0x7fffffffffffffffL

struct compat_ipc64_perm {
	compat_key_t key;
	__compat_uid32_t uid;
	__compat_gid32_t gid;
	__compat_uid32_t cuid;
	__compat_gid32_t cgid;
	unsigned short mode;
	unsigned short __pad1;
	unsigned short seq;
	unsigned short __pad2;
	compat_ulong_t unused1;
	compat_ulong_t unused2;
};

struct compat_semid64_ds {
	struct compat_ipc64_perm sem_perm;
	compat_time_t  sem_otime;
	compat_ulong_t __unused1;
	compat_time_t  sem_ctime;
	compat_ulong_t __unused2;
	compat_ulong_t sem_nsems;
	compat_ulong_t __unused3;
	compat_ulong_t __unused4;
};

struct compat_msqid64_ds {
	struct compat_ipc64_perm msg_perm;
	compat_time_t  msg_stime;
	compat_ulong_t __unused1;
	compat_time_t  msg_rtime;
	compat_ulong_t __unused2;
	compat_time_t  msg_ctime;
	compat_ulong_t __unused3;
	compat_ulong_t msg_cbytes;
	compat_ulong_t msg_qnum;
	compat_ulong_t msg_qbytes;
	compat_pid_t   msg_lspid;
	compat_pid_t   msg_lrpid;
	compat_ulong_t __unused4;
	compat_ulong_t __unused5;
};

struct compat_shmid64_ds {
	struct compat_ipc64_perm shm_perm;
	compat_size_t  shm_segsz;
	compat_time_t  shm_atime;
	compat_ulong_t __unused1;
	compat_time_t  shm_dtime;
	compat_ulong_t __unused2;
	compat_time_t  shm_ctime;
	compat_ulong_t __unused3;
	compat_pid_t   shm_cpid;
	compat_pid_t   shm_lpid;
	compat_ulong_t shm_nattch;
	compat_ulong_t __unused4;
	compat_ulong_t __unused5;
};

/*
 * A pointer passed in from user mode. This should not
 * be used for syscall parameters, just declare them
 * as pointers because the syscall entry code will have
 * appropriately converted them already.
 */

static inline void __user *compat_ptr(compat_uptr_t uptr)
{
	return (void __user *)(long)(s32)uptr;
}

static inline compat_uptr_t ptr_to_compat(void __user *uptr)
{
	return (u32)(unsigned long)uptr;
}

/* Sign-extend when storing a kernel pointer to a user's ptregs. */
static inline unsigned long ptr_to_compat_reg(void __user *uptr)
{
	return (long)(int)(long __force)uptr;
}

static inline void __user *compat_alloc_user_space(long len)
{
	struct pt_regs *regs = task_pt_regs(current);
	return (void __user *)regs->sp - len;
}

static inline int is_compat_task(void)
{
	return current_thread_info()->status & TS_COMPAT;
}

extern int compat_setup_rt_frame(int sig, struct k_sigaction *ka,
				 siginfo_t *info, sigset_t *set,
				 struct pt_regs *regs);

/* Compat syscalls. */
struct compat_sigaction;
struct compat_siginfo;
struct compat_sigaltstack;
long compat_sys_execve(char __user *path, compat_uptr_t __user *argv,
		       compat_uptr_t __user *envp);
long compat_sys_rt_sigaction(int sig, struct compat_sigaction __user *act,
			     struct compat_sigaction __user *oact,
			     size_t sigsetsize);
long compat_sys_rt_sigqueueinfo(int pid, int sig,
				struct compat_siginfo __user *uinfo);
long compat_sys_rt_sigreturn(void);
long compat_sys_sigaltstack(const struct compat_sigaltstack __user *uss_ptr,
			    struct compat_sigaltstack __user *uoss_ptr);
long compat_sys_truncate64(char __user *filename, u32 dummy, u32 low, u32 high);
long compat_sys_ftruncate64(unsigned int fd, u32 dummy, u32 low, u32 high);
long compat_sys_pread64(unsigned int fd, char __user *ubuf, size_t count,
			u32 dummy, u32 low, u32 high);
long compat_sys_pwrite64(unsigned int fd, char __user *ubuf, size_t count,
			 u32 dummy, u32 low, u32 high);
long compat_sys_lookup_dcookie(u32 low, u32 high, char __user *buf, size_t len);
long compat_sys_sync_file_range2(int fd, unsigned int flags,
				 u32 offset_lo, u32 offset_hi,
				 u32 nbytes_lo, u32 nbytes_hi);
long compat_sys_fallocate(int fd, int mode,
			  u32 offset_lo, u32 offset_hi,
			  u32 len_lo, u32 len_hi);
long compat_sys_sched_rr_get_interval(compat_pid_t pid,
				      struct compat_timespec __user *interval);

/* Versions of compat functions that differ from generic Linux. */
struct compat_msgbuf;
long tile_compat_sys_msgsnd(int msqid,
			    struct compat_msgbuf __user *msgp,
			    size_t msgsz, int msgflg);
long tile_compat_sys_msgrcv(int msqid,
			    struct compat_msgbuf __user *msgp,
			    size_t msgsz, long msgtyp, int msgflg);
long tile_compat_sys_ptrace(compat_long_t request, compat_long_t pid,
			    compat_long_t addr, compat_long_t data);

/* Tilera Linux syscalls that don't have "compat" versions. */
#define compat_sys_flush_cache sys_flush_cache

#endif /* _ASM_TILE_COMPAT_H */

#ifndef _ASM_X86_COMPAT_H
#define _ASM_X86_COMPAT_H

/*
 * Architecture specific compatibility types
 */
#include <linux/types.h>
#include <linux/sched.h>
#include <asm/user32.h>

#define COMPAT_USER_HZ 100
#define COMPAT_UTS_MACHINE	"i686\0\0"

typedef u32		compat_size_t;
typedef s32		compat_ssize_t;
typedef s32		compat_time_t;
typedef s32		compat_clock_t;
typedef s32		compat_pid_t;
typedef u16		__compat_uid_t;
typedef u16		__compat_gid_t;
typedef u32		__compat_uid32_t;
typedef u32		__compat_gid32_t;
typedef u16		compat_mode_t;
typedef u32		compat_ino_t;
typedef u16		compat_dev_t;
typedef s32		compat_off_t;
typedef s64		compat_loff_t;
typedef u16		compat_nlink_t;
typedef u16		compat_ipc_pid_t;
typedef s32		compat_daddr_t;
typedef u32		compat_caddr_t;
typedef __kernel_fsid_t	compat_fsid_t;
typedef s32		compat_timer_t;
typedef s32		compat_key_t;

typedef s32		compat_int_t;
typedef s32		compat_long_t;
typedef s64 __attribute__((aligned(4))) compat_s64;
typedef u32		compat_uint_t;
typedef u32		compat_ulong_t;
typedef u64 __attribute__((aligned(4))) compat_u64;

struct compat_timespec {
	compat_time_t	tv_sec;
	s32		tv_nsec;
};

struct compat_timeval {
	compat_time_t	tv_sec;
	s32		tv_usec;
};

struct compat_stat {
	compat_dev_t	st_dev;
	u16		__pad1;
	compat_ino_t	st_ino;
	compat_mode_t	st_mode;
	compat_nlink_t	st_nlink;
	__compat_uid_t	st_uid;
	__compat_gid_t	st_gid;
	compat_dev_t	st_rdev;
	u16		__pad2;
	u32		st_size;
	u32		st_blksize;
	u32		st_blocks;
	u32		st_atime;
	u32		st_atime_nsec;
	u32		st_mtime;
	u32		st_mtime_nsec;
	u32		st_ctime;
	u32		st_ctime_nsec;
	u32		__unused4;
	u32		__unused5;
};

struct compat_flock {
	short		l_type;
	short		l_whence;
	compat_off_t	l_start;
	compat_off_t	l_len;
	compat_pid_t	l_pid;
};

#define F_GETLK64 12	/* using 'struct flock64' */
#define F_SETLK64 13
#define F_SETLKW64 14

/*
 * IA32 uses 4 byte alignment for 64 bit quantities,
 * so we need to pack this structure.
 */
struct compat_flock64 {
	short		l_type;
	short		l_whence;
	compat_loff_t	l_start;
	compat_loff_t	l_len;
	compat_pid_t	l_pid;
} __attribute__((packed));

struct compat_statfs {
	int		f_type;
	int		f_bsize;
	int		f_blocks;
	int		f_bfree;
	int		f_bavail;
	int		f_files;
	int		f_ffree;
	compat_fsid_t	f_fsid;
	int		f_namelen;	/* SunOS ignores this field. */
	int		f_frsize;
	int		f_spare[5];
};

#define COMPAT_RLIM_OLD_INFINITY 0x7fffffff
#define COMPAT_RLIM_INFINITY 0xffffffff

typedef u32		compat_old_sigset_t;	/* at least 32 bits */

#define _COMPAT_NSIG 64
#define _COMPAT_NSIG_BPW 32

typedef u32               compat_sigset_word;

#define COMPAT_OFF_T_MAX 0x7fffffff
#define COMPAT_LOFF_T_MAX 0x7fffffffffffffffL

struct compat_ipc64_perm {
	compat_key_t key;
	__compat_uid32_t uid;
	__compat_gid32_t gid;
	__compat_uid32_t cuid;
	__compat_gid32_t cgid;
	unsigned short mode;
	unsigned short __pad1;
	unsigned short seq;
	unsigned short __pad2;
	compat_ulong_t unused1;
	compat_ulong_t unused2;
};

struct compat_semid64_ds {
	struct compat_ipc64_perm sem_perm;
	compat_time_t  sem_otime;
	compat_ulong_t __unused1;
	compat_time_t  sem_ctime;
	compat_ulong_t __unused2;
	compat_ulong_t sem_nsems;
	compat_ulong_t __unused3;
	compat_ulong_t __unused4;
};

struct compat_msqid64_ds {
	struct compat_ipc64_perm msg_perm;
	compat_time_t  msg_stime;
	compat_ulong_t __unused1;
	compat_time_t  msg_rtime;
	compat_ulong_t __unused2;
	compat_time_t  msg_ctime;
	compat_ulong_t __unused3;
	compat_ulong_t msg_cbytes;
	compat_ulong_t msg_qnum;
	compat_ulong_t msg_qbytes;
	compat_pid_t   msg_lspid;
	compat_pid_t   msg_lrpid;
	compat_ulong_t __unused4;
	compat_ulong_t __unused5;
};

struct compat_shmid64_ds {
	struct compat_ipc64_perm shm_perm;
	compat_size_t  shm_segsz;
	compat_time_t  shm_atime;
	compat_ulong_t __unused1;
	compat_time_t  shm_dtime;
	compat_ulong_t __unused2;
	compat_time_t  shm_ctime;
	compat_ulong_t __unused3;
	compat_pid_t   shm_cpid;
	compat_pid_t   shm_lpid;
	compat_ulong_t shm_nattch;
	compat_ulong_t __unused4;
	compat_ulong_t __unused5;
};

/*
 * The type of struct elf_prstatus.pr_reg in compatible core dumps.
 */
typedef struct user_regs_struct32 compat_elf_gregset_t;

/*
 * A pointer passed in from user mode. This should not
 * be used for syscall parameters, just declare them
 * as pointers because the syscall entry code will have
 * appropriately converted them already.
 */
typedef	u32		compat_uptr_t;

static inline void __user *compat_ptr(compat_uptr_t uptr)
{
	return (void __user *)(unsigned long)uptr;
}

static inline compat_uptr_t ptr_to_compat(void __user *uptr)
{
	return (u32)(unsigned long)uptr;
}

static inline void __user *compat_alloc_user_space(long len)
{
	struct pt_regs *regs = task_pt_regs(current);
	return (void __user *)regs->sp - len;
}

static inline int is_compat_task(void)
{
	return current_thread_info()->status & TS_COMPAT;
}

#endif /* _ASM_X86_COMPAT_H */

#ifndef _LINUX_COMPAT_H
#define _LINUX_COMPAT_H
/*
 * These are the type definitions for the architecture specific
 * syscall compatibility layer.
 */

#ifdef CONFIG_COMPAT

#include <linux/stat.h>
#include <linux/param.h>	/* for HZ */
#include <linux/sem.h>
#include <linux/socket.h>
#include <linux/if.h>

#include <asm/compat.h>
#include <asm/siginfo.h>
#include <asm/signal.h>

#define compat_jiffies_to_clock_t(x) \
 (((unsigned long)(x) * COMPAT_USER_HZ) / HZ)

typedef __compat_uid32_t	compat_uid_t;
typedef __compat_gid32_t	compat_gid_t;

struct compat_sel_arg_struct;
struct rusage;

struct compat_itimerspec { 
	struct compat_timespec it_interval;
	struct compat_timespec it_value;
};

struct compat_utimbuf {
	compat_time_t		actime;
	compat_time_t		modtime;
};

struct compat_itimerval {
	struct compat_timeval	it_interval;
	struct compat_timeval	it_value;
};

struct compat_tms {
	compat_clock_t		tms_utime;
	compat_clock_t		tms_stime;
	compat_clock_t		tms_cutime;
	compat_clock_t		tms_cstime;
};

struct compat_timex {
	compat_uint_t modes;
	compat_long_t offset;
	compat_long_t freq;
	compat_long_t maxerror;
	compat_long_t esterror;
	compat_int_t status;
	compat_long_t constant;
	compat_long_t precision;
	compat_long_t tolerance;
	struct compat_timeval time;
	compat_long_t tick;
	compat_long_t ppsfreq;
	compat_long_t jitter;
	compat_int_t shift;
	compat_long_t stabil;
	compat_long_t jitcnt;
	compat_long_t calcnt;
	compat_long_t errcnt;
	compat_long_t stbcnt;
	compat_int_t tai;

	compat_int_t :32; compat_int_t :32; compat_int_t :32; compat_int_t :32;
	compat_int_t :32; compat_int_t :32; compat_int_t :32; compat_int_t :32;
	compat_int_t :32; compat_int_t :32; compat_int_t :32;
};

#define _COMPAT_NSIG_WORDS (_COMPAT_NSIG / _COMPAT_NSIG_BPW)

typedef struct {
	compat_sigset_word	sig[_COMPAT_NSIG_WORDS];
} compat_sigset_t;

extern int get_compat_timespec(struct timespec *, const struct compat_timespec __user *);
extern int put_compat_timespec(const struct timespec *, struct compat_timespec __user *);

struct compat_iovec {
	compat_uptr_t	iov_base;
	compat_size_t	iov_len;
};

struct compat_rlimit {
	compat_ulong_t	rlim_cur;
	compat_ulong_t	rlim_max;
};

struct compat_rusage {
	struct compat_timeval ru_utime;
	struct compat_timeval ru_stime;
	compat_long_t	ru_maxrss;
	compat_long_t	ru_ixrss;
	compat_long_t	ru_idrss;
	compat_long_t	ru_isrss;
	compat_long_t	ru_minflt;
	compat_long_t	ru_majflt;
	compat_long_t	ru_nswap;
	compat_long_t	ru_inblock;
	compat_long_t	ru_oublock;
	compat_long_t	ru_msgsnd;
	compat_long_t	ru_msgrcv;
	compat_long_t	ru_nsignals;
	compat_long_t	ru_nvcsw;
	compat_long_t	ru_nivcsw;
};

extern int put_compat_rusage(const struct rusage *, struct compat_rusage __user *);

struct compat_siginfo;

extern asmlinkage long compat_sys_waitid(int, compat_pid_t,
		struct compat_siginfo __user *, int,
		struct compat_rusage __user *);

struct compat_dirent {
	u32		d_ino;
	compat_off_t	d_off;
	u16		d_reclen;
	char		d_name[256];
};

struct compat_ustat {
	compat_daddr_t		f_tfree;
	compat_ino_t		f_tinode;
	char			f_fname[6];
	char			f_fpack[6];
};

typedef union compat_sigval {
	compat_int_t	sival_int;
	compat_uptr_t	sival_ptr;
} compat_sigval_t;

#define COMPAT_SIGEV_PAD_SIZE ((SIGEV_MAX_SIZE/sizeof(int)) - 3)

typedef struct compat_sigevent {
	compat_sigval_t sigev_value;
	compat_int_t sigev_signo;
	compat_int_t sigev_notify;
	union {
		compat_int_t _pad[COMPAT_SIGEV_PAD_SIZE];
		compat_int_t _tid;

		struct {
			compat_uptr_t _function;
			compat_uptr_t _attribute;
		} _sigev_thread;
	} _sigev_un;
} compat_sigevent_t;

struct compat_ifmap {
	compat_ulong_t mem_start;
	compat_ulong_t mem_end;
	unsigned short base_addr;
	unsigned char irq;
	unsigned char dma;
	unsigned char port;
};

struct compat_if_settings
{
	unsigned int type;	/* Type of physical device or protocol */
	unsigned int size;	/* Size of the data allocated by the caller */
	compat_uptr_t ifs_ifsu;	/* union of pointers */
};

struct compat_ifreq {
	union {
		char	ifrn_name[IFNAMSIZ];    /* if name, e.g. "en0" */
	} ifr_ifrn;
	union {
		struct	sockaddr ifru_addr;
		struct	sockaddr ifru_dstaddr;
		struct	sockaddr ifru_broadaddr;
		struct	sockaddr ifru_netmask;
		struct	sockaddr ifru_hwaddr;
		short	ifru_flags;
		compat_int_t	ifru_ivalue;
		compat_int_t	ifru_mtu;
		struct	compat_ifmap ifru_map;
		char	ifru_slave[IFNAMSIZ];   /* Just fits the size */
		char	ifru_newname[IFNAMSIZ];
		compat_caddr_t	ifru_data;
		struct	compat_if_settings ifru_settings;
	} ifr_ifru;
};

struct compat_ifconf {
        compat_int_t	ifc_len;                        /* size of buffer */
        compat_caddr_t  ifcbuf;
};

struct compat_robust_list {
	compat_uptr_t			next;
};

struct compat_robust_list_head {
	struct compat_robust_list	list;
	compat_long_t			futex_offset;
	compat_uptr_t			list_op_pending;
};

extern void compat_exit_robust_list(struct task_struct *curr);

asmlinkage long
compat_sys_set_robust_list(struct compat_robust_list_head __user *head,
			   compat_size_t len);
asmlinkage long
compat_sys_get_robust_list(int pid, compat_uptr_t __user *head_ptr,
			   compat_size_t __user *len_ptr);

long compat_sys_semctl(int first, int second, int third, void __user *uptr);
long compat_sys_msgsnd(int first, int second, int third, void __user *uptr);
long compat_sys_msgrcv(int first, int second, int msgtyp, int third,
		int version, void __user *uptr);
long compat_sys_msgctl(int first, int second, void __user *uptr);
long compat_sys_shmat(int first, int second, compat_uptr_t third, int version,
		void __user *uptr);
long compat_sys_shmctl(int first, int second, void __user *uptr);
long compat_sys_semtimedop(int semid, struct sembuf __user *tsems,
		unsigned nsems, const struct compat_timespec __user *timeout);
asmlinkage long compat_sys_keyctl(u32 option,
			      u32 arg2, u32 arg3, u32 arg4, u32 arg5);
asmlinkage long compat_sys_ustat(unsigned dev, struct compat_ustat __user *u32);

asmlinkage ssize_t compat_sys_readv(unsigned long fd,
		const struct compat_iovec __user *vec, unsigned long vlen);
asmlinkage ssize_t compat_sys_writev(unsigned long fd,
		const struct compat_iovec __user *vec, unsigned long vlen);
asmlinkage ssize_t compat_sys_preadv(unsigned long fd,
		const struct compat_iovec __user *vec,
		unsigned long vlen, u32 pos_low, u32 pos_high);
asmlinkage ssize_t compat_sys_pwritev(unsigned long fd,
		const struct compat_iovec __user *vec,
		unsigned long vlen, u32 pos_low, u32 pos_high);

int compat_do_execve(char * filename, compat_uptr_t __user *argv,
	        compat_uptr_t __user *envp, struct pt_regs * regs);

asmlinkage long compat_sys_select(int n, compat_ulong_t __user *inp,
		compat_ulong_t __user *outp, compat_ulong_t __user *exp,
		struct compat_timeval __user *tvp);

asmlinkage long compat_sys_old_select(struct compat_sel_arg_struct __user *arg);

asmlinkage long compat_sys_wait4(compat_pid_t pid,
				 compat_uint_t __user *stat_addr, int options,
				 struct compat_rusage __user *ru);

#define BITS_PER_COMPAT_LONG (8*sizeof(compat_long_t))

#define BITS_TO_COMPAT_LONGS(bits) \
 (((bits)+BITS_PER_COMPAT_LONG-1)/BITS_PER_COMPAT_LONG)

long compat_get_bitmap(unsigned long *mask, const compat_ulong_t __user *umask,
		       unsigned long bitmap_size);
long compat_put_bitmap(compat_ulong_t __user *umask, unsigned long *mask,
		       unsigned long bitmap_size);
int copy_siginfo_from_user32(siginfo_t *to, struct compat_siginfo __user *from);
int copy_siginfo_to_user32(struct compat_siginfo __user *to, siginfo_t *from);
int get_compat_sigevent(struct sigevent *event,
		const struct compat_sigevent __user *u_event);
long compat_sys_rt_tgsigqueueinfo(compat_pid_t tgid, compat_pid_t pid, int sig,
				  struct compat_siginfo __user *uinfo);

static inline int compat_timeval_compare(struct compat_timeval *lhs,
					struct compat_timeval *rhs)
{
	if (lhs->tv_sec < rhs->tv_sec)
		return -1;
	if (lhs->tv_sec > rhs->tv_sec)
		return 1;
	return lhs->tv_usec - rhs->tv_usec;
}

static inline int compat_timespec_compare(struct compat_timespec *lhs,
					struct compat_timespec *rhs)
{
	if (lhs->tv_sec < rhs->tv_sec)
		return -1;
	if (lhs->tv_sec > rhs->tv_sec)
		return 1;
	return lhs->tv_nsec - rhs->tv_nsec;
}

extern int get_compat_itimerspec(struct itimerspec *dst,
				 const struct compat_itimerspec __user *src);
extern int put_compat_itimerspec(struct compat_itimerspec __user *dst,
				 const struct itimerspec *src);

asmlinkage long compat_sys_gettimeofday(struct compat_timeval __user *tv,
		struct timezone __user *tz);
asmlinkage long compat_sys_settimeofday(struct compat_timeval __user *tv,
		struct timezone __user *tz);

asmlinkage long compat_sys_adjtimex(struct compat_timex __user *utp);

extern int compat_printk(const char *fmt, ...);
extern void sigset_from_compat(sigset_t *set, compat_sigset_t *compat);

asmlinkage long compat_sys_migrate_pages(compat_pid_t pid,
		compat_ulong_t maxnode, const compat_ulong_t __user *old_nodes,
		const compat_ulong_t __user *new_nodes);

extern int compat_ptrace_request(struct task_struct *child,
				 compat_long_t request,
				 compat_ulong_t addr, compat_ulong_t data);

extern long compat_arch_ptrace(struct task_struct *child, compat_long_t request,
			       compat_ulong_t addr, compat_ulong_t data);
asmlinkage long compat_sys_ptrace(compat_long_t request, compat_long_t pid,
				  compat_long_t addr, compat_long_t data);

/*
 * epoll (fs/eventpoll.c) compat bits follow ...
 */
struct epoll_event;
#define compat_epoll_event epoll_event
asmlinkage long compat_sys_epoll_pwait(int epfd,
			struct compat_epoll_event __user *events,
			int maxevents, int timeout,
			const compat_sigset_t __user *sigmask,
			compat_size_t sigsetsize);

asmlinkage long compat_sys_utimensat(unsigned int dfd, const char __user *filename,
				struct compat_timespec __user *t, int flags);

asmlinkage long compat_sys_signalfd(int ufd,
				const compat_sigset_t __user *sigmask,
                                compat_size_t sigsetsize);
asmlinkage long compat_sys_timerfd_settime(int ufd, int flags,
				   const struct compat_itimerspec __user *utmr,
				   struct compat_itimerspec __user *otmr);
asmlinkage long compat_sys_timerfd_gettime(int ufd,
				   struct compat_itimerspec __user *otmr);

asmlinkage long compat_sys_move_pages(pid_t pid, unsigned long nr_page,
				      __u32 __user *pages,
				      const int __user *nodes,
				      int __user *status,
				      int flags);
asmlinkage long compat_sys_futimesat(unsigned int dfd, const char __user *filename,
				     struct compat_timeval __user *t);
asmlinkage long compat_sys_newfstatat(unsigned int dfd, const char __user * filename,
				      struct compat_stat __user *statbuf,
				      int flag);
asmlinkage long compat_sys_openat(unsigned int dfd, const char __user *filename,
				  int flags, int mode);

extern ssize_t compat_rw_copy_check_uvector(int type,
		const struct compat_iovec __user *uvector, unsigned long nr_segs,
		unsigned long fast_segs, struct iovec *fast_pointer,
		struct iovec **ret_pointer);
#endif /* CONFIG_COMPAT */
#endif /* _LINUX_COMPAT_H */