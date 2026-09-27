#ifndef __UFFD_WP_COMPAT_H__
#define __UFFD_WP_COMPAT_H__

/*
 * userfaultfd write-protect (UFFD-WP) compatibility shim.
 *
 * The UFFD-WP UAPI (UFFDIO_WRITEPROTECT and struct uffdio_writeprotect) was
 * added to <linux/userfaultfd.h> in Linux 5.7. The paper's SGX node ran a
 * 5.15 kernel, but Hares also builds on hosts whose libc UAPI headers are
 * older (e.g. the Ubuntu 20.04 stock 5.4 headers). Include this header AFTER
 * <linux/userfaultfd.h> and <sys/ioctl.h>; the guard makes it inert when the
 * kernel headers already provide these definitions.
 *
 * The running kernel still needs to support UFFD-WP at run time (>= 5.7);
 * this only fixes compilation against older UAPI headers.
 */
#include <linux/userfaultfd.h>
#include <sys/ioctl.h>

#ifndef UFFDIO_WRITEPROTECT
struct uffdio_writeprotect {
	struct uffdio_range range;
	__u64 mode;
};
#define UFFDIO_WRITEPROTECT_MODE_WP       ((__u64)1 << 0)
#define UFFDIO_WRITEPROTECT_MODE_DONTWAKE ((__u64)1 << 1)
#define _UFFDIO_WRITEPROTECT              (0x06)
#define UFFDIO_WRITEPROTECT \
	_IOWR(UFFDIO, _UFFDIO_WRITEPROTECT, struct uffdio_writeprotect)
#endif /* UFFDIO_WRITEPROTECT */

/* UFFDIO_COPY_MODE_WP (write-protect a page while copying) - also Linux 5.7. */
#ifndef UFFDIO_COPY_MODE_WP
#define UFFDIO_COPY_MODE_WP ((__u64)1 << 1)
#endif

#endif /* __UFFD_WP_COMPAT_H__ */
