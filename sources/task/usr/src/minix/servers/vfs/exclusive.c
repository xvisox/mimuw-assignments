#include "fs.h"
#include "vnode.h"
#include "file.h"
#include <fcntl.h>
// FIXME: remove this include
#include <stdio.h>

int check_exclusive(struct vnode *vp) {
    for (int i = 0; i < NR_EXCLUSIVE; i++) {
        struct exclusive *e = &exclusive_files[i];
        if (e->e_vnode == vp) {
            if (e->e_uid != fp->fp_realuid) {
                return (EACCES);
            } else {
                return (OK);
            }
        }
    }
    return (OK);
}

int remove_exclusive(struct vnode *vp, int fd) {
    for (int i = 0; i < NR_EXCLUSIVE; i++) {
        struct exclusive *e = &exclusive_files[i];
        if (e->e_vnode == vp && e->e_fd == fd) {
            e->e_vnode = NULL;
            e->e_fd = -1;
            e->e_uid = -1;
            return (OK);
        }
    }
    return (OK);
}

int do_exclusive(void) {
    // TODO: implementacja VFS_EXCLUSIVE
    return (ENOSYS);
}

int do_lock(struct vnode *v, int fd) {
    // Check if the file is already locked.
    for (int i = 0; i < NR_EXCLUSIVE; i++) {
        struct exclusive *e = &exclusive_files[i];
        if (e->e_vnode == v) {
            return (EALREADY);
        }
    }
    // Find a free slot.
    for (int i = 0; i < NR_EXCLUSIVE; i++) {
        struct exclusive *e = &exclusive_files[i];
        if (e->e_vnode == NULL) {
            e->e_vnode = v;
            e->e_fd = fd;
            e->e_uid = fp->fp_realuid;
            return (OK);
        }
    }
    return (ENOLCK);
}

int do_unlock(struct vnode *v) {
    // Find the lock.
    for (int i = 0; i < NR_EXCLUSIVE; i++) {
        struct exclusive *e = &exclusive_files[i];
        if (e->e_vnode == v) {
            if (e->e_uid != fp->fp_realuid) {
                return (EPERM);
            } else {
                e->e_vnode = NULL;
                e->e_fd = -1;
                e->e_uid = -1;
                return (OK);
            }
        }
    }
    return (EINVAL);
}

int do_fexclusive(void) {
    int fd = job_m_in.m_lc_vfs_exclusive.fd;
    int flags = job_m_in.m_lc_vfs_exclusive.flags;

    struct filp *f = get_filp(fd, VNODE_NONE);
    if (f == NULL || (f->filp_mode != R_BIT && f->filp_mode != W_BIT)) {
        return (EBADF);
    }
    struct vnode *v = f->filp_vno;
    if (!S_ISREG(v->v_mode)) {
        return (EFTYPE);
    }

    switch (flags) {
        case EXCL_LOCK:
            return do_lock(v, fd);
        case EXCL_LOCK_NO_OTHERS:
            return -2115;
        case EXCL_UNLOCK:
            return do_unlock(v);
        case EXCL_UNLOCK_FORCE:
            return -2115;
    }

    return (EINVAL);
}