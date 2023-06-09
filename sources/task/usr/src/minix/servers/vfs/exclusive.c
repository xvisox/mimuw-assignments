#include "fs.h"
#include "vnode.h"
#include "file.h"
#include <fcntl.h>
#include <stdbool.h>
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

int do_lock(struct vnode *v, int fd, bool no_others) {
    for (int i = 0; i < NR_PROCS && no_others; i++) {
        struct fproc *proc = &fproc[i];
        if (proc->fp_pid == PID_FREE || proc->fp_realuid == fp->fp_realuid) continue;

        for (int j = 0; j < OPEN_MAX; j++) {
            struct filp *f = proc->fp_filp[j];
            if (f == NULL) continue;

            if (f->filp_vno == v) {
                return (EAGAIN);
            }
        }
    }
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

int do_unlock(struct vnode *v, bool force) {
    // Find the lock.
    for (int i = 0; i < NR_EXCLUSIVE; i++) {
        struct exclusive *e = &exclusive_files[i];
        if (e->e_vnode == v) {
            if (e->e_uid == fp->fp_realuid || (force && SU_UID == fp->fp_realuid)) {
                e->e_vnode = NULL;
                e->e_fd = -1;
                e->e_uid = -1;
                return (OK);
            } else {
                return (EPERM);
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
            return do_lock(v, fd, false);
        case EXCL_LOCK_NO_OTHERS:
            return do_lock(v, fd, true);
        case EXCL_UNLOCK:
            return do_unlock(v, false);
        case EXCL_UNLOCK_FORCE:
            return do_unlock(v, true);
    }

    return (EINVAL);
}