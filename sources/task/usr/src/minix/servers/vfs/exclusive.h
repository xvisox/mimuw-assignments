#ifndef __VFS_EXCLUSIVE_H__
#define __VFS_EXCLUSIVE_H__

EXTERN struct exclusive {
    uid_t e_uid;              /* id of the lock owner */
    struct vnode* e_vnode;    /* exclusive vnode */
    int e_fd;                 /* file descriptor associated with vnode, -1 if exclusive by name */
} exclusive_files[NR_EXCLUSIVE];

#endif