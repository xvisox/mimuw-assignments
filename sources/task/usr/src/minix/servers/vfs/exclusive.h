#ifndef __VFS_EXCLUSIVE_H__
#define __VFS_EXCLUSIVE_H__

EXTERN struct exclusive {
    uid_t e_uid;              /* id of the lock owner */
    ino_t e_inode_nr;         /* inode number on its (minor) device */
    endpoint_t e_fs_e;        /* FS process' endpoint number */
    int e_fd;                 /* file descriptor associated with vnode, -1 if exclusive by name */
} exclusive_files[NR_EXCLUSIVE];

#endif