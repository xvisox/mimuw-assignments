#include <lib.h>
#include <minix/rs.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

void reset_errno() {
    errno = 0;
}

int main(int argc, char *argv[]) {
    message m;
    endpoint_t vfs_ep;
    int flags;
    int ret;
    int fd;

    // Sprawdź liczbę argumentów.
    if (argc != 2) {
        printf("Użycie:\n%s plik\n", argv[0]);
        return 1;
    }

    // Coverage:
    // VFS_OPEN      (v)
    // VFS_CREATE    (v)
    // VFS_READ      (x)
    // VFS_WRITE     (x)
    // VFS_TRUNCATE  (v)
    // VFS_FTRUNCATE (x)
    // VFS_RENAME    (v)
    // VFS_UNLINK    (v)
    printf("Testuje dostępności pliku...\n");
    printf("VFS_OPEN:\n");
    reset_errno();
    fd = open(argv[1], O_RDONLY);
    printf("Wynik open: %d, errno: %d\n", fd, errno);

    printf("VFS_CREATE:\n");
    reset_errno();
    fd = open(argv[1], O_WRONLY | O_CREAT | O_EXCL, 0777);
    printf("Wynik open create: %d, errno: %d\n", fd, errno);

    // (!!!) VFS_READ/WRITE/FTRUNCATE NA KOŃCU

    printf("VFS_TRUNCATE:\n");
    reset_errno();
    ret = truncate(argv[1], 2115);
    printf("Wynik truncate: %d, errno: %d\n", ret, errno);

    printf("VFS_RENAME v1:\n");
    reset_errno();
    ret = rename(argv[1], "nowy.c");
    printf("Wynik rename: %d, errno: %d\n", ret, errno);

    printf("VFS_RENAME v2:\n");
    reset_errno();
    ret = rename("nowy.c", argv[1]);
    printf("Wynik rename: %d, errno: %d\n", ret, errno);

    printf("VFS_UNLINK:\n");
    reset_errno();
    ret = unlink(argv[1]);
    printf("Wynik unlink: %d, errno: %d\n", ret, errno);

    // Coverage:
    // VFS_OPEN      (x)
    // VFS_CREATE    (x)
    // VFS_READ      (v)
    // VFS_WRITE     (v)
    // VFS_TRUNCATE  (x)
    // VFS_FTRUNCATE (v)
    // VFS_RENAME    (x)
    // VFS_UNLINK    (x)
    printf("Odblokuj plik i naciśnij cokolwiek...\n");
    getchar();

    fd = open(argv[1], O_RDWR);
    reset_errno();
    printf("Wynik open: %d, errno: %d\n", fd, errno);
    assert(fd >= 0);

    printf("Zablokuj plik i naciśnij cokolwiek...\n");
    getchar();

    printf("VFS_READ:\n");
    char buf[1024];
    reset_errno();
    ret = read(fd, buf, sizeof(buf));
    printf("Wynik read: %d, errno: %d\n", ret, errno);

    printf("VFS_WRITE:\n");
    reset_errno();
    ret = write(fd, buf, sizeof(buf));
    printf("Wynik write: %d, errno: %d\n", ret, errno);

    printf("VFS_FTRUNCATE:\n");
    reset_errno();
    ret = ftruncate(fd, 2115);
    printf("Wynik ftruncate: %d, errno: %d\n", ret, errno);

    ret = open("pliczek.c", O_RDONLY);
    assert(ret >= 0);
    printf("Otwarłem pliczek.c, spróbuj go zablokować i naciśnij coś...\n");
    getchar();

    printf("Spróbuję odblokować pliczek.c...\n");
    m.m_lc_vfs_exclusive.fd = ret;
    m.m_lc_vfs_exclusive.flags = EXCL_UNLOCK_FORCE;
    minix_rs_lookup("vfs", &vfs_ep);
    reset_errno();
    ret = _syscall(vfs_ep, VFS_FEXCLUSIVE, &m);
    printf("Wynik VFS_FEXCLUSIVE: %d, errno: %d\n", ret, errno);

    // Zakończ.
    return ret != 0;
}
