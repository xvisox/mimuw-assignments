#include <lib.h>
#include <minix/rs.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

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
    fd = open(argv[1], O_RDONLY);
    printf("Wynik open: %d, errno: %d\n", fd, errno);

    printf("VFS_CREATE:\n");
    fd = open(argv[1], O_WRONLY | O_CREAT | O_EXCL, 0777);
    printf("Wynik open create: %d, errno: %d\n", fd, errno);

    // TODO: VFS_READ/WRITE/FTRUNCATE NA KOŃCU

    printf("VFS_TRUNCATE:\n");
    errno = 0;
    ret = truncate(argv[1], 2115);
    printf("Wynik truncate: %d, errno: %d\n", ret, errno);

    printf("VFS_RENAME v1:\n");
    ret = rename(argv[1], "nowy.c");
    printf("Wynik rename: %d, errno: %d\n", ret, errno);

    printf("VFS_RENAME v2:\n");
    ret = rename("nowy.c", argv[1]);
    printf("Wynik rename: %d, errno: %d\n", ret, errno);

    printf("VFS_UNLINK:\n");
    ret = unlink(argv[1]);
    printf("Wynik unlink: %d, errno: %d\n", ret, errno);

    // Zakończ.
    return ret != 0;
}
