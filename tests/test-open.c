#include <lib.h>
#include <minix/rs.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    message m;
    endpoint_t vfs_ep;
    int ret;
    int fd;

    fd = open("pliczek.c", O_RDONLY);
    if (fd == -1) {
        printf("Nie można otworzyć pliku pliczek.c (wynik: %d).\n", fd);
        return 1;
    }

    // Zablokuj plik.
    printf("Blokuję plik...\n");
    m.m_lc_vfs_exclusive.fd = fd;
    m.m_lc_vfs_exclusive.flags = EXCL_LOCK_NO_OTHERS;
    minix_rs_lookup("vfs", &vfs_ep);
    ret = _syscall(vfs_ep, VFS_FEXCLUSIVE, &m);
    printf("Wynik VFS_FEXCLUSIVE: %d, errno: %d\n", ret, errno);

    m.m_lc_vfs_exclusive.fd = fd;
    m.m_lc_vfs_exclusive.flags = EXCL_LOCK;
    ret = _syscall(vfs_ep, VFS_FEXCLUSIVE, &m);
    printf("Wynik VFS_FEXCLUSIVE: %d, errno: %d\n", ret, errno);

    printf("Test skończony, naciśnij coś aby kontynuować\n");
    getchar();

    close(fd);

    // Zakończ.
    return ret != 0;
}
