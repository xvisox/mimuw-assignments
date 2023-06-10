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

    printf("Otwarłem plik, czekam na zablokowanie...\n");
    getchar();

    char buf[1024];
    ret = read(fd, buf, 1024);
    printf("Wynik read: %d, errno: %d\n", ret, errno);

    close(fd);

    // Zakończ.
    return ret != 0;
}
