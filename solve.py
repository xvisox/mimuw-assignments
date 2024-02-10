from functools import reduce
from math import gcd

from pwn import *


def solve_equation(s_0, s_1, s_2):
    solutions = {0}
    res = s_2 ^ s_1
    for k in range(1, 65):
        next_solutions = set()

        for y in solutions:
            m = 2 ** k
            candidate_0 = y | (0 << (k - 1))
            if ((s_1 * candidate_0) ^ (s_0 * candidate_0)) % m == res % m:
                next_solutions.add(candidate_0)

            candidate_1 = y | (1 << (k - 1))
            if ((s_1 * candidate_1) ^ (s_0 * candidate_1)) % m == res % m:
                next_solutions.add(candidate_1)

        solutions = next_solutions

    return solutions


def solve_task_1(hostname, port):
    flag = 'nope'

    while flag == 'nope':
        conn = remote(hostname, port)
        conn.recvuntil(b'>')
        conn.sendline(b'1')

        recv = []
        for _ in range(5):
            recv.append(int(conn.recvline().strip()))
        _ = conn.recvline()

        s0 = recv[0]
        s1 = recv[1]
        s2 = recv[2]
        s4 = recv[4]
        m = 2 ** 64

        solutions = solve_equation(s0, s1, s2)
        a = solutions.pop()
        c = s1 ^ (s0 * a)
        result = ((s4 * a) ^ c) % m
        conn.sendline(str(result).encode())

        flag = conn.recvline().strip().decode()
        _ = conn.recvall()
        conn.close()

    return flag


def solve_task_2(hostname, port):
    pass


def solve_task_3(hostname, port):
    pass


def main():
    if len(sys.argv) != 3:
        print("Usage: python3 solve.py <hostname> <port>")
        return

    hostname = sys.argv[1]
    port = int(sys.argv[2])

    tasks = [
        "1) NCG",
        "2) Block cipher (easy)",
        "3) Block cipher (hard)",
    ]
    flags = [
        solve_task_1(hostname, port),
        solve_task_2(hostname, port),
        solve_task_3(hostname, port)
    ]

    for task, flag in zip(tasks, flags):
        print(task, '--', flag)


if __name__ == "__main__":
    main()
