// hm438596

#include <minix/callnr.h>
#include "pm.h"
#include "mproc.h"

#define ROOT_PID 1

static int is_descendant(pid_t ancestor, pid_t descendant) {
    pid_t current_pid = descendant;
    while (current_pid != ROOT_PID) {
        if (current_pid == ancestor) {
            return 1;
        }
        struct mproc *proc = &mproc[find_proc(current_pid)->mp_parent];
        current_pid = proc->mp_pid;
    }
    return 0;
}

int do_transfer_money(void) {
    pid_t source = m_in.m_trans_src;
    pid_t destination = m_in.m_trans_dst;
    int amount = m_in.m_trans_amt;

    struct mproc *src_proc = find_proc(source);
    struct mproc *dst_proc = find_proc(destination);
    if (dst_proc == NULL) {
        return ESRCH;
    }

    if ((is_descendant(source, destination) ||
         is_descendant(destination, source)) &&
        destination != source) {
        return EPERM;
    }

    if (amount < 0 || amount > src_proc->account_balance || dst_proc->account_balance + amount > MAX_BALANCE) {
        return EINVAL;
    }

    src_proc->account_balance -= amount;
    dst_proc->account_balance += amount;

    return src_proc->account_balance;
}