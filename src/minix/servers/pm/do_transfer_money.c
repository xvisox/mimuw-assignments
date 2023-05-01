// hm438596

#include <stdio.h>
#include <minix/callnr.h>
#include "pm.h"
#include "mproc.h"

int do_transfer_money(void) {
    pid_t xd = m_in.m_trans_src;
    printf("do_transfer_money called by %d\n", xd);
    printf("recipient: %d\n", m_in.m_trans_dst);
    printf("amount: %d\n", m_in.m_trans_amt);
    struct mproc *rmp = find_proc(xd);
    if (rmp == NULL) {
        printf("do_transfer_money: find_proc failed wooohoe\n");
        return -1;
    } else {
        printf("do_transfer_money: find_proc succeeded\n");
        printf("%d\n", rmp->account_balance);
    }

    return 0;
}