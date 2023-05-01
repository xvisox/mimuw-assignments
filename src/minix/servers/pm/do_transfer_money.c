// hm438596

#include <stdio.h>
#include <minix/callnr.h>
#include "pm.h"

int do_transfer_money(void) {
    printf("do_transfer_money called by %d\n", m_in.m_source);
    return 0;
}