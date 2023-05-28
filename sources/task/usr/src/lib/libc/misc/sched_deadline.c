// hm438596
#include <lib.h>
#include <minix/rs.h>
#include <string.h>
#include <sys/types.h>
#include <stdbool.h>

int sched_deadline(int64_t deadline, int64_t estimate, bool kill) {
    message m;
    m.m_sched_deadline = deadline;
    m.m_sched_estimate = estimate;
    m.m_sched_kill = kill;
    return _syscall(PM_PROC_NR, PM_SCHED_DEADLINE, &m);
}
