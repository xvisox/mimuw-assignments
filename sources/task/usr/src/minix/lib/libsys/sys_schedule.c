#include "syslib.h"
#include <sys/types.h>
#include <stdbool.h>

int sys_schedule(endpoint_t proc_ep,
			int priority,
			int quantum,
			int cpu,
            int64_t deadline, int64_t estimate)
{
	message m;

	m.m_lsys_krn_schedule.endpoint = proc_ep;
	m.m_lsys_krn_schedule.priority = priority;
	m.m_lsys_krn_schedule.quantum  = quantum;
	m.m_lsys_krn_schedule.cpu = cpu;
    m.m_lsys_krn_schedule.deadline = deadline;
    m.m_lsys_krn_schedule.estimate = estimate;
	return(_kernel_call(SYS_SCHEDULE, &m));
}
