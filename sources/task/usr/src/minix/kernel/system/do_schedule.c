#include "kernel/system.h"
#include <minix/endpoint.h>
#include "kernel/clock.h"
#include <sys/types.h>
#include <stdbool.h>
#include <stdio.h>

/*===========================================================================*
 *				do_schedule, hm438596				     *
 *===========================================================================*/
int do_schedule(struct proc * caller, message * m_ptr)
{
	struct proc *p;
	int proc_nr;
	int priority, quantum, cpu;

	if (!isokendpt(m_ptr->m_lsys_krn_schedule.endpoint, &proc_nr))
		return EINVAL;

	p = proc_addr(proc_nr);

	/* Only this process' scheduler can schedule it */
	if (caller != p->p_scheduler)
		return(EPERM);

	/* Try to schedule the process. */
	priority = m_ptr->m_lsys_krn_schedule.priority;
	quantum = m_ptr->m_lsys_krn_schedule.quantum;
	cpu = m_ptr->m_lsys_krn_schedule.cpu;

    if (priority == DEADLINE_Q) {
        int64_t deadline = m_ptr->m_lsys_krn_schedule.deadline;
        int64_t estimate = m_ptr->m_lsys_krn_schedule.estimate;
        bool kill = m_ptr->m_lsys_krn_schedule.kill;
        printf("KERNEL: do_schedule: deadline=%lld, estimate=%lld, kill=%d\n", deadline, estimate, kill);
    }

	return sched_proc(p, priority, quantum, cpu);
}
