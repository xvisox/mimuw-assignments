/* This file contains the scheduling policy for SCHED
 *
 * The entry points are:
 *   do_noquantum:        Called on behalf of process' that run out of quantum
 *   do_start_scheduling  Request to start scheduling a proc
 *   do_stop_scheduling   Request to stop scheduling a proc
 *   do_nice		  Request to change the nice level on a proc
 *   init_scheduling      Called from main.c to set up/prepare scheduling
 */
#include "sched.h"
#include "schedproc.h"
#include <assert.h>
#include <minix/com.h>
#include <machine/archtypes.h>
#include "kernel/proc.h" /* for queue constants */
#include <stdbool.h>
#include <stdio.h>

static minix_timer_t sched_timer;
static unsigned balance_timeout;

#define BALANCE_TIMEOUT	5 /* how often to balance queues in seconds */

static int schedule_process(struct schedproc * rmp, unsigned flags);
static void balance_queues(minix_timer_t *tp);

#define SCHEDULE_CHANGE_PRIO	0x1
#define SCHEDULE_CHANGE_QUANTUM	0x2
#define SCHEDULE_CHANGE_CPU	0x4

#define SCHEDULE_CHANGE_ALL	(	\
		SCHEDULE_CHANGE_PRIO	|	\
		SCHEDULE_CHANGE_QUANTUM	|	\
		SCHEDULE_CHANGE_CPU		\
		)

#define schedule_process_local(p)	\
	schedule_process(p, SCHEDULE_CHANGE_PRIO | SCHEDULE_CHANGE_QUANTUM)
#define schedule_process_migrate(p)	\
	schedule_process(p, SCHEDULE_CHANGE_CPU)

#define CPU_DEAD	-1

#define cpu_is_available(c)	(cpu_proc[c] >= 0)

#define DEFAULT_USER_TIME_SLICE 200

/* processes created by RS are sysytem processes */
#define is_system_proc(p)	((p)->parent == RS_PROC_NR)

static unsigned cpu_proc[CONFIG_MAX_CPUS];

static void pick_cpu(struct schedproc * proc)
{
#ifdef CONFIG_SMP
	unsigned cpu, c;
	unsigned cpu_load = (unsigned) -1;
	
	if (machine.processors_count == 1) {
		proc->cpu = machine.bsp_id;
		return;
	}

	/* schedule sysytem processes only on the boot cpu */
	if (is_system_proc(proc)) {
		proc->cpu = machine.bsp_id;
		return;
	}

	/* if no other cpu available, try BSP */
	cpu = machine.bsp_id;
	for (c = 0; c < machine.processors_count; c++) {
		/* skip dead cpus */
		if (!cpu_is_available(c))
			continue;
		if (c != machine.bsp_id && cpu_load > cpu_proc[c]) {
			cpu_load = cpu_proc[c];
			cpu = c;
		}
	}
	proc->cpu = cpu;
	cpu_proc[cpu]++;
#else
	proc->cpu = 0;
#endif
}

// hm438596
int64_t get_now() {
    int rv;
    clock_t realtime, ticks;
    time_t boottime;
    if ((rv = getuptime(&ticks, &realtime, &boottime)) != OK) {
        printf("SCHED: WARNING: getuptime failed: %d\n", rv);
        return rv;
    }
    int64_t sec = (boottime + realtime / sys_hz());
    int64_t nano_sec = ((realtime % sys_hz()) * 1000000000LL / sys_hz());
    return sec * 1000LL + nano_sec / 1000000LL;
}

/*===========================================================================*
 *				do_noquantum				     *
 *===========================================================================*/

int do_noquantum(message *m_ptr)
{
	register struct schedproc *rmp;
	int rv, proc_nr_n;

	if (sched_isokendpt(m_ptr->m_source, &proc_nr_n) != OK) {
		printf("SCHED: WARNING: got an invalid endpoint in OOQ msg %u.\n",
		m_ptr->m_source);
		return EBADEPT;
	}

    // hm438596
	rmp = &schedproc[proc_nr_n];
	if (rmp->priority < MIN_USER_Q && rmp->priority != DEADLINE_Q) {
		rmp->priority += 1; /* lower priority */
        if (rmp->priority == DEADLINE_Q) rmp->priority += 1;
	}
    if (rmp->priority == DEADLINE_Q) {
        printf("Process %d has used up its time slice = %u\n", rmp->endpoint, rmp->time_slice);
        rmp->used_time += rmp->time_slice;
        /* Check if the process has exceeded its estimate running time */
        if (rmp->used_time > rmp->estimate) {
            printf("Process %d has exceeded its estimate running time, flag = %d\n", rmp->endpoint, rmp->kill);
            if (!rmp->kill) {
                rmp->priority = PENALTY_Q;
            } else {
                return sys_kill(rmp->endpoint, SIGKILL);
            }
        }
        /* Check if the process has exceeded its deadline */
        int64_t now = get_now();
        if (now > rmp->deadline) {
            printf("Process %d has exceeded its deadline\n", rmp->endpoint);
            rmp->priority = rmp->previous_priority;
        }
    }

	if ((rv = schedule_process_local(rmp)) != OK) {
		return rv;
	}
	return OK;
}

/*===========================================================================*
 *				do_stop_scheduling			     *
 *===========================================================================*/
int do_stop_scheduling(message *m_ptr)
{
	register struct schedproc *rmp;
	int proc_nr_n;

	/* check who can send you requests */
	if (!accept_message(m_ptr))
		return EPERM;

	if (sched_isokendpt(m_ptr->m_lsys_sched_scheduling_stop.endpoint,
		    &proc_nr_n) != OK) {
		printf("SCHED: WARNING: got an invalid endpoint in OOQ msg "
		"%d\n", m_ptr->m_lsys_sched_scheduling_stop.endpoint);
		return EBADEPT;
	}

	rmp = &schedproc[proc_nr_n];
#ifdef CONFIG_SMP
	cpu_proc[rmp->cpu]--;
#endif
	rmp->flags = 0; /*&= ~IN_USE;*/

	return OK;
}

/*===========================================================================*
 *				do_start_scheduling			     *
 *===========================================================================*/
int do_start_scheduling(message *m_ptr)
{
	register struct schedproc *rmp;
	int rv, proc_nr_n, parent_nr_n;
	
	/* we can handle two kinds of messages here */
	assert(m_ptr->m_type == SCHEDULING_START || 
		m_ptr->m_type == SCHEDULING_INHERIT);

	/* check who can send you requests */
	if (!accept_message(m_ptr))
		return EPERM;

	/* Resolve endpoint to proc slot. */
	if ((rv = sched_isemtyendpt(m_ptr->m_lsys_sched_scheduling_start.endpoint,
			&proc_nr_n)) != OK) {
		return rv;
	}
	rmp = &schedproc[proc_nr_n];

	/* Populate process slot */
	rmp->endpoint     = m_ptr->m_lsys_sched_scheduling_start.endpoint;
	rmp->parent       = m_ptr->m_lsys_sched_scheduling_start.parent;
	rmp->max_priority = m_ptr->m_lsys_sched_scheduling_start.maxprio;
	if (rmp->max_priority >= NR_SCHED_QUEUES) {
		return EINVAL;
	}

	/* Inherit current priority and time slice from parent. Since there
	 * is currently only one scheduler scheduling the whole system, this
	 * value is local and we assert that the parent endpoint is valid */
	if (rmp->endpoint == rmp->parent) {
		/* We have a special case here for init, which is the first
		   process scheduled, and the parent of itself. */
		rmp->priority   = USER_Q;
		rmp->time_slice = DEFAULT_USER_TIME_SLICE;

		/*
		 * Since kernel never changes the cpu of a process, all are
		 * started on the BSP and the userspace scheduling hasn't
		 * changed that yet either, we can be sure that BSP is the
		 * processor where the processes run now.
		 */
#ifdef CONFIG_SMP
		rmp->cpu = machine.bsp_id;
		/* FIXME set the cpu mask */
#endif
	}
	
	switch (m_ptr->m_type) {

	case SCHEDULING_START:
		/* We have a special case here for system processes, for which
		 * quanum and priority are set explicitly rather than inherited 
		 * from the parent */
		rmp->priority   = rmp->max_priority;
		rmp->time_slice = m_ptr->m_lsys_sched_scheduling_start.quantum;
		break;
		
	case SCHEDULING_INHERIT:
		/* Inherit current priority and time slice from parent. Since there
		 * is currently only one scheduler scheduling the whole system, this
		 * value is local and we assert that the parent endpoint is valid */
		if ((rv = sched_isokendpt(m_ptr->m_lsys_sched_scheduling_start.parent,
				&parent_nr_n)) != OK)
			return rv;

		rmp->priority = schedproc[parent_nr_n].priority;
		rmp->time_slice = schedproc[parent_nr_n].time_slice;
        // hm438596
        rmp->deadline = schedproc[parent_nr_n].deadline;
        rmp->estimate = schedproc[parent_nr_n].estimate;
        rmp->kill = schedproc[parent_nr_n].kill;
        rmp->used_time = schedproc[parent_nr_n].used_time;
        rmp->previous_priority = schedproc[parent_nr_n].previous_priority;
		break;
		
	default: 
		/* not reachable */
		assert(0);
	}

	/* Take over scheduling the process. The kernel reply message populates
	 * the processes current priority and its time slice */
	if ((rv = sys_schedctl(0, rmp->endpoint, 0, 0, 0)) != OK) {
		printf("Sched: Error taking over scheduling for %d, kernel said %d\n",
			rmp->endpoint, rv);
		return rv;
	}
	rmp->flags = IN_USE;

	/* Schedule the process, giving it some quantum */
	pick_cpu(rmp);
	while ((rv = schedule_process(rmp, SCHEDULE_CHANGE_ALL)) == EBADCPU) {
		/* don't try this CPU ever again */
		cpu_proc[rmp->cpu] = CPU_DEAD;
		pick_cpu(rmp);
	}

	if (rv != OK) {
		printf("Sched: Error while scheduling process, kernel replied %d\n",
			rv);
		return rv;
	}

	/* Mark ourselves as the new scheduler.
	 * By default, processes are scheduled by the parents scheduler. In case
	 * this scheduler would want to delegate scheduling to another
	 * scheduler, it could do so and then write the endpoint of that
	 * scheduler into the "scheduler" field.
	 */

	m_ptr->m_sched_lsys_scheduling_start.scheduler = SCHED_PROC_NR;

	return OK;
}

/*===========================================================================*
 *				do_nice					     *
 *===========================================================================*/
int do_nice(message *m_ptr)
{
	struct schedproc *rmp;
	int rv;
	int proc_nr_n;
	unsigned new_q, old_q, old_max_q;

	/* check who can send you requests */
	if (!accept_message(m_ptr))
		return EPERM;

	if (sched_isokendpt(m_ptr->m_pm_sched_scheduling_set_nice.endpoint, &proc_nr_n) != OK) {
		printf("SCHED: WARNING: got an invalid endpoint in OoQ msg "
		"%d\n", m_ptr->m_pm_sched_scheduling_set_nice.endpoint);
		return EBADEPT;
	}

	rmp = &schedproc[proc_nr_n];
	new_q = m_ptr->m_pm_sched_scheduling_set_nice.maxprio;
	if (new_q >= NR_SCHED_QUEUES) {
		return EINVAL;
	}

	/* Store old values, in case we need to roll back the changes */
	old_q     = rmp->priority;
	old_max_q = rmp->max_priority;

    // hm438596
    if (new_q == DEADLINE_Q) new_q += 1;
    if (old_q == DEADLINE_Q) return EINVAL;

	/* Update the proc entry and reschedule the process */
	rmp->max_priority = rmp->priority = new_q;

	if ((rv = schedule_process_local(rmp)) != OK) {
		/* Something went wrong when rescheduling the process, roll
		 * back the changes to proc struct */
		rmp->priority     = old_q;
		rmp->max_priority = old_max_q;
	}

	return rv;
}

/*===========================================================================*
 *				schedule_process			     *
 *===========================================================================*/
static int schedule_process(struct schedproc * rmp, unsigned flags)
{
	int err;
	int new_prio, new_quantum, new_cpu;

	pick_cpu(rmp);

	if (flags & SCHEDULE_CHANGE_PRIO)
		new_prio = rmp->priority;
	else
		new_prio = -1;

	if (flags & SCHEDULE_CHANGE_QUANTUM)
		new_quantum = rmp->time_slice;
	else
		new_quantum = -1;

	if (flags & SCHEDULE_CHANGE_CPU)
		new_cpu = rmp->cpu;
	else
		new_cpu = -1;

    // hm438596
    int64_t new_deadline = rmp->deadline;
    int64_t new_estimate = rmp->estimate;
    bool new_kill = rmp->kill;
	if ((err = sys_schedule(rmp->endpoint, new_prio,
		new_quantum, new_cpu, new_deadline, new_estimate, new_kill)) != OK) {
		printf("PM: An error occurred when trying to schedule %d: %d\n",
		rmp->endpoint, err);
	}

	return err;
}


/*===========================================================================*
 *				start_scheduling			     *
 *===========================================================================*/

void init_scheduling(void)
{
	balance_timeout = BALANCE_TIMEOUT * sys_hz();
	init_timer(&sched_timer);
	set_timer(&sched_timer, balance_timeout, balance_queues, 0);
}

/*===========================================================================*
 *				balance_queues				     *
 *===========================================================================*/

/* This function in called every 100 ticks to rebalance the queues. The current
 * scheduler bumps processes down one priority when ever they run out of
 * quantum. This function will find all proccesses that have been bumped down,
 * and pulls them back up. This default policy will soon be changed.
 */
static void balance_queues(minix_timer_t *tp)
{
	struct schedproc *rmp;
	int proc_nr;

	for (proc_nr=0, rmp=schedproc; proc_nr < NR_PROCS; proc_nr++, rmp++) {
		if (rmp->flags & IN_USE) {
            // hm438596
			if (rmp->priority > rmp->max_priority && rmp->priority != DEADLINE_Q) {
				rmp->priority -= 1; /* increase priority */
                if (rmp->priority == DEADLINE_Q) rmp->priority -= 1;
				schedule_process_local(rmp);
			}
		}
	}

	set_timer(&sched_timer, balance_timeout, balance_queues, 0);
}

/*===========================================================================*
 *				do_deadline_scheduling, hm438596				     *
 *===========================================================================*/
int do_deadline_scheduling(message *m_ptr) {
    printf("SCHED: do_deadline_scheduling called\n");
    struct schedproc *rmp;
    int rv;
    int proc_nr_n;
    unsigned old_q;

    /* Check who can send you requests */
    if (!accept_message(m_ptr))
        return EPERM;

    if (sched_isokendpt(m_ptr->m_sched_endpoint, &proc_nr_n) != OK) {
        printf("SCHED: WARNING: got an invalid endpoint in OoQ msg %d\n", m_ptr->m_sched_endpoint);
        return EBADEPT;
    }

    /* Save variables for later */
    rmp = &schedproc[proc_nr_n];
    old_q = rmp->priority;
    int64_t deadline = m_ptr->m_sched_deadline, estimate = m_ptr->m_sched_estimate;
    bool kill = m_ptr->m_sched_kill;

    /* Get current time to check if the deadline is in the past */
    int64_t now = get_now();
    printf("SCHED: current time = %lld\n", now);

    /* Check if the deadline can be met */
    if (now + estimate > deadline && deadline != -1) {
        printf("SCHED: WARNING: wrong deadline, cannot schedule process\n");
        return EINVAL;
    }

    /* Check if the estimate is valid */
    if (estimate < 0) {
        printf("SCHED: WARNING: wrong estimate, cannot schedule process\n");
        return EINVAL;
    }

    /* Check if the process is already in the deadline queue */
    if (old_q == DEADLINE_Q && deadline != -1) {
        printf("SCHED: WARNING: process %d is already in deadline queue\n", rmp->endpoint);
        return EPERM;
    }

    /* Check if process can abort deadline scheduling */
    if (old_q != DEADLINE_Q && deadline == -1) {
        printf("SCHED: WARNING: process %d can't abort deadline scheduling\n", rmp->endpoint);
        return EPERM;
    }

    /* Check if deadline is in the past */
    if (now > deadline && deadline != -1) {
        printf("SCHED: WARNING: deadline is in the past, cannot schedule process\n");
        if (old_q != DEADLINE_Q) return OK;
        rmp->priority = rmp->previous_priority;
        return schedule_process_local(rmp);
    }

    /* Update the proc entry and reschedule the process */
    if (deadline == -1) {
        printf("SCHED: process %d aborts deadline scheduling\n", rmp->endpoint);
        rmp->priority = rmp->previous_priority;
    } else {
        printf("SCHED: process %d starts deadline scheduling\n", rmp->endpoint);
        rmp->priority = DEADLINE_Q;
    }

    rmp->deadline = deadline;
    rmp->estimate = estimate;
    rmp->kill = kill;
    rmp->previous_priority = old_q;
    rmp->used_time = 0;
    if ((rv = schedule_process_local(rmp)) != OK) {
        printf("SCHED: An error occurred when trying to schedule %d: %d\n", rmp->endpoint, rv);
        rmp->priority = old_q;
    }

    return rv;
}
