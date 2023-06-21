package cp2022.solution;

import cp2022.base.Workplace;

import java.util.concurrent.Semaphore;

public class WrappedWorkplace extends Workplace {
    private final TheWorkshop workshop; // Workshop to which this workplace belongs.
    private final Workplace workplace;  // The workplace which is being wrapped.
    private final Semaphore work;
    private StatusOfWorkplace status;
    private Long occupiedBy;            // Who is currently occupying this place.
    private Long threadToRelease;       // Thread that we should release.

    protected WrappedWorkplace(Workplace workplace, TheWorkshop workshop) {
        super(workplace.getId());
        this.workplace = workplace;
        this.work = new Semaphore(1);
        this.status = StatusOfWorkplace.EMPTY;
        this.occupiedBy = null;
        this.threadToRelease = null;
        this.workshop = workshop;
    }

    public StatusOfWorkplace getStatus() {
        return status;
    }

    public Semaphore workSemaphore() {
        return work;
    }

    public Long whoIsOccupying() {
        return occupiedBy;
    }

    public void setWhoIsOccupying(Long occupiedBy) {
        this.occupiedBy = occupiedBy;
        this.status = StatusOfWorkplace.WORKING;
    }

    public void setStatus(StatusOfWorkplace status) {
        this.status = status;
    }

    public void setThreadToRelease(Long threadToRelease) {
        this.threadToRelease = threadToRelease;
    }

    @Override
    public void use() {
        // Cascade waking up.
        if (threadToRelease != null) {
            workshop.semaphores.get(threadToRelease).release();
            threadToRelease = null;
        }

        // In this place, we want to release previously occupied workplace.
        // This code is actually executed only if the thread called switchTo() method.
        WrappedWorkplace previous = workshop.currentlyOccupying.getOrDefault(Thread.currentThread().getId(), null);
        workshop.currentlyOccupying.put(Thread.currentThread().getId(), this);
        if (previous != null) {
            previous.work.release();
            // If someone else is already on our previous workplace, or if we are on the same
            // workplace as we were before then nothing should change.
            // First condition is necessary in releasing the cycle and the second one
            // covers the case when switchTo() was called with the same workplace as before.
            if (previous.occupiedBy == Thread.currentThread().getId() && previous != this) {
                previous.occupiedBy = null;
                previous.status = StatusOfWorkplace.EMPTY;
            }
        }

        try {
            work.acquire();
        } catch (InterruptedException e) {
            throw new RuntimeException("panic: unexpected thread interruption");
        }

        workplace.use();
        status = StatusOfWorkplace.OCCUPIED;
    }
}
