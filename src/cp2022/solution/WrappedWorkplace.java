package cp2022.solution;

import cp2022.base.Workplace;

import java.util.concurrent.Semaphore;

import static cp2022.solution.TheWorkshop.currentlyOccupying;
import static cp2022.solution.TheWorkshop.semaphores;

public class WrappedWorkplace extends Workplace {
    private final Workplace workplace;
    private final Semaphore work;
    private StatusOfWorkplace status;
    private Long occupiedBy; // Who is currently occupying this place.
    private Long threadToRelease; // Thread that we should release.

    protected WrappedWorkplace(Workplace workplace) {
        super(workplace.getId());
        this.workplace = workplace;
        this.work = new Semaphore(1);
        this.status = StatusOfWorkplace.EMPTY;
        this.occupiedBy = null;
        this.threadToRelease = null;
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
        if (threadToRelease != null) {
            semaphores.get(threadToRelease).release();
            threadToRelease = null;
        }

        // In this place, we want to release previously occupied workplace.
        WrappedWorkplace toRelease = currentlyOccupying.getOrDefault(Thread.currentThread().getId(), null);
        currentlyOccupying.put(Thread.currentThread().getId(), this);
        if (toRelease != null) {
            toRelease.work.release();
            // If someone else is already on our previous workplace, or if we are on the same
            // workplace as we were before then nothing should change.
            if (toRelease.occupiedBy == Thread.currentThread().getId() && toRelease != this) {
                toRelease.status = StatusOfWorkplace.EMPTY;
            }
        }

        try {
            work.acquire();
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }

        workplace.use();
        status = StatusOfWorkplace.OCCUPIED;
    }
}
