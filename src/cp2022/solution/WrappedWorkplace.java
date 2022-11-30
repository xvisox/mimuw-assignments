package cp2022.solution;

import cp2022.base.Workplace;

import java.util.concurrent.Semaphore;

import static cp2022.solution.TheWorkshop.currentlyOccupying;

public class WrappedWorkplace extends Workplace {
    private final Workplace workplace;
    private final Semaphore work;
    private final Semaphore permission;
    private StatusOfWorkplace status;
    private Long occupiedBy; // Who is currently occupying this place.
    private boolean shouldRelease;

    protected WrappedWorkplace(Workplace workplace) {
        super(workplace.getId());
        this.workplace = workplace;
        this.work = new Semaphore(1);
        this.permission = new Semaphore(0);
        this.status = StatusOfWorkplace.EMPTY;
        this.occupiedBy = null;
        this.shouldRelease = false;

    }

    public StatusOfWorkplace getStatus() {
        return status;
    }

    public Semaphore workSemaphore() {
        return work;
    }

    public Semaphore permissionSemaphore() {
        return permission;
    }

    public void setRelease() {
        this.shouldRelease = true;
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

    @Override
    public void use() {
        // The thread who is releasing other threads is
        // waiting for the permission to wake up another thread.
        if (shouldRelease) {
            permission.release();
            shouldRelease = false;
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
