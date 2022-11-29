package cp2022.solution;

import cp2022.base.Workplace;

import java.util.concurrent.Semaphore;

import static cp2022.solution.TheWorkshop.currentlyOccupying;

public class WrappedWorkplace extends Workplace {
    private final Workplace workplace;
    private final Semaphore work;
    private StatusOfWorkplace state;
    private Long occupiedBy;

    protected WrappedWorkplace(Workplace workplace) {
        super(workplace.getId());
        this.workplace = workplace;
        this.work = new Semaphore(1);
        this.state = StatusOfWorkplace.EMPTY;
        this.occupiedBy = null;
    }

    public StatusOfWorkplace getState() {
        return state;
    }

    public Semaphore workSemaphore() {
        return work;
    }

    public Long whoIsOccupying() {
        return occupiedBy;
    }

    public void setWhoIsOccupying(Long occupiedBy) {
        this.occupiedBy = occupiedBy;
        this.state = StatusOfWorkplace.WORKING;
    }

    public void setState(StatusOfWorkplace state) {
        this.state = state;
    }

    @Override
    public void use() {
        WrappedWorkplace toRelease = currentlyOccupying.getOrDefault(Thread.currentThread().getId(), null);
        currentlyOccupying.put(Thread.currentThread().getId(), this);
        if (toRelease != null) {
            toRelease.work.release();
            if (toRelease.occupiedBy == Thread.currentThread().getId() && toRelease != this) {
                toRelease.state = StatusOfWorkplace.EMPTY;
            }
        }

        try {
            work.acquire();
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }

        workplace.use();
        state = StatusOfWorkplace.OCCUPIED;
    }
}
