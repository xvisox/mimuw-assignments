package cp2022.solution;

import cp2022.base.Workplace;

import java.util.concurrent.Semaphore;

import static cp2022.solution.TheWorkshop.currentlyOccupying;

public class WrappedWorkplace extends Workplace {
    private final Workplace workplace;
    private final Semaphore work;
    private StatusOfWork state;

    protected WrappedWorkplace(Workplace workplace) {
        super(workplace.getId());
        this.workplace = workplace;
        this.work = new Semaphore(1);
        this.state = StatusOfWork.FINISHED;
    }

    public StatusOfWork getState() {
        return state;
    }

    public Semaphore workSemaphore() {
        return work;
    }

    public void setState(StatusOfWork state) {
        this.state = state;
    }

    @Override
    public void use() {
        WrappedWorkplace toRelease = currentlyOccupying.getOrDefault(Thread.currentThread().getId(), null);
        currentlyOccupying.put(Thread.currentThread().getId(), this);
        if (toRelease != null) {
            toRelease.workSemaphore().release();
        }

        try {
            work.acquire();
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }

        workplace.use();
    }
}
