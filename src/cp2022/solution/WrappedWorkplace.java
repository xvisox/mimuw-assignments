package cp2022.solution;

import cp2022.base.Workplace;

import java.util.concurrent.Semaphore;

public class WrappedWorkplace extends Workplace {
    private final Workplace workplace;
    private final Semaphore work;
    private final Semaphore mutex;
    private StateOfWork state;

    protected WrappedWorkplace(Workplace workplace) {
        super(workplace.getId());
        this.workplace = workplace;
        this.work = new Semaphore(1);
        this.mutex = new Semaphore(1);
        this.state = StateOfWork.FINISHED;
    }

    public StateOfWork getState() {
        return state;
    }

    @Override
    public void use() {
        try {
            work.acquire();
            mutex.acquire();
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        state = StateOfWork.IN_PROGRESS;

        mutex.release();
        workplace.use();

        try {
            mutex.acquire();
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        state = StateOfWork.FINISHED;

        mutex.release();
        work.release();
    }
}
