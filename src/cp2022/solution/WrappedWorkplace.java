package cp2022.solution;

import cp2022.base.Workplace;

import java.util.concurrent.Semaphore;

public class WrappedWorkplace extends Workplace {
    private final Workplace workplace;
    private final Semaphore work;
    private StateOfWork state;

    protected WrappedWorkplace(Workplace workplace) {
        super(workplace.getId());
        this.workplace = workplace;
        this.work = new Semaphore(1);
        this.state = StateOfWork.FINISHED;
    }

    public StateOfWork getState() {
        return state;
    }

    public void setState() {
        this.state = StateOfWork.IN_PROGRESS;
    }

    @Override
    public void use() {
        try {
            work.acquire();
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }

        workplace.use();
        state = StateOfWork.FINISHED;
        work.release();
    }
}
