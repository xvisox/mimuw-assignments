package cp2022.solution;

import cp2022.base.Workplace;

public class WrappedWorkplace extends Workplace {
    private final Workplace workplace;

    protected WrappedWorkplace(Workplace workplace) {
        super(workplace.getId());
        this.workplace = workplace;
    }

    @Override
    public void use() {
        // jakies warunki dunno bla bla
        workplace.use();
    }
}
