package cp2022.solution;

import cp2022.base.Workplace;
import cp2022.base.WorkplaceId;
import cp2022.base.Workshop;

import java.util.ArrayList;
import java.util.Collection;

public class WrappedWorkshop implements Workshop {
    private final ArrayList<WrappedWorkplace> workplaces = new ArrayList<>();

    public WrappedWorkshop(Collection<Workplace> workplaces) {
        for (var workplace : workplaces) {
            this.workplaces.add(new WrappedWorkplace(workplace));
        }
    }

    private WrappedWorkplace getWorkplaceById(WorkplaceId workplaceId) {
        for (var workplace : workplaces) {
            if (workplace.getId() == workplaceId) {
                return workplace;
            }
        }
        return null;
    }

    @Override
    public Workplace enter(WorkplaceId wid) {
        return null;
    }

    @Override
    public Workplace switchTo(WorkplaceId wid) {
        return null;
    }

    @Override
    public void leave() {

    }
}
