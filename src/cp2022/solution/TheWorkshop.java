package cp2022.solution;

import cp2022.base.Workplace;
import cp2022.base.WorkplaceId;
import cp2022.base.Workshop;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;

public class TheWorkshop implements Workshop {

    private static class WrappedThread {
        private final WorkplaceId workplaceId;
        private final long threadId;
        private final int moment;

        private WrappedThread(long threadId, int moment, WorkplaceId workplaceId) {
            this.threadId = threadId;
            this.moment = moment;
            this.workplaceId = workplaceId;
        }
    }

    private final Map<WorkplaceId, WrappedWorkplace> workplaces = new ConcurrentHashMap<>();
    private final Map<Long, Semaphore> semaphores = new ConcurrentHashMap<>();
    private final List<WrappedThread> waitingRoom = new LinkedList<>();
    private final Semaphore mutex = new Semaphore(1);
    private final int N = workplaces.size();
    private int globalTime = 0;

    public TheWorkshop(Collection<Workplace> workplaces) {
        for (var workplace : workplaces) {
            this.workplaces.put(workplace.getId(), new WrappedWorkplace(workplace));
        }
    }

    @Override
    public Workplace enter(WorkplaceId wid) {
        try {
            mutex.acquire();
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }

        semaphores.putIfAbsent(Thread.currentThread().getId(), new Semaphore(0));
        waitingRoom.add(new WrappedThread(Thread.currentThread().getId(), globalTime++, wid));
        normalize();
        mutex.release();

        try {
            semaphores.get(Thread.currentThread().getId()).acquire();
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }

        return workplaces.get(wid);
    }

    @Override
    public Workplace switchTo(WorkplaceId wid) {
        try {
            mutex.acquire();
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }

        waitingRoom.add(new WrappedThread(Thread.currentThread().getId(), globalTime, wid));
        normalize();
        mutex.release();

        try {
            semaphores.get(Thread.currentThread().getId()).acquire();
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }

        return workplaces.get(wid);
    }

    @Override
    public void leave() {
        try {
            mutex.acquire();
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }

        normalize();
        mutex.release();
    }

    boolean isOccupied(WorkplaceId workplaceId) {
        return workplaces.get(workplaceId).getState() == StateOfWork.IN_PROGRESS;
    }

    void normalize() {
        while (!waitingRoom.isEmpty() && !isOccupied(waitingRoom.get(0).workplaceId)) {
            semaphores.get(waitingRoom.get(0).threadId).release();
            waitingRoom.remove(0);
        }
    }
}
