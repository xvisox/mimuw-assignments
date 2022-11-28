package cp2022.solution;

import cp2022.base.Workplace;
import cp2022.base.WorkplaceId;
import cp2022.base.Workshop;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;
import java.util.LinkedList;

public class TheWorkshop implements Workshop {

    private record WrappedThread(long threadId, int moment, WorkplaceId workplaceId) {
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
        WrappedThread toRemove;

        while (!waitingRoom.isEmpty() && !isOccupied(waitingRoom.get(0).workplaceId)) {
            toRemove = waitingRoom.get(0);
            waitingRoom.remove(toRemove);

            workplaces.get(toRemove.workplaceId).setState();
            semaphores.get(toRemove.threadId).release();
        }
        if (waitingRoom.isEmpty()) return;


        ListIterator<WrappedThread> it = waitingRoom.listIterator();
        WrappedThread first = waitingRoom.get(0);
        it.next();

        while (it.hasNext()) {
            if (it.next().moment - first.moment >= 2 * N) {
                break;
            }
            if (!isOccupied(it.next().workplaceId)) {
                toRemove = it.next();
                it.remove();

                workplaces.get(toRemove.workplaceId).setState();
                semaphores.get(toRemove.threadId).release();
            }
        }
    }
}
