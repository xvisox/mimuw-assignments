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

    public static final Map<Long, WrappedWorkplace> currentlyOccupying = new ConcurrentHashMap<>();
    private final Map<WorkplaceId, WrappedWorkplace> workplaces = new ConcurrentHashMap<>();
    private final Map<Long, Semaphore> semaphores = new ConcurrentHashMap<>();
    private final List<WrappedThread> waitingRoom = new LinkedList<>();
    private final Semaphore mutex = new Semaphore(1);
    private final int N;
    private int globalTime;

    public TheWorkshop(Collection<Workplace> workplaces) {
        for (var workplace : workplaces) {
            this.workplaces.put(workplace.getId(), new WrappedWorkplace(workplace));
        }
        this.N = workplaces.size();
        this.globalTime = 0;
    }

    @Override
    public Workplace enter(WorkplaceId wid) {
        try {
            mutex.acquire();
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }

        WrappedWorkplace currentlyOccupied = currentlyOccupying.getOrDefault(Thread.currentThread().getId(), null);
        setStatusToFinished(currentlyOccupied);
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

        // SwitchTo was called to the same place as previously.
        WrappedWorkplace currentlyOccupied = currentlyOccupying.getOrDefault(Thread.currentThread().getId(), null);
        if (currentlyOccupied != null && currentlyOccupied.getId() == wid) {
            mutex.release();
            return currentlyOccupied;
        }

        setStatusToFinished(currentlyOccupied);
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

        WrappedWorkplace currentlyOccupied = currentlyOccupying.getOrDefault(Thread.currentThread().getId(), null);
        setStatusToFinished(currentlyOccupied);
        normalize();
        mutex.release();

        WrappedWorkplace toRelease = currentlyOccupying.getOrDefault(Thread.currentThread().getId(), null);
        if (toRelease != null) {
            currentlyOccupying.remove(Thread.currentThread().getId());
            toRelease.workSemaphore().release();
        }
    }

    void setStatusToFinished(WrappedWorkplace workplace) {
        if (workplace != null) workplace.setState(StatusOfWork.FINISHED);
    }

    boolean canOccupy(WorkplaceId workplaceId) {
        return workplaces.get(workplaceId).getState() != StatusOfWork.IN_PROGRESS;
    }

    void normalize() {
        WrappedThread threadToRemove, waitingThread;

        while (!waitingRoom.isEmpty() && canOccupy(waitingRoom.get(0).workplaceId)) {
            threadToRemove = waitingRoom.get(0);
            waitingRoom.remove(threadToRemove);

            workplaces.get(threadToRemove.workplaceId).setState(StatusOfWork.IN_PROGRESS);
            semaphores.get(threadToRemove.threadId).release();
        }
        if (waitingRoom.isEmpty()) return;

        ListIterator<WrappedThread> it = waitingRoom.listIterator();
        WrappedThread first = waitingRoom.get(0);
        it.next();

        while (it.hasNext()) {
            waitingThread = it.next();

            if (waitingThread.moment - first.moment >= 2 * N) {
                break;
            }
            if (canOccupy(waitingThread.workplaceId)) {
                threadToRemove = waitingThread;
                it.remove();

                workplaces.get(threadToRemove.workplaceId).setState(StatusOfWork.IN_PROGRESS);
                semaphores.get(threadToRemove.threadId).release();
            }
        }
    }
}
