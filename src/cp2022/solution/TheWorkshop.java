package cp2022.solution;

import cp2022.base.Workplace;
import cp2022.base.WorkplaceId;
import cp2022.base.Workshop;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;

public class TheWorkshop implements Workshop {

    private record WrappedThread(long threadId, int moment, WorkplaceId workplaceId, boolean isEnter) {
    }

    public static final Map<Long, WrappedWorkplace> currentlyOccupying = new ConcurrentHashMap<>();
    private final Map<WorkplaceId, WrappedWorkplace> workplaces = new ConcurrentHashMap<>();
    private final Map<Long, Semaphore> semaphores = new ConcurrentHashMap<>();
    private final Map<Long, WrappedWorkplace> waitingToOccupy = new HashMap<>();
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

        var threadId = Thread.currentThread().getId();
        semaphores.putIfAbsent(threadId, new Semaphore(0));
        waitingToOccupy.put(threadId, workplaces.get(wid));
        waitingRoom.add(new WrappedThread(threadId, globalTime, wid, true));
        normalize();
        mutex.release();

        try {
            semaphores.get(threadId).acquire();
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
        var threadId = Thread.currentThread().getId();
        WrappedWorkplace currentlyOccupied = currentlyOccupying.getOrDefault(threadId, null);
        if (currentlyOccupied != null && currentlyOccupied.getId() == wid) {
            mutex.release();
            return currentlyOccupied;
        }

        waitingRoom.add(new WrappedThread(threadId, globalTime, wid, false));
        waitingToOccupy.put(threadId, workplaces.get(wid));
        normalize();

        // Cycle detection.
        if (waitingToOccupy.containsKey(threadId)) {
            findAndSolveCycle(threadId);
        }
        mutex.release();

        try {
            semaphores.get(threadId).acquire();
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

        var threadId = Thread.currentThread().getId();
        WrappedWorkplace currentlyOccupied = currentlyOccupying.getOrDefault(threadId, null);
        setStatusToEmpty(currentlyOccupied);
        normalize();
        mutex.release();

        if (currentlyOccupied != null) {
            currentlyOccupying.remove(threadId);
            currentlyOccupied.workSemaphore().release();
        }
    }

    void findAndSolveCycle(Long threadId) {
        Long waitingThreadId = threadId;
        HashSet<Long> cycle = new HashSet<>();
        WrappedWorkplace waitingFor;
        cycle.add(waitingThreadId);

        boolean found = false;
        while (!found) {
            waitingFor = waitingToOccupy.get(waitingThreadId);
            if (waitingFor == null || waitingFor.getState() != StatusOfWorkplace.OCCUPIED) {
                break;
            } else {
                waitingThreadId = waitingFor.whoIsOccupying();
                if (waitingThreadId.equals(threadId)) {
                    found = true;
                } else {
                    cycle.add(waitingThreadId);
                }
            }
        }

        if (found) resolveCycle(cycle);
    }

    void resolveCycle(HashSet<Long> cycle) {
        for (var thread : cycle) {
            waitingToOccupy.get(thread).setWhoIsOccupying(thread);
            waitingToOccupy.remove(thread);
            semaphores.get(thread).release();
        }
        waitingRoom.removeIf(wrappedThread -> cycle.contains(wrappedThread.threadId));
    }

    void setStatusToEmpty(WrappedWorkplace workplace) {
        if (workplace != null) workplace.setState(StatusOfWorkplace.EMPTY);
    }

    boolean canOccupy(WorkplaceId workplaceId) {
        return workplaces.get(workplaceId).getState() == StatusOfWorkplace.EMPTY;
    }

    void releaseThread(WrappedThread threadToRelease) {
        waitingToOccupy.remove(threadToRelease.threadId);
        workplaces.get(threadToRelease.workplaceId).setWhoIsOccupying(threadToRelease.threadId);
        semaphores.get(threadToRelease.threadId).release();
    }

    void releaseThreadsFromBeginning() {
        WrappedThread threadToRelease;
        while (!waitingRoom.isEmpty() && canOccupy(waitingRoom.get(0).workplaceId)) {
            threadToRelease = waitingRoom.get(0);

            if (threadToRelease.isEnter) globalTime++;
            waitingRoom.remove(threadToRelease);
            releaseThread(threadToRelease);
        }
    }

    boolean isStarvation(WrappedThread first) {
        return (globalTime - first.moment) >= (2 * N - 1);
    }

    void releaseThreadsWithoutStarvation() {
        WrappedThread threadToRelease;
        ListIterator<WrappedThread> it = waitingRoom.listIterator();
        WrappedThread first = waitingRoom.get(0);
//        it.next();

        while (it.hasNext()) {
            threadToRelease = it.next();

            if (threadToRelease.isEnter && isStarvation(first)) {
                break;
            }

            if (canOccupy(threadToRelease.workplaceId)) {
                if (threadToRelease.isEnter) globalTime++;
                it.remove();
                releaseThread(threadToRelease);
            }
        }

        while (it.hasNext()) {
            threadToRelease = it.next();

            if (!threadToRelease.isEnter && canOccupy(threadToRelease.workplaceId)) {
                it.remove();
                releaseThread(threadToRelease);
            }
        }
    }

    void normalize() {
        releaseThreadsFromBeginning();
        if (waitingRoom.isEmpty()) return;
        releaseThreadsWithoutStarvation();
    }
}
