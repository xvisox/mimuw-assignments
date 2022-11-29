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

    // I am identifying thread as worker.
    // Information about which worker is where.
    public static final Map<Long, WrappedWorkplace> currentlyOccupying = new ConcurrentHashMap<>();
    // Mapping workplace identifier to workplace.
    private final Map<WorkplaceId, WrappedWorkplace> workplaces = new ConcurrentHashMap<>();
    // A semaphore for every worker.
    private final Map<Long, Semaphore> semaphores = new ConcurrentHashMap<>();
    // Information about for what workers are waiting for.
    private final Map<Long, WrappedWorkplace> waitingToOccupy = new HashMap<>();
    // "Queue" of all workers waiting for their workplaces.
    private final List<WrappedThread> waitingRoom = new LinkedList<>();

    private final Semaphore mutex = new Semaphore(1);
    private final int N; // Number of workplaces.
    private int globalTime; // Time concept of workshop, it increments with ended entries to workshop.

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
        normalize(); // Releases waiting threads if possible.
        mutex.release();

        try {
            // Trying to occupy the workplace.
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
        normalize(); // Releases waiting threads if possible.

        // Cycle detection - if worker is still waiting
        // for his wanted workplace that might mean
        // that he is in a cycle and should be released.
        if (waitingToOccupy.containsKey(threadId)) {
            findAndSolveCycle(threadId);
        }
        mutex.release();

        try {
            // Trying to occupy the workplace.
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
        // Releasing currently occupied workplace for other workers.
        WrappedWorkplace currentlyOccupied = currentlyOccupying.getOrDefault(threadId, null);
        currentlyOccupied.setStatus(StatusOfWorkplace.EMPTY);
        normalize(); // Releases waiting threads if possible.
        currentlyOccupying.remove(threadId);
        currentlyOccupied.workSemaphore().release();

        mutex.release();
    }

    void findAndSolveCycle(Long threadId) {
        Long waitingThreadId = threadId;
        HashSet<Long> cycle = new HashSet<>();
        WrappedWorkplace waitingFor;
        cycle.add(threadId);

        boolean found = false;
        while (!found) {
            waitingFor = waitingToOccupy.get(waitingThreadId);
            if (waitingFor == null || waitingFor.getStatus() != StatusOfWorkplace.OCCUPIED) {
                break; // This means that potential cycle has ended.
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

    boolean canOccupy(WorkplaceId workplaceId) {
        return workplaces.get(workplaceId).getStatus() == StatusOfWorkplace.EMPTY;
    }

    void releaseThread(WrappedThread threadToRelease) {
        waitingToOccupy.remove(threadToRelease.threadId);
        workplaces.get(threadToRelease.workplaceId).setWhoIsOccupying(threadToRelease.threadId);
        semaphores.get(threadToRelease.threadId).release();
    }

    // Releasing threads from the beginning of list can't cause starvation
    // so as long as first elements are removed we can continue releasing.
    void releaseThreadsFromBeginning() {
        WrappedThread threadToRelease;
        while (!waitingRoom.isEmpty() && canOccupy(waitingRoom.get(0).workplaceId)) {
            threadToRelease = waitingRoom.get(0);

            if (threadToRelease.isEnter) globalTime++;
            waitingRoom.remove(threadToRelease);
            releaseThread(threadToRelease);
        }
    }

    // Checking if releasing the thread would cause
    // the starvation of first waiting thread.
    boolean isStarvation(WrappedThread first) {
        return (globalTime - first.moment) >= (2 * N - 1);
    }

    void releaseThreadsWithoutStarvation() {
        WrappedThread threadToRelease;
        ListIterator<WrappedThread> it = waitingRoom.listIterator();
        WrappedThread first = waitingRoom.get(0);

        while (it.hasNext()) {
            threadToRelease = it.next();

            // If we release this worker, it would cause starvation.
            if (threadToRelease.isEnter && isStarvation(first)) break;

            if (canOccupy(threadToRelease.workplaceId)) {
                if (threadToRelease.isEnter) globalTime++;
                it.remove();
                releaseThread(threadToRelease);
            }
        }

        // From this moment, all the threads that are being
        // released were called from switchTo method,
        // so they can cause starvation.
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
