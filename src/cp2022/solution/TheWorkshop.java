package cp2022.solution;

import cp2022.base.Workplace;
import cp2022.base.WorkplaceId;
import cp2022.base.Workshop;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;

public class TheWorkshop implements Workshop {

    private static class WrappedThread {
        private final long threadId;
        private final WorkplaceId workplaceId;
        private final boolean isEnter;
        private boolean marked;
        private int released;

        private WrappedThread(long threadId, int released, WorkplaceId workplaceId, boolean isEnter) {
            this.threadId = threadId;
            this.released = released;
            this.workplaceId = workplaceId;
            this.isEnter = isEnter;
            this.marked = false;
        }

        private void increment(int count) {
            released += count;
        }
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

    public TheWorkshop(Collection<Workplace> workplaces) {
        for (var workplace : workplaces) {
            this.workplaces.put(workplace.getId(), new WrappedWorkplace(workplace));
        }
        this.N = workplaces.size();
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
        waitingRoom.add(new WrappedThread(threadId, 0, wid, true));
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

        waitingRoom.add(new WrappedThread(threadId, 0, wid, false));
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
        // Firstly, we set all the necessary variables.
        for (var thread : cycle) {
            waitingToOccupy.get(thread).setWhoIsOccupying(thread);
            waitingToOccupy.remove(thread);
        }
        // Releasing threads in cycle.
        // Disclaimer - we can wake them up in a loop
        // because all the necessary variables are now set
        // and the threads will synchronize through the
        // work semaphore.
        for (var thread : cycle) {
            semaphores.get(thread).release();
        }
        // Removing released threads from waiting room.
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
    // as long as first elements are removed in order that they were added
    // to waiting room, so we must wait for previous workplace to wake up
    // another threads.
    void releaseThreadsFromBeginning() {
        WrappedThread threadToRelease;
        while (!waitingRoom.isEmpty() && canOccupy(waitingRoom.get(0).workplaceId)) {
            threadToRelease = waitingRoom.get(0);
            waitingRoom.remove(threadToRelease);
            workplaces.get(threadToRelease.workplaceId).setRelease();
            releaseThread(threadToRelease);
            if (threadToRelease.threadId == Thread.currentThread().getId()) continue;

            try {
                // Waiting for the permission from the worker.
                workplaces.get(threadToRelease.workplaceId).permissionSemaphore().acquire();
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
        }
    }

    void releaseThreadsWithoutStarvation() {
        WrappedThread threadToRelease, previous = null;
        ListIterator<WrappedThread> it = waitingRoom.listIterator();
        int releasedAfterFirst = waitingRoom.get(0).released;

        while (it.hasNext() && releasedAfterFirst < (2 * N - 1)) {
            threadToRelease = it.next();

            if (canOccupy(threadToRelease.workplaceId)) {
                it.remove();
                releaseThread(threadToRelease);
                if (threadToRelease.isEnter) {
                    releasedAfterFirst++;
                    assert (previous != null);
                    previous.marked = true;
                }
            }

            previous = threadToRelease;
        }

        // Updating the information about how many threads
        // were released after every thread in waiting room.
        int diff = releasedAfterFirst - waitingRoom.get(0).released;
        for (var thread : waitingRoom) {
            thread.increment(diff);
            if (thread.marked) {
                diff--;
                thread.marked = false;

                if (diff == 0) break;
            }
        }

        // From this moment, all the threads that are being
        // released were called from switchTo method,
        // so they can't cause starvation.
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
