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
        private int marked;
        private int released;

        private WrappedThread(long threadId, WorkplaceId workplaceId, boolean isEnter) {
            this.threadId = threadId;
            this.workplaceId = workplaceId;
            this.isEnter = isEnter;
            this.released = 0;
            this.marked = 0;
        }

        private void increment(int count) {
            released += count;
        }
    }

    // I am identifying thread as worker.
    // Information about which worker is where.
    public final Map<Long, WrappedWorkplace> currentlyOccupying = new ConcurrentHashMap<>();
    // A semaphore for every worker.
    public final Map<Long, Semaphore> semaphores = new ConcurrentHashMap<>();
    // Mapping workplace identifier to workplace.
    private final Map<WorkplaceId, WrappedWorkplace> workplaces = new ConcurrentHashMap<>();
    // Information about for what workers are waiting for.
    private final Map<Long, WrappedWorkplace> waitingToOccupy = new HashMap<>();
    // "Queue" of all workers waiting for their workplaces.
    private final List<WrappedThread> waitingRoom = new LinkedList<>();

    private final HashSet<Long> cycle = new HashSet<>();
    private final Semaphore mutex = new Semaphore(1);
    private final int N; // Number of workplaces.

    public TheWorkshop(Collection<Workplace> workplaces) {
        for (var workplace : workplaces) {
            this.workplaces.put(workplace.getId(), new WrappedWorkplace(workplace, this));
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
        waitingRoom.add(new WrappedThread(threadId, wid, true));
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

        waitingRoom.add(new WrappedThread(threadId, wid, false));
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

        if (found) resolveCycle();
        cycle.clear();
    }

    void resolveCycle() {
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
        occupyWorkplace(threadToRelease);
        semaphores.get(threadToRelease.threadId).release();
    }

    void occupyWorkplace(WrappedThread threadToRelease) {
        waitingToOccupy.remove(threadToRelease.threadId);
        workplaces.get(threadToRelease.workplaceId).setWhoIsOccupying(threadToRelease.threadId);
    }

    // Releasing threads from the beginning of list can't cause starvation
    // as long as first elements are removed in order that they were added
    // to waiting room, so we must wait for previous worker to wake up
    // another threads (cascade releasing).
    WrappedThread releaseThreadsFromBeginning() {
        WrappedThread thread, lastThread = null;
        while (!waitingRoom.isEmpty() && canOccupy(waitingRoom.get(0).workplaceId)) {
            thread = waitingRoom.get(0);
            waitingRoom.remove(thread);
            if (lastThread == null) {
                releaseThread(thread);
            } else {
                occupyWorkplace(thread);
                workplaces.get(lastThread.workplaceId).setThreadToRelease(thread.threadId);
            }

            lastThread = thread;
        }
        return lastThread;
    }

    void updateReleasedAfterStatistic(int releasedAfterFirst) {
        int diff = releasedAfterFirst - waitingRoom.get(0).released;
        for (var thread : waitingRoom) {
            thread.increment(diff);
            if (thread.marked > 0) {
                diff -= thread.marked;
                thread.marked = 0;

                if (diff == 0) break;
            }
        }
    }

    void releaseThreadsWithoutStarvation(WrappedThread lastThread) {
        int releasedAfterFirst = waitingRoom.get(0).released;
        ListIterator<WrappedThread> it = waitingRoom.listIterator();
        WrappedThread thread, previous = it.next();

        while (it.hasNext() && releasedAfterFirst < (2 * N - 1)) {
            thread = it.next();

            if (canOccupy(thread.workplaceId)) {
                it.remove();

                if (thread.isEnter) {
                    releasedAfterFirst++;
                    previous.marked++;

                    if (lastThread == null) {
                        releaseThread(thread);
                    } else {
                        occupyWorkplace(thread);
                        workplaces.get(lastThread.workplaceId).setThreadToRelease(thread.threadId);
                    }

                    lastThread = thread;
                } else {
                    releaseThread(thread);
                }
            }

            previous = thread;
        }

        // Updating the information about how many threads
        // were released after every thread in waiting room.
        updateReleasedAfterStatistic(releasedAfterFirst);

        // From this moment, all the threads that are being
        // released were called from switchTo method,
        // so they can't cause starvation.
        while (it.hasNext()) {
            thread = it.next();
            if (!thread.isEnter && canOccupy(thread.workplaceId)) {
                it.remove();
                releaseThread(thread);
            }
        }
    }

    void normalize() {
        WrappedThread lastThread = releaseThreadsFromBeginning();
        if (waitingRoom.isEmpty()) return;
        releaseThreadsWithoutStarvation(lastThread);
    }
}
