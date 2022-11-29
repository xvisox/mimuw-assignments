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

        semaphores.putIfAbsent(Thread.currentThread().getId(), new Semaphore(0));
        waitingToOccupy.put(Thread.currentThread().getId(), workplaces.get(wid));
        waitingRoom.add(new WrappedThread(Thread.currentThread().getId(), globalTime, wid, true));
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

        waitingRoom.add(new WrappedThread(Thread.currentThread().getId(), globalTime, wid, false));
        waitingToOccupy.put(Thread.currentThread().getId(), workplaces.get(wid));
        normalize();

        // Cycle detection.
        if (waitingToOccupy.containsKey(Thread.currentThread().getId())) {
            Long firstThreadId = Thread.currentThread().getId();
            Long waitingThreadId = Thread.currentThread().getId();
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
                    if (waitingThreadId.equals(firstThreadId)) {
                        found = true;
                    } else {
                        cycle.add(waitingThreadId);
                    }
                }
            }

            if (found) resolveCycle(cycle);
        }
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
        setStatusToEmpty(currentlyOccupied);
        normalize();
        mutex.release();

        if (currentlyOccupied != null) {
            currentlyOccupying.remove(Thread.currentThread().getId());
            currentlyOccupied.workSemaphore().release();
        }
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

    void releaseThread(WrappedThread threadToRemove) {
        waitingToOccupy.remove(threadToRemove.threadId);
        workplaces.get(threadToRemove.workplaceId).setWhoIsOccupying(threadToRemove.threadId);
        semaphores.get(threadToRemove.threadId).release();
    }

    // FIXME
    void normalize() {
//        for (var el : waitingRoom) {
//            System.out.print(el.threadId + " ");
//        }
//        System.out.println();
        WrappedThread threadToRemove, waitingThread;

        while (!waitingRoom.isEmpty() && canOccupy(waitingRoom.get(0).workplaceId)) {
            threadToRemove = waitingRoom.get(0);

            if (threadToRemove.isEnter) globalTime++;
            waitingRoom.remove(threadToRemove);
            releaseThread(threadToRemove);
        }
        if (waitingRoom.isEmpty()) return;

        ListIterator<WrappedThread> it = waitingRoom.listIterator();
        WrappedThread first = waitingRoom.get(0);
        it.next();

        while (it.hasNext()) {
            waitingThread = it.next();

            if (waitingThread.isEnter && (waitingThread.moment - first.moment) >= (2 * N - 2)) {
                break;
            }

            if (canOccupy(waitingThread.workplaceId)) {
                threadToRemove = waitingThread;

                if (threadToRemove.isEnter) globalTime++;
                it.remove();
                releaseThread(threadToRemove);
            }
        }

        while (it.hasNext()) {
            waitingThread = it.next();

            if (!waitingThread.isEnter && canOccupy(waitingThread.workplaceId)) {
                threadToRemove = waitingThread;
                it.remove();
                releaseThread(threadToRemove);
            }
        }
    }
}
