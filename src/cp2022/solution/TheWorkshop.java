package cp2022.solution;

import cp2022.base.Workplace;
import cp2022.base.WorkplaceId;
import cp2022.base.Workshop;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;

public class TheWorkshop implements Workshop {

    private record WrappedThread(long threadId, int moment, WorkplaceId workplaceId) {
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
//            System.out.println("elo");
            mutex.acquire();
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }

        semaphores.putIfAbsent(Thread.currentThread().getId(), new Semaphore(0));
        waitingToOccupy.put(Thread.currentThread().getId(), workplaces.get(wid));
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

        waitingRoom.add(new WrappedThread(Thread.currentThread().getId(), globalTime, wid));
        waitingToOccupy.put(Thread.currentThread().getId(), workplaces.get(wid));
        normalize();
        if (waitingToOccupy.containsKey(Thread.currentThread().getId())) {

            Long first = Thread.currentThread().getId();
            Long waitingThreadId = Thread.currentThread().getId();
            HashSet<Long> cycle = new HashSet<>();
            cycle.add(waitingThreadId);

            boolean found = false;
            WrappedWorkplace waitingFor;
            while (!found) {
                waitingFor = waitingToOccupy.get(waitingThreadId);
                if (waitingFor.getState() != StatusOfWorkplace.OCCUPIED) {
                    break;
                } else {
                    waitingThreadId = waitingFor.whoIsOccupying();
                    if (waitingThreadId.equals(first)) {
                        found = true;
                    } else {
                        cycle.add(waitingThreadId);
                    }
                }
            }

            if (found) {
                for (var thread : cycle) {
                    waitingToOccupy.get(thread).setWhoIsOccupying(thread);
                    waitingToOccupy.remove(thread);
                    semaphores.get(thread).release();
                }
                var it = waitingRoom.listIterator();
                while (it.hasNext()) {
                    if (cycle.contains(it.next().threadId)) {
                        it.remove();
                    }
                }
            } else {
                // nic ?
            }

        } else {
            setStatusToEmpty(currentlyOccupied);
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

    void setStatusToEmpty(WrappedWorkplace workplace) {
        if (workplace != null) workplace.setState(StatusOfWorkplace.EMPTY);
    }

    boolean canOccupy(WorkplaceId workplaceId) {
        return workplaces.get(workplaceId).getState() == StatusOfWorkplace.EMPTY;
    }

    void normalize() {
        for (var el : waitingRoom) {
            System.out.print(el.threadId + " ");
        }
        System.out.println();
        WrappedThread threadToRemove, waitingThread;

        while (!waitingRoom.isEmpty() && canOccupy(waitingRoom.get(0).workplaceId)) {
//            System.out.println("wpuszczam");
            threadToRemove = waitingRoom.get(0);
            waitingRoom.remove(threadToRemove);

            waitingToOccupy.remove(threadToRemove.threadId);
            workplaces.get(threadToRemove.workplaceId).setWhoIsOccupying(threadToRemove.threadId);
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
//                System.out.println("wpuszczam 1");
                threadToRemove = waitingThread;
                it.remove();

                waitingToOccupy.remove(threadToRemove.threadId);
                workplaces.get(threadToRemove.workplaceId).setWhoIsOccupying(threadToRemove.threadId);
                semaphores.get(threadToRemove.threadId).release();
            }
        }
        System.out.println("end of");
    }
}
