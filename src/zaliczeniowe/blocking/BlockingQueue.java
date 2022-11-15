package zaliczeniowe.blocking;

import java.util.LinkedList;

public class BlockingQueue<T> {
    private final int capacity;
    private final LinkedList<T> list;

    public BlockingQueue(int capacity) {
        this.capacity = capacity;
        this.list = new LinkedList<>();
    }

    public synchronized T take() throws InterruptedException {
        while (list.isEmpty()) {
            wait();
        }
        return list.pollFirst();
    }

    public synchronized void put(T item) throws InterruptedException {
        list.addLast(item);
        notifyAll();
    }

    public synchronized int getSize() {
        return list.size();
    }

    public int getCapacity() {
        return capacity;
    }
}