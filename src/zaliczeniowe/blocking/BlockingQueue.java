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
        var result = list.pollFirst();
        notifyAll();
        return result;
    }

    public synchronized void put(T item) throws InterruptedException {
        while (list.size() == capacity) {
            wait();
        }
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