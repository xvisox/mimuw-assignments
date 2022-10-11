package przyklady01;

import java.util.ArrayList;

public class Primes {
    static int[] check = new int[]{2, 3, 5, 7, 11, 13, 17, 19, 23, 29};
    static int[] starts = new int[]{31, 37, 41, 43, 47, 49, 53, 59};
    static final int BOUND = 10000;
    static volatile boolean found = false;
    static ArrayList<Thread> threads;

    static boolean areAlive() {
        for (var thread : threads) {
            if (thread.isAlive()) return true;
        }
        return false;
    }

    static boolean isPrime(int n) {
        for (var el : check) {
            if (n % el == 0) {
                return false;
            }
        }
        // Odpalanie wątków.
        found = false;
        threads = new ArrayList<>();
        for (var start : starts) {
            Runnable r = new Primer(start, n);
            Thread t = new Thread(r);
            threads.add(t);
            t.start();
        }
        while (areAlive()) {
            // WAIT
        }
        return !found;
    }

    private static class Primer implements Runnable {
        private int start;
        private final int n;

        private Primer(int start, int n) {
            this.start = start;
            this.n = n;
        }

        @Override
        public void run() {
            while (start < n && !found) {
                if (n % start == 0) {
                    found = true;
                }
                start += 30;
            }
        }
    }

    public static void main(String[] args) {
        int counter = 0;
        for (int i = 2; i < BOUND; i++) {
            if (isPrime(i)) counter++;
        }
        System.out.println(counter + check.length);
    }

}
