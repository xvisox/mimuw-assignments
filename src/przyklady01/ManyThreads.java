package przyklady01;

public class ManyThreads {
    private static final int THREAD_COUNT = 10;

    private static class Helper implements Runnable {
        private final int n;

        public Helper(int n) {
            this.n = n;
        }

        @Override
        public void run() {
            // FIXME: implement here
            if (n < THREAD_COUNT) {
                Runnable r = new Helper(n + 1);
                Thread t = new Thread(r, String.valueOf(n + 1));
                t.start();
            }
            int i = 1;
            while (i < 1000000) {
                i += Math.pow(2, n);
            }
            System.out.println(n);
        }

    }

    public static void main(String[] args) {
        // FIXME: implement here
        Runnable r = new Helper(1);
        Thread t = new Thread(r, String.valueOf(1));
        t.start();
    }

}
