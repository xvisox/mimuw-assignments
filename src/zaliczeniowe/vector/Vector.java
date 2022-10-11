package zaliczeniowe.vector;

import java.util.ArrayList;
import java.util.Arrays;

public class Vector {
    private final int[] values;
    private final int length;
    private static final int SUBVECTOR_LENGTH = 10;

    public Vector(int... values) {
        this.values = values;
        this.length = values.length;
    }

    public int[] getValues() {
        return values;
    }

    private enum Operation {
        ADD, MULTIPLY
    }

    public Vector sumSeq(Vector other) {
        int[] newValues = new int[length];
        int i = 0;
        while (i < length) {
            newValues[i] = other.values[i] + values[i];
            i++;
        }
        return new Vector(newValues);
    }

    public Vector dotSeq(Vector other) {
        int[] newValues = new int[length];
        int i = 0;
        while (i < length) {
            newValues[i] = other.values[i] * values[i];
            i++;
        }
        return new Vector(newValues);
    }

    private Vector operationOnVectors(Vector other, Operation operation) {
        int[] newValues = new int[length];
        ArrayList<Thread> threads = new ArrayList<>();
        int i = 0;
        while (i < length) {
            Thread t = new Thread(new VectorRunnable(i, operation, values, other.values, newValues));
            threads.add(t);
            t.start();
            i += SUBVECTOR_LENGTH;
        }
        for (var thread : threads) {
            try {
                thread.join();
            } catch (InterruptedException e) {
                thread.interrupt();
            }
        }
        return new Vector(newValues);
    }

    public Vector sum(Vector other) {
        return operationOnVectors(other, Operation.ADD);
    }

    public Vector dot(Vector other) {
        return operationOnVectors(other, Operation.MULTIPLY);
    }

    @Override
    public String toString() {
        return Arrays.toString(values);
    }

    private record VectorRunnable(int start, Operation operation, int[] values1, int[] values2, int[] newValues)
            implements Runnable {

        @Override
        public void run() {
            int i = start;
            int end = Math.min(start + SUBVECTOR_LENGTH, newValues.length);
            if (operation.equals(Operation.MULTIPLY)) {
                while (i < end) {
                    newValues[i] = values1[i] * values2[i];
                    i++;
                }
            } else {
                while (i < end) {
                    newValues[i] = values1[i] + values2[i];
                    i++;
                }
            }
        }
    }
}
