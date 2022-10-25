package zaliczeniowe.macierzsafe;

import java.util.ArrayList;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.function.IntBinaryOperator;

public class MatrixRowSums {
    private static final int ROWS = 1000;
    private static final int COLUMNS = 100;

    private static class Matrix {
        private final int rows;
        private final int columns;
        private final IntBinaryOperator definition;
        // Thread for every column.
        private final ArrayList<Thread> threads;
        // ConcurrentDeque for every row.
        private final ConcurrentHashMap<Integer, LinkedBlockingQueue<Integer>> rowsValues;

        public Matrix(int rows, int columns, IntBinaryOperator definition) {
            this.rows = rows;
            this.columns = columns;
            this.definition = definition;
            this.threads = new ArrayList<>();
            this.rowsValues = new ConcurrentHashMap<>();
        }

        public int[] rowSums() {
            int[] rowSums = new int[rows];
            for (int row = 0; row < rows; ++row) {
                int sum = 0;
                for (int column = 0; column < columns; ++column) {
                    sum += definition.applyAsInt(row, column);
                }
                rowSums[row] = sum;
            }
            return rowSums;
        }

        public int[] rowSumsConcurrent() {
            int[] rowSums = new int[rows];

            // Creating and starting thread for every column.
            for (int i = 0; i < columns; i++) {
                threads.add(new Thread(new ColumnRunnable(i, this)));
            }
            for (var thread : threads) {
                thread.start();
            }
            for (int i = 0; i < rows; i++) {
                for (int j = 0; j < columns; j++) {
                    try {
                        rowSums[i] += rowsValues.get(i).take();
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        System.out.println(Thread.currentThread().getName() + "interrupted!");
                    }
                }
                rowsValues.remove(i);
            }

            return rowSums;
        }

        private record ColumnRunnable(int column, Matrix matrix) implements Runnable {
            @Override
            public void run() {
                int computedValue;
                for (int row = 0; row < matrix.rows; row++) {
                    computedValue = matrix.definition.applyAsInt(row, column);
                    matrix.rowsValues.computeIfAbsent(row, k -> new LinkedBlockingQueue<>()).add(computedValue);
                }
            }
        }
    }

    public static void main(String[] args) {
        Matrix matrix = new Matrix(ROWS, COLUMNS, (row, column) -> {
            int a = 2 * column + 1;
            return (row + 1) * (a % 4 - 2) * a;
        });

        int[] rowSums = matrix.rowSums();
        int[] rowSumsConcurrent = matrix.rowSumsConcurrent();

        System.out.println("Sum sequential:");
        for (int i = 0; i < rowSums.length; i++) {
            System.out.println(i + " -> " + rowSums[i]);
        }

        System.out.println("Sum concurrent:");
        for (int i = 0; i < rowSums.length; i++) {
            assert (rowSumsConcurrent[i] == rowSums[i]);
            System.out.println(i + " -> " + rowSumsConcurrent[i]);
        }
    }
}
