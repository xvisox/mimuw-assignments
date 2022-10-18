package zaliczeniowe.macierz;

import java.util.concurrent.BrokenBarrierException;
import java.util.concurrent.CyclicBarrier;
import java.util.function.IntBinaryOperator;

public class MatrixRowSums {
    private static final int ROWS = 100;
    private static final int COLUMNS = 1000;

    private static class Matrix {
        private final int rows;
        private final int columns;
        private final IntBinaryOperator definition;

        private CyclicBarrier barrier;
        private static int row = 0;

        public Matrix(int rows, int columns, IntBinaryOperator definition) {
            this.rows = rows;
            this.columns = columns;
            this.definition = definition;
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
            int[] oneRow = new int[columns];
            barrier = new CyclicBarrier(columns, new SumOneRow(rowSums, oneRow));

            Thread[] threads = new Thread[columns];

            // Creating and starting up threads.
            for (int column = 0; column < columns; column++) {
                threads[column] = new Thread(new ColumnRunnable(column, this, oneRow));
            }
            for (var thread : threads) {
                thread.start();
            }
            for (var thread : threads) {
                try {
                    thread.join();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    System.out.println(Thread.currentThread().getName() + " interrupted!");
                    throw new RuntimeException(e);
                }
            }

            return rowSums;
        }

        private record ColumnRunnable(int column, Matrix matrix, int[] oneRow) implements Runnable {
            @Override
            public void run() {
                for (int row = 0; row < matrix.rows; row++) {
                    oneRow[column] = matrix.definition.applyAsInt(row, column);
                    try {
                        matrix.barrier.await();
                    } catch (InterruptedException | BrokenBarrierException e) {
                        throw new RuntimeException(e);
                    }
                }
            }
        }

        private record SumOneRow(int[] rowSums, int[] oneRow) implements Runnable {
            @Override
            public void run() {
                for (int val : oneRow) {
                    rowSums[row] += val;
                }
                row++;
            }
        }
    }

    public static void main(String[] args) {
        Matrix matrix = new Matrix(ROWS, COLUMNS, (row, column) -> {
            int a = 2 * column + 1;
            return (row + 1) * (a % 4 - 2) * a;
        });

        System.out.println("Result sequential:");
        int[] rowSums = matrix.rowSums();
        for (int i = 0; i < rowSums.length; i++) {
            System.out.println(i + " -> " + rowSums[i]);
        }

        System.out.println("Result concurrent:");
        int[] rowSumsConcurrent = matrix.rowSumsConcurrent();
        for (int i = 0; i < rowSums.length; i++) {
            System.out.println(i + " -> " + rowSumsConcurrent[i]);
            assert (rowSumsConcurrent[i] == rowSums[i]);
        }
    }
}
