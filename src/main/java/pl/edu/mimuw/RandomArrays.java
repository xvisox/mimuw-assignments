package pl.edu.mimuw;

import pl.edu.mimuw.matrix.MatrixCellValue;

import java.util.Random;

public class RandomArrays {

    public static double[][] randomTwoDimArray(Random random, int n) {
        double[][] randTwoDim = new double[n][n];
        for (int i = 0; i < n; i++) {
            for (int j = 0; j < n; j++) {
                randTwoDim[i][j] = random.nextDouble() * 50;
            }
        }
        return randTwoDim;
    }

    public static double[] randomOneDimArray(Random random, int n) {
        double[] randOneDim = new double[n];
        for (int j = 0; j < n; j++) {
            randOneDim[j] = random.nextDouble() * 50;
        }
        return randOneDim;
    }

    public static MatrixCellValue[] randomMatrixCells(Random random, int n) {
        int howMany = n * n / 2;
        int randCol, randRow;
        MatrixCellValue[] randomValues = new MatrixCellValue[howMany];
        for (int i = 0; i < howMany; i++) {
            randRow = random.nextInt(n);
            randCol = random.nextInt(n);
            randomValues[i] = new MatrixCellValue(randRow, randCol, random.nextDouble() * 50);
        }
        return randomValues;
    }
}
