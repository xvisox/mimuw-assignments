package pl.edu.mimuw;

import pl.edu.mimuw.matrix.IDoubleMatrix;
import pl.edu.mimuw.matrix.Shape;

import java.util.Random;

import static pl.edu.mimuw.utility.RandomArrays.*;
import static pl.edu.mimuw.matrix.DoubleMatrixFactory.*;
import static pl.edu.mimuw.matrix.MatrixCellValue.cell;
import static pl.edu.mimuw.matrix.Shape.matrix;

public class Main {
    public static void main(String[] args) {
        int n = 10;
        Shape shape = Shape.matrix(n, n);
        Random random = new Random();

        boolean showMatrices = true;
        if (showMatrices) {
            // Full matrix of random values
            IDoubleMatrix commonMatrix = full(randomTwoDimArray(random, n));
            System.out.println(commonMatrix);

            // Diagonal matrix of random values
            IDoubleMatrix diagonalMatrix = diagonal(randomOneDimArray(random, n));
            System.out.println(diagonalMatrix);

            // Column matrix of random values
            IDoubleMatrix columnMatrix = columnMatrix(shape, randomOneDimArray(random, n));
            System.out.println(columnMatrix);

            // Row matrix of random values
            IDoubleMatrix rowMatrix = rowMatrix(shape, randomOneDimArray(random, n));
            System.out.println(rowMatrix);

            // Constant matrix of random value
            IDoubleMatrix constantMatrix = constant(shape, random.nextDouble() * 50);
            System.out.println(constantMatrix);

            // Identity matrix
            IDoubleMatrix identityMatrix = identity(n);
            System.out.println(identityMatrix);

            // Non regular sparse matrix of random values
            IDoubleMatrix nonRegularSparseMatrix = sparse(shape, randomMatrixCells(random, n));
            System.out.println(nonRegularSparseMatrix);

            // Vector matrix of random values
            IDoubleMatrix vector = vector(randomOneDimArray(random, n));
            System.out.println(vector);

            // Zero matrix
            IDoubleMatrix zeroMatrix = zero(shape);
            System.out.println(zeroMatrix);

            // Anti-diagonal matrix of random values
            IDoubleMatrix antiDiagonalMatrix = antiDiagonal(randomOneDimArray(random, n));
            System.out.println(antiDiagonalMatrix);
        }


    }
}
