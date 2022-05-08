package pl.edu.mimuw;

import pl.edu.mimuw.matrices.NonRegularMatrix;
import pl.edu.mimuw.matrix.IDoubleMatrix;
import pl.edu.mimuw.matrix.Shape;

import java.util.Random;

import static pl.edu.mimuw.RandomArrays.*;
import static pl.edu.mimuw.matrix.DoubleMatrixFactory.*;
import static pl.edu.mimuw.matrix.MatrixCellValue.cell;
import static pl.edu.mimuw.matrix.Shape.matrix;

public class Main {
    public static void main(String[] args) {
        int n = 10;
        Shape shape = Shape.matrix(n, n);
        Random random = new Random();

        boolean showMatrices = false;
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


        // Multiplication, adding and subtracting tests.
        IDoubleMatrix SPARSE_2X3 = sparse(matrix(2, 3),
                cell(0, 0, 1),
                cell(0, 1, 2),
                cell(0, 2, 3),
                cell(1, 0, 4),
                cell(1, 1, 5),
                cell(1, 2, 6)
        );
        IDoubleMatrix test = SPARSE_2X3.times(-2).plus(SPARSE_2X3);
        IDoubleMatrix test1 = SPARSE_2X3.times(-1);

        System.out.println(test);
        System.out.println(test1);

    }
}
