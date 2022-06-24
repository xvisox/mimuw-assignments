package pl.edu.mimuw;

import pl.edu.mimuw.matrix.IDoubleMatrix;
import pl.edu.mimuw.matrix.Shape;

import java.util.Random;

import static pl.edu.mimuw.utility.RandomArrays.*;
import static pl.edu.mimuw.matrix.DoubleMatrixFactory.*;

public class Main {
    public static void main(String[] args) {
        int n = 10;
        Shape shape = Shape.matrix(n, n);
        Random random = new Random();

        // Code was written in IDE IntelliJ Idea 2020.3
        System.out.println("-------- EXAMPLE MATRICES --------\n");

        // 1) Full matrix of random values
        IDoubleMatrix commonMatrix = full(randomTwoDimArray(random, n));
        System.out.println(commonMatrix);

        // 2) Diagonal matrix of random values
        IDoubleMatrix diagonalMatrix = diagonal(randomOneDimArray(random, n));
        System.out.println(diagonalMatrix);

        // 3) Column matrix of random values
        IDoubleMatrix columnMatrix = columnMatrix(shape, randomOneDimArray(random, n));
        System.out.println(columnMatrix);

        // 4) Row matrix of random values
        IDoubleMatrix rowMatrix = rowMatrix(shape, randomOneDimArray(random, n));
        System.out.println(rowMatrix);

        // 5) Constant matrix of random value
        IDoubleMatrix constantMatrix = constant(shape, random.nextDouble() * 50);
        System.out.println(constantMatrix);

        // 6) Identity matrix
        IDoubleMatrix identityMatrix = identity(n);
        System.out.println(identityMatrix);

        // 7) Non regular sparse matrix of random values
        IDoubleMatrix nonRegularSparseMatrix = sparse(shape, randomMatrixCells(random, n));
        System.out.println(nonRegularSparseMatrix);

        // 8) Vector matrix of random values
        IDoubleMatrix vector = vector(randomOneDimArray(random, n));
        System.out.println(vector);

        // 9) Zero matrix
        IDoubleMatrix zeroMatrix = zero(shape);
        System.out.println(zeroMatrix);

        // 10) Anti-diagonal matrix of random values
        IDoubleMatrix antiDiagonalMatrix = antiDiagonal(randomOneDimArray(random, n));
        System.out.println(antiDiagonalMatrix);

        System.out.println("\n-------- OPERATION EXAMPLES --------\n");
        // a) Multiplication example.
        System.out.println(commonMatrix.times(diagonalMatrix));
        // b) Addition example.
        System.out.println(commonMatrix.plus(diagonalMatrix));
        // c) Subtracting example.
        System.out.println(commonMatrix.minus(diagonalMatrix));
        // d) Scalar multiplication example.
        System.out.println(commonMatrix.times(10));
        // e) Scalar addition example.
        System.out.println(commonMatrix.plus(10));
        // f) Scalar subtracting example.
        System.out.println(commonMatrix.minus(10));
    }
}
