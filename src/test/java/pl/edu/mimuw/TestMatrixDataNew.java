package pl.edu.mimuw;

import pl.edu.mimuw.matrix.IDoubleMatrix;
import pl.edu.mimuw.matrix.MatrixCellValue;
import pl.edu.mimuw.matrix.Shape;

import static pl.edu.mimuw.matrix.DoubleMatrixFactory.*;

public class TestMatrixDataNew {
    // Additional data matrices
    private static final Shape shape = Shape.matrix(3, 3);

    public static final double TEST_PRECISION = 0.000001d;

    public static final IDoubleMatrix FULL = full(new double[][]{
            new double[]{2, 5, -3},
            new double[]{0, -7, 4},
            new double[]{3, 9, -1}
    });

    public static final IDoubleMatrix SPARSE = sparse(
            shape, new MatrixCellValue(0, 2, 6),
            new MatrixCellValue(1, 0, -2),
            new MatrixCellValue(2, 2, 1)
    );

    public static final IDoubleMatrix ANTIDIAGONAL = antiDiagonal(4, -1, 3);

    public static final IDoubleMatrix COLUMN = columnMatrix(shape, -7, 1, 1);

    public static final IDoubleMatrix CONSTANT = constant(shape, 3);

    public static final IDoubleMatrix DIAGONAL = diagonal(9, -2, 0);

    public static final IDoubleMatrix IDENTITY = identity(3);

    public static final IDoubleMatrix ROW = rowMatrix(shape, -1, -1, 2);

    public static final IDoubleMatrix ZERO = zero(shape);
}
