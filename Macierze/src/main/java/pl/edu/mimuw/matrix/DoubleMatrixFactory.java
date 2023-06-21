package pl.edu.mimuw.matrix;

import pl.edu.mimuw.matrices.*;

public class DoubleMatrixFactory {

    private DoubleMatrixFactory() {
    }

    public static IDoubleMatrix sparse(Shape shape, MatrixCellValue... values) {
        assert (shape != null && values != null);
        return new NonRegularMatrix(shape, values);
    }

    public static IDoubleMatrix full(double[][] values) {
        assert (values != null);
        assert (values.length > 0);
        assert (values[0].length > 0);
        int compareLength = values[0].length;
        for (double[] value : values) {
            assert (compareLength == value.length);
        }
        return new FullMatrix(values);
    }

    public static IDoubleMatrix identity(int size) {
        assert (size > 0);
        return new IdentityMatrix(size);
    }

    public static IDoubleMatrix diagonal(double... diagonalValues) {
        assert (diagonalValues != null);
        int size = diagonalValues.length;
        return new DiagonalMatrix(Shape.matrix(size, size), diagonalValues, "Diagonal");
    }

    public static IDoubleMatrix antiDiagonal(double... antiDiagonalValues) {
        assert (antiDiagonalValues != null);
        int size = antiDiagonalValues.length;
        return new AntiDiagonalMatrix(Shape.matrix(size, size), antiDiagonalValues);
    }

    public static IDoubleMatrix vector(double... values) {
        assert (values != null);
        return new Vector(values);
    }

    public static IDoubleMatrix zero(Shape shape) {
        assert (shape != null);
        return new ZeroMatrix(shape);
    }

    public static IDoubleMatrix constant(Shape shape, double value) {
        assert (shape != null);
        return new ConstantMatrix(shape, value, "Constant");
    }

    public static IDoubleMatrix rowMatrix(Shape shape, double... values) {
        assert (shape != null && values != null);
        return new RowMatrix(shape, values);
    }

    public static IDoubleMatrix columnMatrix(Shape shape, double... values) {
        assert (shape != null && values != null);
        return new ColumnMatrix(shape, values);
    }

}
