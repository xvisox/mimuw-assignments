package pl.edu.mimuw.matrix;

import pl.edu.mimuw.matrices.*;

public class DoubleMatrixFactory {

    private DoubleMatrixFactory() {
    }

    public static IDoubleMatrix sparse(Shape shape, MatrixCellValue... values) {
        return new NonRegularMatrix(shape, values);
    }

    public static IDoubleMatrix full(double[][] values) {
        return new FullMatrix(values);
    }

    public static IDoubleMatrix identity(int size) {
        return new IdentityMatrix(size);
    }

    public static IDoubleMatrix diagonal(double... diagonalValues) {
        int size = diagonalValues.length;
        return new DiagonalMatrix(Shape.matrix(size, size), diagonalValues);
    }

    public static IDoubleMatrix antiDiagonal(double... antiDiagonalValues) {
        int size = antiDiagonalValues.length;
        return new AntiDiagonalMatrix(Shape.matrix(size, size), antiDiagonalValues);
    }

    public static IDoubleMatrix vector(double... values) {
        return new Vector(values);
    }

    public static IDoubleMatrix zero(Shape shape) {
        return new ZeroMatrix(shape);
    }

    public static IDoubleMatrix constant(Shape shape, double value) {
        return new ConstantMatrix(shape, value);
    }

    public static IDoubleMatrix rowMatrix(Shape shape, double... values) {
        return new RowMatrix(shape, values);
    }

    public static IDoubleMatrix columnMatrix(Shape shape, double... values) {
        return new ColumnMatrix(shape, values);
    }

}
