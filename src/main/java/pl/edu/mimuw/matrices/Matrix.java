package pl.edu.mimuw.matrices;

import pl.edu.mimuw.matrix.IDoubleMatrix;
import pl.edu.mimuw.matrix.Shape;

public abstract class Matrix implements IDoubleMatrix {
    protected final Shape shape;
    protected String name;

    protected Matrix(Shape shape, String name) {
        assert (shape.columns != 0);
        assert (shape.rows != 0);
        this.shape = shape;
        this.name = name;
    }

    @Override
    public IDoubleMatrix times(IDoubleMatrix other) {
        int rows1 = shape.rows;
        int columns1 = shape.columns;
        int rows2 = other.shape().rows;
        int columns2 = other.shape().columns;
        assert (columns1 == rows2);

        int sum;
        IDoubleMatrix result = new FullMatrix(new double[rows1][columns2]);
        for (int i = 0; i < rows1; i++) {
            for (int j = 0; j < columns2; j++) {
                sum = 0;
                for (int k = 0; k < columns1; k++) {
                    sum += this.data()[i][k] * other.data()[k][j];
                }
                result.data()[i][j] = sum;
            }
        }
        return result;
    }

    @Override
    public IDoubleMatrix times(double scalar) {
        IDoubleMatrix result = new FullMatrix(new double[shape.rows][shape.columns]);
        for (int i = 0; i < shape.rows; i++)
            for (int j = 0; j < shape.columns; j++) {
                result.data()[i][j] = scalar * this.data()[i][j];
            }
        return result;
    }

    @Override
    public IDoubleMatrix plus(IDoubleMatrix other) {
        assert (shape.equals(other.shape()));

        IDoubleMatrix result = new FullMatrix(new double[shape.rows][shape.columns]);
        for (int i = 0; i < shape.rows; i++)
            for (int j = 0; j < shape.columns; j++) {
                result.data()[i][j] = this.data()[i][j] + other.data()[i][j];
            }
        return result;
    }

    @Override
    public IDoubleMatrix plus(double scalar) {
        IDoubleMatrix result = new FullMatrix(new double[shape.rows][shape.columns]);
        for (int i = 0; i < shape.rows; i++)
            for (int j = 0; j < shape.columns; j++) {
                result.data()[i][j] = scalar + this.data()[i][j];
            }
        return result;
    }

    @Override
    public IDoubleMatrix minus(IDoubleMatrix other) {
        assert (shape.equals(other.shape()));

        IDoubleMatrix result = new FullMatrix(new double[shape.rows][shape.columns]);
        for (int i = 0; i < shape.rows; i++) {
            for (int j = 0; j < shape.columns; j++) {
                result.data()[i][j] = this.data()[i][j] - other.data()[i][j];
            }
        }
        return result;
    }

    @Override
    public IDoubleMatrix minus(double scalar) {
        return plus(-scalar);
    }

    @Override
    public double get(int row, int column) {
        shape.assertInShape(row, column);
        return data()[row][column];
    }

    // Maximum column sum.
    @Override
    public double normOne() {
        double sum, maxSum;
        maxSum = -Double.MAX_VALUE;
        for (int i = 0; i < shape.columns; i++) {
            sum = 0;
            for (int j = 0; j < shape.rows; j++) {
                sum += Math.abs(this.data()[j][i]);
            }
            maxSum = Math.max(maxSum, sum);
        }
        return maxSum;
    }

    // Maximum row sum.
    @Override
    public double normInfinity() {
        double sum, maxSum;
        maxSum = -Double.MAX_VALUE;
        for (int i = 0; i < shape.rows; i++) {
            sum = 0;
            for (int j = 0; j < shape.columns; j++) {
                sum += Math.abs(this.data()[i][j]);
            }
            maxSum = Math.max(maxSum, sum);
        }
        return maxSum;
    }

    @Override
    public double frobeniusNorm() {
        double result = 0;
        for (int i = 0; i < shape.rows; i++) {
            for (int j = 0; j < shape.columns; j++) {
                result += Math.pow(this.data()[i][j], 2);
            }
        }
        return Math.sqrt(result);
    }

    @Override
    public Shape shape() {
        return shape;
    }

    protected static String fmt(double d) {
        if (d == (int) d) return String.format("%6d", (int) d);
        else return String.format("%6.2f", d);
    }

    protected static String centerString(int width, String s) {
        return String.format("%-" + width + "s", String.format("%" + (s.length() + (width - s.length()) / 2) + "s", s));
    }


    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("Printing %s matrix of size %dx%d...\n", this.name, shape.rows, shape.columns));
        for (int i = 0; i < shape.rows; i++) {
            for (int j = 0; j < shape.columns; j++) {
                sb.append(fmt(data()[i][j]));
                sb.append(' ');
            }
            sb.append('\n');
        }
        return sb.toString();
    }
}
