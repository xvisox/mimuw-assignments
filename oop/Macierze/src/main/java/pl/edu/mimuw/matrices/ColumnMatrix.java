package pl.edu.mimuw.matrices;

import pl.edu.mimuw.matrix.IDoubleMatrix;
import pl.edu.mimuw.matrix.Shape;

import java.util.Arrays;

import static pl.edu.mimuw.utility.StringFormat.*;

public class ColumnMatrix extends MoreThanOneValue {

    public ColumnMatrix(Shape shape, double[] values) {
        super(shape, values, "Column");
        assert (shape.rows == values.length);
    }

    @Override
    public double[][] data() {
        double[][] result = new double[shape.rows][shape.columns];
        for (int i = 0; i < shape.rows; i++) {
            Arrays.fill(result[i], values[i]);
        }
        return result;
    }

    @Override
    public double get(int row, int column) {
        shape.assertInShape(row, column);
        return values[row];
    }

    @Override
    public IDoubleMatrix times(double scalar) {
        if (scalar == 0) return new ZeroMatrix(shape);
        return new ColumnMatrix(shape, getNewValues('*', scalar));
    }

    @Override
    public IDoubleMatrix plus(double scalar) {
        return new ColumnMatrix(shape, getNewValues('+', scalar));
    }

    @Override
    public IDoubleMatrix minus(double scalar) {
        return new ColumnMatrix(shape, getNewValues('-', scalar));
    }

    @Override
    public double normOne() {
        double result = 0;
        for (double val : values) {
            result += Math.abs(val);
        }
        return result;
    }

    @Override
    public double normInfinity() {
        double result = 0;
        for (double val : values) {
            result = Math.max(result, Math.abs(val));
        }
        return result * shape.rows;
    }

    @Override
    public double frobeniusNorm() {
        double result = 0;
        for (double val : values) {
            result += shape.columns * Math.pow(val, 2);
        }
        return Math.sqrt(result);
    }

    @Override
    public String toString() {
        if (shape.columns < 5 || shape.rows < 5) return super.toString();

        StringBuilder sb = new StringBuilder();
        sb.append(getMatrixPrint(this, name));

        for (int i = 0; i < shape.rows; i++) {
            sb.append(fmt(values[i]));
            sb.append("   ...   ");
            sb.append(fmt(values[i]));
            sb.append('\n');
        }

        return sb.toString();
    }
}
