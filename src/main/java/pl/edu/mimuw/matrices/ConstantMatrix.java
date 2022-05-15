package pl.edu.mimuw.matrices;

import pl.edu.mimuw.matrix.IDoubleMatrix;
import pl.edu.mimuw.matrix.Shape;

import java.util.Arrays;

import static pl.edu.mimuw.utility.StringFormat.centerString;
import static pl.edu.mimuw.utility.StringFormat.getMatrixPrint;

public class ConstantMatrix extends RegularMatrix {
    private final double value;

    public ConstantMatrix(Shape shape, double value, String name) {
        super(shape, name);
        this.value = value;
    }

    @Override
    public double[][] data() {
        double[][] result = new double[shape.rows][shape.columns];
        for (int i = 0; i < shape.rows; i++) {
            Arrays.fill(result[i], value);
        }
        return result;
    }

    @Override
    public IDoubleMatrix times(double scalar) {
        return new ConstantMatrix(shape, value * scalar, "Constant");
    }

    @Override
    public IDoubleMatrix plus(double scalar) {
        return new ConstantMatrix(shape, value + scalar, "Constant");
    }

    @Override
    public IDoubleMatrix minus(double scalar) {
        return new ConstantMatrix(shape, value - scalar, "Constant");
    }

    @Override
    public IDoubleMatrix plus(IDoubleMatrix other) {
        assertAddition(other);
        if (other instanceof ConstantMatrix) {
            return new ConstantMatrix(shape, value + ((ConstantMatrix) other).value, "Constant");
        } else {
            return super.plus(other);
        }
    }

    @Override
    public IDoubleMatrix minus(IDoubleMatrix other) {
        assertAddition(other);
        return plus(other.times(-1));
    }

    @Override
    public double get(int row, int column) {
        shape.assertInShape(row, column);
        return value;
    }

    @Override
    public double normOne() {
        return shape.rows * value;
    }

    @Override
    public double normInfinity() {
        return shape.columns * value;
    }

    @Override
    public double frobeniusNorm() {
        return Math.sqrt(shape.rows * shape.columns * Math.pow(value, 2));
    }

    @Override
    public String toString() {
        if (shape.columns < 5 || shape.rows < 5) return super.toString();

        StringBuilder sb = new StringBuilder();
        sb.append(getMatrixPrint(this, name));

        sb.append(String.format("%.2f", value));
        sb.append(centerString(11, "..."));
        sb.append(String.format("%.2f", value));
        sb.append('\n');


        for (int i = 0; i < 3; i++) {
            sb.append('.');
            sb.append(centerString(14, "  "));
            sb.append(".\n");
        }

        sb.append(String.format("%.2f", value));
        sb.append(centerString(11, "..."));
        sb.append(String.format("%.2f", value));
        sb.append('\n');

        return sb.toString();
    }
}
