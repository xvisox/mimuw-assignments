package pl.edu.mimuw.matrices;

import pl.edu.mimuw.matrix.IDoubleMatrix;
import pl.edu.mimuw.matrix.Shape;

public class DiagonalMatrix extends MoreThanOneValue {

    public DiagonalMatrix(Shape shape, double[] values, String name) {
        super(shape, values, name);
    }

    public DiagonalMatrix(Shape shape, String name) {
        super(shape, name);
    }

    @Override
    public double[][] data() {
        int size = shape.rows;
        double[][] result = new double[size][size];
        for (int i = 0; i < size; i++) {
            result[i][i] = values[i];
        }
        return result;
    }

    @Override
    public IDoubleMatrix plus(IDoubleMatrix other) {
        assert (shape.equals(other.shape()));
        if (other instanceof DiagonalMatrix) {
            double[] newValues = new double[Math.min(shape.rows, shape.columns)];
            for (int i = 0; i < newValues.length; i++) {
                newValues[i] = ((DiagonalMatrix) other).values[i] + this.values[i];
            }
            return new DiagonalMatrix(shape, newValues, "Diagonal");
        } else {
            return super.plus(other);
        }
    }

    @Override
    public IDoubleMatrix minus(IDoubleMatrix other) {
        assert (shape.equals(other.shape()));
        if (other instanceof DiagonalMatrix) {
            double[] newValues = new double[Math.min(shape.rows, shape.columns)];
            for (int i = 0; i < newValues.length; i++) {
                newValues[i] = ((DiagonalMatrix) other).values[i] - this.values[i];
            }
            return new DiagonalMatrix(shape, newValues, "Diagonal");
        } else {
            return super.plus(other);
        }
    }

    @Override
    public String toString() {
        if (shape.columns < 5 || shape.rows < 5) return super.toString();

        StringBuilder sb = new StringBuilder();
        sb.append(String.format("Printing %s matrix of size %dx%d...\n", this.name, shape.rows, shape.columns));

        sb.append(String.format("%6.2f", values[0]));
        sb.append(centerString((shape.rows - 2) * 4, " "));
        sb.append("...0\n");

        for (int i = 1; i < shape.rows - 1; i++) {
            sb.append(centerString(i * 4, " "));
            sb.append(String.format("%6.2f\n", values[i]));
        }

        sb.append("0...");
        sb.append(centerString((shape.rows - 2) * 4, " "));
        sb.append(String.format("%6.2f\n", values[shape.rows - 1]));

        return sb.toString();
    }
}
