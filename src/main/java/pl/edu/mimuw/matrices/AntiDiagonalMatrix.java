package pl.edu.mimuw.matrices;

import pl.edu.mimuw.matrix.Shape;

public class AntiDiagonalMatrix extends MoreThanOneValue {

    public AntiDiagonalMatrix(Shape shape, double... antiDiagonalValues) {
        super(shape, antiDiagonalValues, "Anti-diagonal");
    }

    @Override
    public double[][] data() {
        int size = shape.rows;
        double[][] result = new double[size][size];
        for (int i = 0; i < size; i++) {
            result[size - 1 - i][i] = values[i];
        }
        return result;
    }

    @Override
    public String toString() {
        if (shape.columns < 5 || shape.rows < 5) return super.toString();

        StringBuilder sb = new StringBuilder();
        sb.append(String.format("Printing %s matrix of size %dx%d...\n", this.name, shape.rows, shape.columns));

        sb.append("     0...");
        sb.append(centerString(shape.rows * 4 - 8, " "));
        sb.append(String.format("%6.2f\n", values[0]));

        for (int i = 1; i < shape.rows - 1; i++) {
            sb.append(centerString(shape.rows * 4 - (i) * 4, " "));
            sb.append(String.format("%6.2f\n", values[i]));
        }

        sb.append(String.format("%10.2f", values[shape.rows - 1]));
        sb.append(centerString(shape.rows * 4 - 8, " "));
        sb.append(" ...0");

        return sb.toString();
    }
}