package pl.edu.mimuw.matrices;

import pl.edu.mimuw.matrix.Shape;

public class AntiDiagonalMatrix extends MoreThanOneValue {

    public AntiDiagonalMatrix(Shape shape, double... antiDiagonalValues) {
        super(shape, antiDiagonalValues);
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
}