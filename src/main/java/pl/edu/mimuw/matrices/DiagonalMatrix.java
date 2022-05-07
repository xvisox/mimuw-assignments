package pl.edu.mimuw.matrices;

import pl.edu.mimuw.matrix.Shape;

public class DiagonalMatrix extends MoreThanOneValue {

    public DiagonalMatrix(Shape shape, double[] values) {
        super(shape, values);
    }

    public DiagonalMatrix(Shape shape) {
        super(shape);
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
}
