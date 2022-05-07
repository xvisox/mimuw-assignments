package pl.edu.mimuw.matrices;

import pl.edu.mimuw.matrix.Shape;

import java.util.Arrays;

public class ColumnMatrix extends MoreThanOneValue {

    public ColumnMatrix(Shape shape, double[] values) {
        super(shape, values);
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
}
