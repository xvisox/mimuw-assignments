package pl.edu.mimuw.matrices;

import pl.edu.mimuw.matrix.Shape;

public class RowMatrix extends MoreThanOneValue {

    public RowMatrix(Shape shape, double[] values) {
        super(shape, values);
        assert (shape.columns == values.length);
    }

    @Override
    public double[][] data() {
        double[][] result = new double[shape.rows][shape.columns];
        for (int i = 0; i < shape.rows; i++) {
            System.arraycopy(values, 0, result[i], 0, shape.columns);
        }
        return result;
    }
}
