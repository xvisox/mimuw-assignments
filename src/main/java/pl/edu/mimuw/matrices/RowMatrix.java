package pl.edu.mimuw.matrices;

import pl.edu.mimuw.matrix.Shape;

import static pl.edu.mimuw.utility.StringFormat.*;

public class RowMatrix extends MoreThanOneValue {

    public RowMatrix(Shape shape, double[] values) {
        super(shape, values, "Row");
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

    @Override
    public String toString() {
        if (shape.columns < 5 || shape.rows < 5) return super.toString();

        StringBuilder sb = new StringBuilder();
        sb.append(getMatrixPrint(this, name));

        for (int i = 0; i < shape.columns; i++) {
            sb.append(fmt(values[i]));
        }
        sb.append('\n');

        for (int i = 0; i < 3; i++) {
            sb.append(String.valueOf(String.format("%6c", '.')).repeat(shape.columns));
            sb.append('\n');
        }

        for (int i = 0; i < shape.columns; i++) {
            sb.append(fmt(values[i]));
        }

        sb.append('\n');
        return sb.toString();
    }
}
