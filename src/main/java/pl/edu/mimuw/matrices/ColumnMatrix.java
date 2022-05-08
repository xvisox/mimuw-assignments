package pl.edu.mimuw.matrices;

import pl.edu.mimuw.matrix.Shape;

import java.util.Arrays;

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
    public String toString() {
        if (shape.columns < 5 || shape.rows < 5) return super.toString();

        StringBuilder sb = new StringBuilder();
        sb.append(String.format("Printing %s matrix of size %dx%d...\n", this.name, shape.rows, shape.columns));

        for (int i = 0; i < shape.rows; i++) {
            sb.append(fmt(values[i]));
            sb.append("   ...   ");
            sb.append(fmt(values[i]));
            sb.append('\n');
        }

        return sb.toString();
    }
}
