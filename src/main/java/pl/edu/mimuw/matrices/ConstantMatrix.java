package pl.edu.mimuw.matrices;

import pl.edu.mimuw.matrix.Shape;

import java.util.Arrays;

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
    public String toString() {
        if (shape.columns < 5 || shape.rows < 5) return super.toString();

        StringBuilder sb = new StringBuilder();
        sb.append(String.format("Printing %s matrix of size %dx%d...\n", this.name, shape.rows, shape.columns));

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
