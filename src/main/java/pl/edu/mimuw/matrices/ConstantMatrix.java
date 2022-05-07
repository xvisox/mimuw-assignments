package pl.edu.mimuw.matrices;

import pl.edu.mimuw.matrix.Shape;

import java.util.Arrays;

public class ConstantMatrix extends RegularMatrix {
    private final double value;

    public ConstantMatrix(Shape shape, double value) {
        super(shape);
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
}
