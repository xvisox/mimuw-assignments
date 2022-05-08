package pl.edu.mimuw.matrices;

import pl.edu.mimuw.matrix.Shape;

public class FullMatrix extends Matrix {
    private final double[][] values;

    public FullMatrix(double[][] values) {
        super(Shape.matrix(values.length, values[0].length), "Common");
        this.values = values;
    }

    @Override
    public double[][] data() {
        return values;
    }
}
