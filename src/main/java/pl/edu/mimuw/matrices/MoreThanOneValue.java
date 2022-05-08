package pl.edu.mimuw.matrices;

import pl.edu.mimuw.matrix.Shape;

public abstract class MoreThanOneValue extends RegularMatrix {
    protected double[] values;

    protected MoreThanOneValue(Shape shape, double[] values, String name) {
        super(shape, name);
        this.values = values;
    }

    public MoreThanOneValue(Shape shape, String name) {
        super(shape, name);
    }
}
