package pl.edu.mimuw.matrices;

import pl.edu.mimuw.matrix.Shape;

public class ZeroMatrix extends ConstantMatrix {

    public ZeroMatrix(Shape shape) {
        super(shape, 0);
    }
}
