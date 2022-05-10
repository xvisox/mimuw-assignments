package pl.edu.mimuw.matrices;

import pl.edu.mimuw.matrix.IDoubleMatrix;
import pl.edu.mimuw.matrix.Shape;

public class ZeroMatrix extends ConstantMatrix {

    public ZeroMatrix(Shape shape) {
        super(shape, 0, "Zero");
    }

    @Override
    public IDoubleMatrix times(IDoubleMatrix other) {
        assertMultiplication(other);
        return new ZeroMatrix(this.shape);
    }

    @Override
    public IDoubleMatrix times(double scalar) {
        return new ZeroMatrix(this.shape);
    }
}
