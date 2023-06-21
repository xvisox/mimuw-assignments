package pl.edu.mimuw.matrices;

import pl.edu.mimuw.matrix.Shape;

public abstract class SparseMatrix extends Matrix {

    protected SparseMatrix(Shape shape, String name) {
        super(shape, name);
    }
}
