package pl.edu.mimuw.matrices;

import pl.edu.mimuw.matrix.Shape;

public abstract class RegularMatrix extends SparseMatrix{
    protected RegularMatrix(Shape shape) {
        super(shape);
    }
}
