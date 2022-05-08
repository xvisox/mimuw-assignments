package pl.edu.mimuw.matrices;

import pl.edu.mimuw.matrix.Shape;

public class IdentityMatrix extends DiagonalMatrix {

    public IdentityMatrix(int size) {
        super(Shape.matrix(size, size), "Identity");
        this.values = new double[size];
        for (int i = 0; i < size; i++) {
            values[i] = 1;
        }
    }

}
