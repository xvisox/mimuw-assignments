package pl.edu.mimuw.matrices;

import pl.edu.mimuw.matrix.Shape;

public class Vector extends MoreThanOneValue {

    public Vector(double... values) {
        super(Shape.vector(values.length), "Vector");
        this.values = values;
    }

    @Override
    public double[][] data() {
        double[][] result = new double[shape.rows][1];
        for (int i = 0; i < shape.rows; i++) {
            result[i][0] = values[i];
        }
        return result;
    }
}
