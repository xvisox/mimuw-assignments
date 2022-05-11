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

    @Override
    public double normOne() {
        double result = 0;
        for (double val : values) {
            result += Math.abs(val);
        }
        return result;
    }

    @Override
    public double normInfinity() {
        double max = -Double.MAX_VALUE;
        for (double val : values) {
            max = Math.max(Math.abs(val), max);
        }
        return max;
    }
}
