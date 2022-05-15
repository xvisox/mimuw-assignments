package pl.edu.mimuw.matrices;

import pl.edu.mimuw.matrix.Shape;

public abstract class MoreThanOneValue extends RegularMatrix {
    protected double[] values;

    protected MoreThanOneValue(Shape shape, double[] values, String name) {
        this(shape, name);
        this.values = values;
    }

    public MoreThanOneValue(Shape shape, String name) {
        super(shape, name);
    }

    protected double[] getNewValues(char operation, double scalar) {
        double[] result = new double[values.length];
        switch (operation) {
            case '+':
                for (int i = 0; i < values.length; i++)
                    result[i] = values[i] + scalar;
                break;
            case '-':
                for (int i = 0; i < values.length; i++)
                    result[i] = values[i] - scalar;
                break;
            case '*':
                for (int i = 0; i < values.length; i++)
                    result[i] = values[i] * scalar;
                break;
        }
        return result;
    }

    @Override
    public double frobeniusNorm() {
        double result = 0;
        for (double val : values) {
            result += Math.pow(val, 2);
        }
        return Math.sqrt(result);
    }
}
