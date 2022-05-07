package pl.edu.mimuw.matrix;

public final class ColumnValue {

    public final int column;
    public final double value;

    public ColumnValue(int column, double value) {
        this.column = column;
        this.value = value;
    }

    public static ColumnValue columnValue(int column, double value) {
        return new ColumnValue(column, value);
    }
}
