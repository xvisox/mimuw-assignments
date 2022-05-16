package pl.edu.mimuw.matrix;

public final class MatrixCellValue {

    public final int row;
    public final int column;
    public final double value;

    public MatrixCellValue(int row, int column, double value) {
        this.column = column;
        this.row = row;
        this.value = value;
    }

    public MatrixCellValue(MatrixCellValue cell) {
        this.column = cell.column;
        this.row = cell.row;
        this.value = cell.value;
    }

    @Override
    public String toString() {
        return "{" + value + " @[" + row + ", " + column + "]}";
    }

    public static MatrixCellValue cell(int row, int column, double value) {
        return new MatrixCellValue(row, column, value);
    }

    public int getRow() {
        return row;
    }

    public int getColumn() {
        return column;
    }

    public static MatrixCellValue getMatrixCellMultiply(MatrixCellValue cell, MatrixCellValue other) {
        return new MatrixCellValue(cell.row, other.column, cell.value * other.value);
    }

    public static MatrixCellValue getMatrixCellOperation(char operation, MatrixCellValue cell, double scalar) {
        MatrixCellValue result = null;
        switch (operation) {
            case '+':
                result = new MatrixCellValue(cell.row, cell.column, cell.value + scalar);
                break;
            case '-':
                result = new MatrixCellValue(cell.row, cell.column, cell.value - scalar);
                break;
            case '*':
                result = new MatrixCellValue(cell.row, cell.column, cell.value * scalar);
                break;
        }
        return result;
    }

    public static boolean areCellsEqual(MatrixCellValue c1, MatrixCellValue c2) {
        return c1.column == c2.column && c1.row == c2.row;
    }

    // If first is smaller than second returns true;
    public static boolean compareCells(MatrixCellValue c1, MatrixCellValue c2) {
        if (c1.row < c2.row) {
            return true;
        } else if (c1.row > c2.row) {
            return false;
        } else {
            return c1.column < c2.column;
        }
    }
}
