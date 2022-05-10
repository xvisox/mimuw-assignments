package pl.edu.mimuw.matrices;

import pl.edu.mimuw.matrix.IDoubleMatrix;
import pl.edu.mimuw.matrix.MatrixCellValue;
import pl.edu.mimuw.matrix.Shape;

import java.util.ArrayList;

public class NonRegularMatrix extends SparseMatrix {
    private final ArrayList<MatrixCellValue> cellValues;

    public NonRegularMatrix(Shape shape, MatrixCellValue... values) {
        this(shape);
        for (MatrixCellValue cell : values) {
            shape.assertInShape(cell.row, cell.column);
            cellValues.add(cell);
        }
    }

    public NonRegularMatrix(Shape shape) {
        super(shape, "Non Regular Sparse");
        this.cellValues = new ArrayList<>();
    }

    private MatrixCellValue getMatrixCellMultiply(MatrixCellValue cell, MatrixCellValue other) {
        return new MatrixCellValue(cell.row, other.column, cell.value * other.value);
    }

    private MatrixCellValue getMatrixCellOperation(char operation, MatrixCellValue cell, double scalar) {
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

    @Override
    public IDoubleMatrix minus(IDoubleMatrix other) {
        assert (shape.equals(other.shape()));
        if (other instanceof NonRegularMatrix) {
            return this.plus(other.times(-1));
        }
        return super.minus(other);
    }

    @Override
    public IDoubleMatrix plus(IDoubleMatrix other) {
        assert (shape.equals(other.shape()));
        if (!(other instanceof NonRegularMatrix)) return super.plus(other);

        NonRegularMatrix result = new NonRegularMatrix(shape);
        result.cellValues.addAll(cellValues);
        int i = 0;
        for (MatrixCellValue cell : ((NonRegularMatrix) other).cellValues) {
            // Looking for cell in matrix with the same column and row as cell in other matrix.
            while (i < cellValues.size() && cellValues.get(i).row < cell.row && cellValues.get(i).column < cell.column)
                i++;
            // If we found a match, we set found cell to the new cell with incremented value.
            if (i < cellValues.size() && cell.column == cellValues.get(i).column && cell.row == cellValues.get(i).row) {
                result.cellValues.set(i, new MatrixCellValue(cell.row, cell.column, cell.value + cellValues.get(i).value));
            }
            i++;
        }
        return result;
    }

    @Override
    public IDoubleMatrix minus(double scalar) {
        int i = 0;
        MatrixCellValue[] values = new MatrixCellValue[this.cellValues.size()];
        for (MatrixCellValue cell : cellValues) {
            values[i++] = getMatrixCellOperation('-', cell, scalar);
        }
        return new NonRegularMatrix(shape, values);
    }

    @Override
    public IDoubleMatrix plus(double scalar) {
        int i = 0;
        MatrixCellValue[] values = new MatrixCellValue[this.cellValues.size()];
        for (MatrixCellValue cell : cellValues) {
            values[i++] = getMatrixCellOperation('+', cell, scalar);
        }
        return new NonRegularMatrix(shape, values);
    }

    @Override
    public IDoubleMatrix times(IDoubleMatrix other) {
        assert (shape.columns == other.shape().rows);
        if (!(other instanceof NonRegularMatrix)) {
            return super.times(other);
        }

        Shape newShape = Shape.matrix(shape.rows, other.shape().columns);
        NonRegularMatrix result = new NonRegularMatrix(newShape);
        boolean found;

        for (MatrixCellValue cell : cellValues) {
            for (MatrixCellValue cellOther : ((NonRegularMatrix) other).cellValues) {
                if (cell.column == cellOther.row) {
                    found = false;
                    for (MatrixCellValue resCell : result.cellValues) {
                        if (resCell.column == cellOther.column && resCell.row == cell.row) {
                            resCell.value += cell.value * cellOther.value;
                            found = true;
                            break;
                        } else if (resCell.column > cell.column || resCell.row > cell.row) {
                            break;
                        }
                    }
                    if (!found)
                        result.cellValues.add(getMatrixCellMultiply(cell, cellOther));
                }
            }
        }
        return result;
    }

    @Override
    public IDoubleMatrix times(double scalar) {
        int i = 0;
        MatrixCellValue[] values = new MatrixCellValue[this.cellValues.size()];
        for (MatrixCellValue cell : cellValues) {
            values[i++] = getMatrixCellOperation('*', cell, scalar);
        }
        return new NonRegularMatrix(shape, values);
    }

    @Override
    public double get(int row, int column) {
        shape.assertInShape(row, column);
        for (MatrixCellValue cell : cellValues) {
            if (row == cell.row && column == cell.column) {
                return cell.value;
            }
        }
        return 0;
    }

    @Override
    public double[][] data() {
        double[][] result = new double[shape.rows][shape.columns];
        for (MatrixCellValue cell : cellValues) {
            result[cell.row][cell.column] = cell.value;
        }
        return result;
    }
}
