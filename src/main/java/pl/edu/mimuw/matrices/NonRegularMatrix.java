package pl.edu.mimuw.matrices;

import pl.edu.mimuw.matrix.IDoubleMatrix;
import pl.edu.mimuw.matrix.MatrixCellValue;
import pl.edu.mimuw.matrix.Shape;

import java.util.*;

public class NonRegularMatrix extends SparseMatrix {
    private final ArrayList<MatrixCellValue> cells;

    public NonRegularMatrix(Shape shape, MatrixCellValue... values) {
        this(shape);
        for (MatrixCellValue cell : values) {
            shape.assertInShape(cell.row, cell.column);
            cells.add(cell);
        }
        Comparator<MatrixCellValue> cellComparator = Comparator.comparing(MatrixCellValue::getRow).thenComparing(MatrixCellValue::getColumn);
        cells.sort(cellComparator);
    }

    public NonRegularMatrix(Shape shape) {
        super(shape, "Non Regular Sparse");
        this.cells = new ArrayList<>();
    }

    private MatrixCellValue getMatrixCellMultiply(MatrixCellValue cell, MatrixCellValue other, double additional) {
        return new MatrixCellValue(cell.row, other.column, cell.value * other.value + additional);
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

    // If first is smaller than second returns true;
    private boolean compareCells(MatrixCellValue c1, MatrixCellValue c2) {
        if (c1.row < c2.row) {
            return true;
        } else if (c1.row > c2.row) {
            return false;
        } else {
            return c1.column < c2.column;
        }
    }

    @Override
    public IDoubleMatrix plus(IDoubleMatrix other) {
        assertAddition(other);
        if (!(other instanceof NonRegularMatrix)) return super.plus(other);

        NonRegularMatrix result = new NonRegularMatrix(shape);
        int i = 0;
        int j = 0;
        NonRegularMatrix mtx = (NonRegularMatrix) other;
        while (i < cells.size() && j < mtx.cells.size()) {
            if (cells.get(i).row == mtx.cells.get(j).row && cells.get(i).column == mtx.cells.get(j).column) {
                result.cells.add(getMatrixCellOperation('+', cells.get(i), mtx.cells.get(j).value));
                i++;
                j++;
            } else {
                if (compareCells(cells.get(i), mtx.cells.get(j))) {
                    result.cells.add(new MatrixCellValue(cells.get(i)));
                    i++;
                } else {
                    result.cells.add(new MatrixCellValue(mtx.cells.get(j)));
                    j++;
                }
            }
        }
        if (i == cells.size()) {
            while (j < mtx.cells.size()) {
                result.cells.add(new MatrixCellValue(mtx.cells.get(j)));
                j++;
            }
        }
        if (j == mtx.cells.size()) {
            while (i < cells.size()) {
                result.cells.add(new MatrixCellValue(cells.get(i)));
                i++;
            }
        }
        return result;
    }

    @Override
    public IDoubleMatrix minus(IDoubleMatrix other) {
        assertAddition(other);
        if (other instanceof NonRegularMatrix) {
            return this.plus(other.times(-1));
        }
        return super.minus(other);
    }

    @Override
    public IDoubleMatrix minus(double scalar) {
        int i = 0;
        MatrixCellValue[] values = new MatrixCellValue[this.cells.size()];
        for (MatrixCellValue cell : cells) {
            values[i++] = getMatrixCellOperation('-', cell, scalar);
        }
        return new NonRegularMatrix(shape, values);
    }

    @Override
    public IDoubleMatrix plus(double scalar) {
        int i = 0;
        MatrixCellValue[] values = new MatrixCellValue[this.cells.size()];
        for (MatrixCellValue cell : cells) {
            values[i++] = getMatrixCellOperation('+', cell, scalar);
        }
        return new NonRegularMatrix(shape, values);
    }

    @Override
    public IDoubleMatrix times(IDoubleMatrix other) {
        assertMultiplication(other);
        if (!(other instanceof NonRegularMatrix)) {
            return super.times(other);
        }

        MatrixCellValue resCell;
        Shape newShape = Shape.matrix(shape.rows, other.shape().columns);
        NonRegularMatrix result = new NonRegularMatrix(newShape);
        boolean found;

        for (MatrixCellValue cell : cells) {
            for (MatrixCellValue cellOther : ((NonRegularMatrix) other).cells) {
                if (cell.column == cellOther.row) {
                    found = false;
                    for (int i = 0; i < result.cells.size(); i++) {
                        resCell = result.cells.get(i);
                        if (resCell.column == cellOther.column && resCell.row == cell.row) {
                            result.cells.set(i, getMatrixCellMultiply(cell, cellOther, resCell.value));
                            found = true;
                            break;
                        } else if (resCell.column > cell.column && resCell.row > cell.row) {
                            break;
                        }
                    }
                    if (!found) result.cells.add(getMatrixCellMultiply(cell, cellOther, 0));
                }
            }
        }
        return result;
    }

    @Override
    public IDoubleMatrix times(double scalar) {
        int i = 0;
        MatrixCellValue[] values = new MatrixCellValue[this.cells.size()];
        for (MatrixCellValue cell : cells) {
            values[i++] = getMatrixCellOperation('*', cell, scalar);
        }
        return new NonRegularMatrix(shape, values);
    }

    @Override
    public double get(int row, int column) {
        shape.assertInShape(row, column);
        for (MatrixCellValue cell : cells) {
            if (row == cell.row && column == cell.column) {
                return cell.value;
            }
        }
        return 0;
    }

    @Override
    public double[][] data() {
        double[][] result = new double[shape.rows][shape.columns];
        for (MatrixCellValue cell : cells) {
            result[cell.row][cell.column] = cell.value;
        }
        return result;
    }

    @Override
    public double normOne() {
        double result = 0;
        Map<Integer, Double> columnSums = new HashMap<>();
        for (MatrixCellValue cell : cells) {
            columnSums.merge(cell.column, Math.abs(cell.value), Double::sum);
            result = Math.max(columnSums.get(cell.column), result);
        }
        return result;
    }

    @Override
    public double normInfinity() {
        double result = 0;
        Map<Integer, Double> rowSums = new HashMap<>();
        for (MatrixCellValue cell : cells) {
            rowSums.merge(cell.row, Math.abs(cell.value), Double::sum);
            result = Math.max(rowSums.get(cell.row), result);
        }
        return result;
    }

    @Override
    public double frobeniusNorm() {
        double result = 0;
        for (MatrixCellValue cell : cells) {
            result += Math.pow(cell.value, 2);
        }
        return Math.sqrt(result);
    }
}
