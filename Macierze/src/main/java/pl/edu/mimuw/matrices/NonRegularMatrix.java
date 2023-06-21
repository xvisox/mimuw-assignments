package pl.edu.mimuw.matrices;

import pl.edu.mimuw.matrix.IDoubleMatrix;
import pl.edu.mimuw.matrix.MatrixCellValue;
import pl.edu.mimuw.matrix.Shape;

import java.util.*;

import static pl.edu.mimuw.matrix.MatrixCellValue.*;

public class NonRegularMatrix extends SparseMatrix {
    private final ArrayList<MatrixCellValue> cells;

    public NonRegularMatrix(Shape shape, MatrixCellValue... values) {
        this(shape);
        for (MatrixCellValue cell : values) {
            shape.assertInShape(cell.row, cell.column);
            cells.add(cell);
        }
        Comparator<MatrixCellValue> cellComparator = Comparator
                .comparing(MatrixCellValue::getRow)
                .thenComparing(MatrixCellValue::getColumn);
        cells.sort(cellComparator);
    }

    public NonRegularMatrix(Shape shape) {
        super(shape, "Non Regular Sparse");
        this.cells = new ArrayList<>();
    }


    @Override
    public IDoubleMatrix plus(IDoubleMatrix other) {
        assertAddition(other);
        if (!(other instanceof NonRegularMatrix)) return super.plus(other);

        int i = 0;
        int j = 0;
        NonRegularMatrix result = new NonRegularMatrix(shape);
        NonRegularMatrix mtx = (NonRegularMatrix) other;
        while (i < cells.size() && j < mtx.cells.size()) {
            // First case - merging two cells from given sparse matrices into one.
            if (cells.get(i).row == mtx.cells.get(j).row && cells.get(i).column == mtx.cells.get(j).column) {
                result.cells.add(getMatrixCellOperation('+', cells.get(i++), mtx.cells.get(j++).value));
            } else {
                // Second case - adding one of two cells to result arraylist.
                if (compareCells(cells.get(i), mtx.cells.get(j))) {
                    result.cells.add(new MatrixCellValue(cells.get(i++)));
                } else {
                    result.cells.add(new MatrixCellValue(mtx.cells.get(j++)));
                }
            }
        }
        // Adding rest of the cells that left in the arrays.
        if (i == cells.size()) {
            while (j < mtx.cells.size()) {
                result.cells.add(new MatrixCellValue(mtx.cells.get(j++)));
            }
        }
        if (j == mtx.cells.size()) {
            while (i < cells.size()) {
                result.cells.add(new MatrixCellValue(cells.get(i++)));
            }
        }
        return result;
    }

    @Override
    public IDoubleMatrix minus(IDoubleMatrix other) {
        assertAddition(other);
        if (!(other instanceof NonRegularMatrix)) return super.minus(other);

        return this.plus(other.times(-1));
    }

    @Override
    public IDoubleMatrix times(IDoubleMatrix other) {
        assertMultiplication(other);
        if (!(other instanceof NonRegularMatrix)) return super.times(other);

        Shape newShape = Shape.matrix(shape.rows, other.shape().columns);
        ArrayList<MatrixCellValue> temp = new ArrayList<>();
        NonRegularMatrix result = new NonRegularMatrix(newShape);

        for (MatrixCellValue cell : cells) {
            for (MatrixCellValue cellOther : ((NonRegularMatrix) other).cells) {
                if (cell.column == cellOther.row) {
                    temp.add(getMatrixCellMultiply(cell, cellOther));
                }
            }
        }
        // Sorting cells by row and column.
        Comparator<MatrixCellValue> cellComparator = Comparator
                .comparing(MatrixCellValue::getRow)
                .thenComparing(MatrixCellValue::getColumn);
        temp.sort(cellComparator);
        // Merging cells with the same row and column.
        int i = 0;
        if (temp.size() > 0) {
            result.cells.add(temp.remove(0));
        }
        for (MatrixCellValue cell : temp) {
            if (areCellsEqual(cell, result.cells.get(i))) {
                result.cells.set(i, getMatrixCellOperation('+', cell, result.cells.get(i).value));
            } else {
                result.cells.add(cell);
                i++;
            }
        }
        return result;
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
    public IDoubleMatrix times(double scalar) {
        if (scalar == 0) return new ZeroMatrix(shape);
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
