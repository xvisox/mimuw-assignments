package pl.edu.mimuw.matrices;

import pl.edu.mimuw.matrix.IDoubleMatrix;
import pl.edu.mimuw.matrix.MatrixCellValue;
import pl.edu.mimuw.matrix.Shape;

import java.util.ArrayList;
import java.util.List;

public class NonRegularMatrix extends SparseMatrix {
    private final ArrayList<MatrixCellValue> cellValues;

    public NonRegularMatrix(Shape shape, MatrixCellValue... values) {
        super(shape, "Non Regular Sparse");
        this.cellValues = new ArrayList<>();
        cellValues.addAll(List.of(values));
    }

    public NonRegularMatrix(Shape shape) {
        super(shape, "Non Regular Sparse");
        this.cellValues = new ArrayList<>();
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
        if (other instanceof NonRegularMatrix) {
            NonRegularMatrix result = new NonRegularMatrix(shape);
            result.cellValues.addAll(cellValues);

            int i = 0;
            for (MatrixCellValue cell : ((NonRegularMatrix) other).cellValues) {
                while (i < cellValues.size() && cellValues.get(i).row < cell.row && cellValues.get(i).column < cell.column) {
                    i++;
                }
                if (i < cellValues.size() && cell.column == cellValues.get(i).column && cell.row == cellValues.get(i).row) {
                    result.cellValues.set(i, new MatrixCellValue(cell.row, cell.column, cell.value + cellValues.get(i).value));
                }
                i++;
            }
            return result;
        }
        return super.plus(other);
    }

    @Override
    public IDoubleMatrix minus(double scalar) {
        int i = 0;
        MatrixCellValue[] values = new MatrixCellValue[this.cellValues.size()];
        for (MatrixCellValue cell : cellValues) {
            values[i++] = new MatrixCellValue(cell.row, cell.column, cell.value - scalar);
        }
        return new NonRegularMatrix(shape, values);
    }

    @Override
    public IDoubleMatrix plus(double scalar) {
        int i = 0;
        MatrixCellValue[] values = new MatrixCellValue[this.cellValues.size()];
        for (MatrixCellValue cell : cellValues) {
            values[i++] = new MatrixCellValue(cell.row, cell.column, cell.value + scalar);
        }
        return new NonRegularMatrix(shape, values);
    }

    @Override
    public IDoubleMatrix times(IDoubleMatrix other) {
        assert (shape.columns == other.shape().rows);
        if (other instanceof NonRegularMatrix) {
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
                            result.cellValues.add(new MatrixCellValue(cell.row, cellOther.column, cell.value * cellOther.value));
                    }
                }
            }
            return result;
        }
        return super.times(other);
    }

    @Override
    public IDoubleMatrix times(double scalar) {
        int i = 0;
        MatrixCellValue[] values = new MatrixCellValue[this.cellValues.size()];
        for (MatrixCellValue cell : cellValues) {
            values[i++] = new MatrixCellValue(cell.row, cell.column, cell.value * scalar);
        }
        return new NonRegularMatrix(shape, values);
    }

    @Override
    public double get(int row, int column) {
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
