package pl.edu.mimuw.matrices;

import pl.edu.mimuw.matrix.ColumnValue;
import pl.edu.mimuw.matrix.MatrixCellValue;
import pl.edu.mimuw.matrix.Shape;

import java.util.ArrayList;

import static pl.edu.mimuw.matrix.ColumnValue.columnValue;

public class NonRegularMatrix extends SparseMatrix {
    private final ArrayList<ArrayList<ColumnValue>> rowsList;

    public NonRegularMatrix(Shape shape, MatrixCellValue... values) {
        super(shape);
        this.rowsList = new ArrayList<>();

        for (int i = 0; i < shape.rows; i++) {
            rowsList.add(new ArrayList<>());
        }
        assert (rowsList.size() == shape.rows);

        for (MatrixCellValue cell : values) {
            shape.assertInShape(cell.row, cell.column);
            rowsList.get(cell.row).add(columnValue(cell.column, cell.value));
        }
    }

    @Override
    public double[][] data() {
        double[][] result = new double[shape.rows][shape.columns];

        for (int row = 0; row < shape.rows; row++) {
            for (ColumnValue columnValue : rowsList.get(row)) {
                result[row][columnValue.column] = columnValue.value;
            }
        }
        return result;
    }
}
