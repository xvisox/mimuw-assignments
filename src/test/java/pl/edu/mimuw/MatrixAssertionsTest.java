package pl.edu.mimuw;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ArgumentsSource;
import pl.edu.mimuw.matrix.IDoubleMatrix;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static pl.edu.mimuw.TestMatrixData.*;
import static pl.edu.mimuw.matrix.DoubleMatrixFactory.*;
import static pl.edu.mimuw.matrix.MatrixCellValue.cell;
import static pl.edu.mimuw.matrix.Shape.matrix;

public class MatrixAssertionsTest {

    @Test
    void testInvalidConstructThrowsOnDifferentSizes() {
        assertThrows(AssertionError.class, () -> full(new double[][]{
                new double[]{1, 2, 3},
                new double[]{1, 2, 3, 4},
        }));
    }

    @Test
    void testInvalidConstructThrowsOnOutboundIndices() {
        assertThrows(AssertionError.class, () -> sparse(matrix(3, 2),
                cell(3, 2, 1)
        ));
    }

    @Test
    void testInvalidConstructThrowsOnOutboundNegativeIndices() {
        assertThrows(AssertionError.class, () -> sparse(matrix(3, 2),
                cell(-3, -2, 1)
        ));
    }

    @Test
    void testFullInvalidConstructThrowsOnEmpty() {
        assertThrows(AssertionError.class, () -> full(new double[][]{}));
    }

    @Test
    void testFullInvalidConstructThrowsOnNull() {
        assertThrows(AssertionError.class, () -> full(null));
    }

    @Test
    void testInvalidConstructorsThrowsOnNull() {
        assertThrows(AssertionError.class, () -> sparse(null, null));
        assertThrows(AssertionError.class, () -> identity(-1));
        assertThrows(AssertionError.class, () -> diagonal(null));
        assertThrows(AssertionError.class, () -> antiDiagonal(null));
        assertThrows(AssertionError.class, () -> vector(null));
        assertThrows(AssertionError.class, () -> zero(null));
        assertThrows(AssertionError.class, () -> constant(null, 10));
        assertThrows(AssertionError.class, () -> rowMatrix(null, null));
        assertThrows(AssertionError.class, () -> columnMatrix(null, null));
    }

    @ParameterizedTest
    @ArgumentsSource(TestMatrixArgumentProvider.class)
    void testGetThrowsOnNegativeRow(IDoubleMatrix m) {
        assertThrows(AssertionError.class, () -> m.get(-1, 0));
    }

    @ParameterizedTest
    @ArgumentsSource(TestMatrixArgumentProvider.class)
    void testGetThrowsOnNegativeColumn(IDoubleMatrix m) {
        assertThrows(AssertionError.class, () -> m.get(0, -1));
    }

    @ParameterizedTest
    @ArgumentsSource(TestMatrixArgumentProvider.class)
    void testFullGetThrowsTooBigRow(IDoubleMatrix m) {
        assertThrows(AssertionError.class, () -> m.get(4242, 0));
    }

    @ParameterizedTest
    @ArgumentsSource(TestMatrixArgumentProvider.class)
    void testGetThrowsOnTooBigColumn(IDoubleMatrix m) {
        assertThrows(AssertionError.class, () -> m.get(0, 4242));
    }

    @Test
    void testFullAddThrowsOnNotMatchedSizes() {
        assertThrows(AssertionError.class, () -> FULL_3X2.plus(FULL_2X3));
    }

    @Test
    void testSparseAddThrowsOnNotMatchedSizes() {
        assertThrows(AssertionError.class, () -> SPARSE_3X2.plus(SPARSE_2X3));
    }

    @Test
    void testAdditionThrowsOnNotMatchedSizes() {
        assertThrows(AssertionError.class, () -> FULL_3X2.plus(FULL_2X3));
        assertThrows(AssertionError.class, () -> DIAGONAL_3X3.plus(DIAGONAL_4X4));
        assertThrows(AssertionError.class, () -> ANTI_DIAGONAL_3X3.plus(ANTI_DIAGONAL_4X4));
        assertThrows(AssertionError.class, () -> VECTOR_2.plus(VECTOR_3));
        assertThrows(AssertionError.class, () -> ID_2.plus(ID_3));
        assertThrows(AssertionError.class, () -> ZERO_3X2.plus(ZERO_2X2));
    }

    @Test
    void testFullTimesThrowsOnNotMatchedSizes() {
        assertThrows(AssertionError.class, () -> FULL_3X2.times(FULL_3X2));
    }

    @Test
    void testSparseTimesThrowsOnNotMatchedSizes() {
        assertThrows(AssertionError.class, () -> SPARSE_3X2.times(SPARSE_3X2));
    }

    @Test
    void testColumnMatrixWrongInput() {
        assertThrows(AssertionError.class, () -> columnMatrix(matrix(5, 6), 1, 2, 3, 4, 5, 6));
    }

    @Test
    void testRowMatrixWrongInput() {
        assertThrows(AssertionError.class, () -> rowMatrix(matrix(6, 5), 1, 2, 3, 4, 5, 6));
    }

    @Test
    void testAntiDiagonalGet() {
        final var l = antiDiagonal(0, 1, 2, 3, 4, 5, 6, 7, 8, 9);
        assertEquals(0, l.get(4, 8));
        assertEquals(8, l.get(1, 8));
    }
}
