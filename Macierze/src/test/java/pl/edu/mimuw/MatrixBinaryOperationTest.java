package pl.edu.mimuw;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ArgumentsSource;
import pl.edu.mimuw.matrix.DoubleMatrixFactory;
import pl.edu.mimuw.matrix.IDoubleMatrix;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static pl.edu.mimuw.matrix.DoubleMatrixFactory.constant;
import static pl.edu.mimuw.matrix.DoubleMatrixFactory.zero;
import static pl.edu.mimuw.matrix.MatrixCellValue.cell;
import static pl.edu.mimuw.matrix.Shape.matrix;

public class MatrixBinaryOperationTest {

    @ParameterizedTest
    @ArgumentsSource(TestMatrixSameArgumentProvider.class)
    void testPlusMatrices(IDoubleMatrix l, IDoubleMatrix r) {
        final var result = l.plus(r).data();

        final var expectedResult = new double[][]{
                new double[]{2, 4, 6},
                new double[]{8, 10, 12},
        };

        assertArrayEquals(expectedResult, result);
    }

    @ParameterizedTest
    @ArgumentsSource(TestMatrixSameArgumentProvider.class)
    void testMinusMatrices(IDoubleMatrix l, IDoubleMatrix r) {
        final var result = l.minus(r).data();

        final var expectedResult = new double[][]{
                new double[]{0, 0, 0},
                new double[]{0, 0, 0},
        };

        assertArrayEquals(expectedResult, result);
    }

    @ParameterizedTest
    @ArgumentsSource(TestMatrixTransposedShapeArgumentProvider.class)
    void testTimesMatrices(IDoubleMatrix l, IDoubleMatrix r) {
        final var result = l.times(r).data();

        final var expectedResult = new double[][]{
                new double[]{22, 28},
                new double[]{49, 64},
        };

        assertArrayEquals(expectedResult, result);
    }

    @ParameterizedTest
    @ArgumentsSource(TestMatrixArgumentProvider.class)
    void testTimesScalar(IDoubleMatrix m) {
        final var result = m.times(2).minus(m).data();
        final var expectedResult = m.data();

        assertArrayEquals(expectedResult, result);
    }

    @ParameterizedTest
    @ArgumentsSource(TestMatrixArgumentProvider.class)
    void testTimesMinusScalar(IDoubleMatrix m) {
        final var result = m.times(-2).plus(m).data();
        final var expectedResult = m.times(-1).data();

        assertArrayEquals(expectedResult, result);
    }

    @ParameterizedTest
    @ArgumentsSource(TestMatrixArgumentProvider.class)
    void testPlusMinusScalar(IDoubleMatrix m) {
        final var result = m.plus(42).minus(42).data();
        final var expectedResult = m.data();

        assertArrayEquals(expectedResult, result);
    }

    @ParameterizedTest
    @ArgumentsSource(TestMatrixArgumentProvider.class)
    void testMinusPlusScalar(IDoubleMatrix m) {
        final var result = m.plus(42).minus(42).data();
        final var expectedResult = m.data();

        assertArrayEquals(expectedResult, result);
    }

    @Test
    void testPlusSparseMatrices() {
        final var l = DoubleMatrixFactory.sparse(
                matrix(1_000_000, 1_000_000_000),
                cell(0, 0, 42),
                cell(767, 123_123, 24),
                cell(999_999, 999_999_999, 66)
        );
        final var r = DoubleMatrixFactory.sparse(
                matrix(1_000_000, 1_000_000_000),
                cell(0, 0, 24),
                cell(767, 123_123, 42)
        );
        final var result = l.plus(r);

        assertEquals(66, result.get(0, 0));
        assertEquals(66, result.get(767, 123_123));
        assertEquals(66, result.get(999_999, 999_999_999));
    }

    @Test
    void testMinusSparseMatrices() {
        final var l = DoubleMatrixFactory.sparse(
                matrix(1_000_000, 1_000_000_000),
                cell(0, 0, 42),
                cell(767, 123_123, 24),
                cell(999_999, 999_999_999, 66)
        );
        final var r = DoubleMatrixFactory.sparse(
                matrix(1_000_000, 1_000_000_000),
                cell(0, 0, 24),
                cell(767, 123_123, 42)
        );
        final var result = l.minus(r);

        assertEquals(18, result.get(0, 0));
        assertEquals(-18, result.get(767, 123_123));
        assertEquals(66, result.get(999_999, 999_999_999));
    }

    @Test
    void testTimesSparseMatrices() {
        final var l = DoubleMatrixFactory.sparse(
                matrix(1_000_000, 1_000_000_000),
                cell(0, 0, 3),
                cell(0, 213, 2),
                cell(0, 555_555, 66),

                cell(456_456, 1, 7),
                cell(456_456, 321, 8),
                cell(456_456, 444_444, 66)

        );
        final var r = DoubleMatrixFactory.sparse(
                matrix(1_000_000_000, 1_000_000),
                cell(0, 0, 4),
                cell(213, 0, 5),
                cell(666_666, 0, 66),

                cell(1, 456_456, 9),
                cell(321, 456_456, 10),
                cell(444_445, 456_456, 66)
        );
        final var result = l.times(r);

        assertEquals(22, result.get(0, 0));
        assertEquals(143, result.get(456_456, 456_456));
        assertEquals(0, result.get(42, 42));
    }

    @ParameterizedTest
    @ArgumentsSource(TestMatrixSameArgumentProvider.class)
    void testZeroMatrixTimes(IDoubleMatrix l, IDoubleMatrix r) {
        final var z = zero(matrix(3, 2));
        final var result = l.times(z).times(r).data();
        final var expectedResult = new double[][]{
                new double[]{0, 0, 0},
                new double[]{0, 0, 0},
        };
        assertArrayEquals(expectedResult, result);
    }

    @ParameterizedTest
    @ArgumentsSource(TestMatrixArgumentProvider.class)
    void testZeroMatrixTimes(IDoubleMatrix m) {
        final var shape = m.shape();
        final var z = zero(matrix(shape.rows, shape.columns));
        final var expectedResult = m.data();
        assertArrayEquals(expectedResult, z.plus(m).data());
        assertArrayEquals(expectedResult, m.plus(z).data());
    }

    @Test
    void testSparseMatricesAdditional() {
        final var l = DoubleMatrixFactory.sparse(
                matrix(7, 7),
                cell(0, 0, 1),
                cell(0, 2, 2),
                cell(0, 4, 3),
                cell(0, 6, 5),

                cell(2, 5, 4),

                cell(3, 1, 2),
                cell(3, 3, 3),

                cell(5, 0, 8),

                cell(6, 0, 9),
                cell(6, 2, 7),
                cell(6, 5, 6)

        );
        final var r = DoubleMatrixFactory.sparse(
                matrix(7, 7),
                cell(0, 0, 123),
                cell(0, 1, 1),
                cell(0, 5, 123),

                cell(1, 3, 1),

                cell(2, 0, 14),
                cell(2, 6, 1),

                cell(3, 0, 14),
                cell(3, 1, 1),

                cell(4, 0, 14),

                cell(5, 2, 7),
                cell(5, 4, 9),
                cell(5, 5, 123),
                cell(5, 6, 1),

                cell(6, 1, 1),
                cell(6, 3, 1),
                cell(6, 4, 2),
                cell(6, 5, 123)
        );
        final var result = l.times(r);
        final var resultAdd = l.plus(r);
        final var resultSubtract = l.minus(r);

        // Multiplication tests.
        assertEquals(193, result.get(0, 0));
        assertEquals(6, result.get(0, 1));
        assertEquals(0, result.get(0, 2));
        assertEquals(5, result.get(0, 3));
        assertEquals(10, result.get(0, 4));
        assertEquals(738, result.get(0, 5));
        assertEquals(2, result.get(0, 6));

        for (int i = 0; i < 7; i++) {
            assertEquals(0, result.get(1, i));
        }

        assertEquals(28, result.get(2, 2));
        assertEquals(36, result.get(2, 4));
        assertEquals(492, result.get(2, 5));
        assertEquals(4, result.get(2, 6));

        assertEquals(42, result.get(3, 0));
        assertEquals(3, result.get(3, 1));
        assertEquals(2, result.get(3, 3));

        for (int i = 0; i < 7; i++) {
            assertEquals(0, result.get(4, i));
        }

        assertEquals(984, result.get(5, 0));
        assertEquals(8, result.get(5, 1));
        assertEquals(984, result.get(5, 5));

        assertEquals(1205, result.get(6, 0));
        assertEquals(9, result.get(6, 1));
        assertEquals(42, result.get(6, 2));
        assertEquals(0, result.get(6, 3));
        assertEquals(54, result.get(6, 4));
        assertEquals(1845, result.get(6, 5));
        assertEquals(13, result.get(6, 6));

        // Adding and subtracting tests.
        assertEquals(129, resultAdd.get(6, 5));
        assertEquals(3, resultAdd.get(3, 1));
        assertEquals(124, resultAdd.get(0, 0));

        assertEquals(-117, resultSubtract.get(6, 5));
        assertEquals(1, resultSubtract.get(3, 1));
        assertEquals(-122, resultSubtract.get(0, 0));
    }

    @Test
    void testSparseMatricesWithoutFirstRow() {
        final var l = DoubleMatrixFactory.sparse(
                matrix(7, 7),
                cell(2, 5, 4),
                cell(3, 1, 2),
                cell(3, 3, 3),
                cell(5, 0, 8),
                cell(6, 0, 9),
                cell(6, 2, 7),
                cell(6, 5, 6)

        );
        final var r = DoubleMatrixFactory.sparse(
                matrix(7, 7),
                cell(1, 3, 1),
                cell(2, 0, 14),
                cell(2, 6, 1),
                cell(3, 0, 14),
                cell(3, 1, 1),
                cell(4, 0, 14),
                cell(5, 2, 7),
                cell(5, 4, 9),
                cell(5, 5, 123),
                cell(5, 6, 1),
                cell(6, 1, 1),
                cell(6, 3, 1),
                cell(6, 4, 2),
                cell(6, 5, 123)
        );
        final var result = l.times(r);
        final var resultAdd = l.plus(r);
        final var resultSubtract = l.minus(r);

        // Multiplication tests.
        assertEquals(0, result.get(0, 0));
        assertEquals(28, result.get(2, 2));
        assertEquals(4, result.get(2, 6));
        assertEquals(2, result.get(3, 3));

        // Adding and subtracting tests.
        assertEquals(1, resultAdd.get(1, 3));
        assertEquals(0, resultAdd.get(0, 3));
        assertEquals(3, resultAdd.get(3, 1));

        assertEquals(-1, resultSubtract.get(1, 3));
        assertEquals(0, resultSubtract.get(0, 3));
        assertEquals(1, resultSubtract.get(3, 1));
    }

    @Test
    void testConstantMatricesAddition() {
        final var l = constant(matrix(1000000, 1000000), 10);
        final var r = constant(matrix(1000000, 1000000), 25);
        final var resultAdd = l.plus(r);
        final var resultSubtract = l.minus(r);
        final var resultScalarAdd = l.plus(40);
        final var resultScalarSubtract = l.minus(40);

        assertEquals(35, resultAdd.get(999999, 999999));
        assertEquals(-15, resultSubtract.get(999999, 999999));
        assertEquals(50, resultScalarAdd.get(999999, 999999));
        assertEquals(-30, resultScalarSubtract.get(999999, 999999));
    }
}
