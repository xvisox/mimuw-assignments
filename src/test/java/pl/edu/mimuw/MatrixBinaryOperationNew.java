package pl.edu.mimuw;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ArgumentsSource;
import pl.edu.mimuw.matrix.IDoubleMatrix;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static pl.edu.mimuw.TestMatrixDataNew.TEST_PRECISION;

public class MatrixBinaryOperationNew {

    static void assertArrayEqualsPrecision(double[][] a, double[][] b, double precision) {
        for (int i = 0; i < 3; i++) {
            for (int j = 0; j < 3; j++) {
                assertEquals(a[i][j], b[i][j], precision, "Różnica na indeksach [" + i + "][" + j + "]. Oczekiwano " + a[i][j] + " a otrzymano " + b[i][j]);
            }
        }
    }

    @ParameterizedTest
    @ArgumentsSource(TestMatrixArgumentProviderNew.class)
    void TestMultiplication(IDoubleMatrix l, IDoubleMatrix r) {
        double[][] standard = l.standardMultiply(r).data();
        double[][] optimised = l.times(r).data();

        assertArrayEqualsPrecision(standard, optimised, TEST_PRECISION);
    }
}
