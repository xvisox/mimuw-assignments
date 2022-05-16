package pl.edu.mimuw;

import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import pl.edu.mimuw.matrix.IDoubleMatrix;

import java.util.stream.Stream;

import static org.junit.jupiter.params.provider.Arguments.of;
import static pl.edu.mimuw.TestMatrixDataNew.*;

public class TestMatrixArgumentProviderNew implements ArgumentsProvider {
    private static IDoubleMatrix give(int i) {
        switch (i) {
            case 0:
                return FULL;
            case 1:
                return SPARSE;
            case 2:
                return ANTIDIAGONAL;
            case 3:
                return DIAGONAL;
            case 4:
                return ROW;
            case 5:
                return COLUMN;
            case 6:
                return CONSTANT;
            case 7:
                return IDENTITY;
            default:
                return ZERO;
        }
    }

    public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
        Arguments[] args = new Arguments[81];

        for (int i = 0; i < 9; i++) {
            for (int j = 0; j < 9; j++) {
                args[9 * i + j] = of(give(i), give(j));
            }
        }

        return Stream.of(args);
    }
}
