package pl.edu.mimuw.utility;

import pl.edu.mimuw.matrix.IDoubleMatrix;

public class StringFormat {
    // Utility method to format the values in matrices.
    public static String fmt(double d) {
        if (d == (int) d) return String.format("%6d", (int) d);
        else return String.format("%6.2f", d);
    }

    // Utility method to center the string in given width.
    public static String centerString(int width, String s) {
        return String.format("%-" + width + "s", String.format("%" + (s.length() + (width - s.length()) / 2) + "s", s));
    }

    // Utility method to get the string with information which matrix is going to be printed.
    public static String getMatrixPrint(IDoubleMatrix matrix, String name) {
        return String.format("Printing %s matrix of size %dx%d...\n", name, matrix.shape().rows, matrix.shape().columns);
    }

}
