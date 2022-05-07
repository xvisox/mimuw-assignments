package pl.edu.mimuw.matrix;

public class DoubleMatrixFactory {

  private DoubleMatrixFactory() {
  }

  public static IDoubleMatrix sparse(Shape shape, MatrixCellValue... values){
    return null; // Tu trzeba wpisać właściwą instrukcję
  }

  public static IDoubleMatrix full(double[][] values) {
    return null; // Tu trzeba wpisać właściwą instrukcję
  }

  public static IDoubleMatrix identity(int size) {
    return null; // Tu trzeba wpisać właściwą instrukcję
  }

  public static IDoubleMatrix diagonal(double... diagonalValues) {
    return null; // Tu trzeba wpisać właściwą instrukcję
  }

  public static IDoubleMatrix antiDiagonal(double... antiDiagonalValues) {
    return null; // Tu trzeba wpisać właściwą instrukcję
  }

  public static IDoubleMatrix vector(double... values){
    return null; // Tu trzeba wpisać właściwą instrukcję
  }

  public static IDoubleMatrix zero(Shape shape) {
    return null; // Tu trzeba wpisać właściwą instrukcję
  }
}
