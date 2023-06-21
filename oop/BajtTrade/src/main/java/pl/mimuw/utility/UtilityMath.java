package pl.mimuw.utility;

public class UtilityMath {

    // Funkcja zwracająca maksimum 4 zmiennych typu double.
    public static double max(double a, double b, double c, double d) {
        return Math.max(Math.max(a, b), Math.max(c, d));
    }

    // Funkcja zwracająca maksimum 4 zmiennych typu int.
    public static int max(int a, int b, int c, int d) {
        return Math.max(Math.max(a, b), Math.max(c, d));
    }

    // Pomocnicza stała, żeby spekulanci nie wystawiali nic za darmo.
    public static final int MINIMALNA_CENA = 2;
}
