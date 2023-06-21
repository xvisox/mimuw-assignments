package com.company.rational;

public class Rational {
    private int numerator;
    private int denominator;

    public Rational(int numerator, int denominator) throws DivisionByZero {
        this.denominator = denominator;
        this.numerator = numerator;
        if (this.denominator == 0) {
            throw new DivisionByZero("Division by zero!");
        }
    }

    public Rational(int numerator) {
        this.numerator = numerator;
        this.denominator = 1;
    }

    public int getSign() {
        if (this.numerator == 0) {
            return 0;
        } else {
            return this.numerator > 0 ? 1 : -1;
        }
    }

    public int getNumerator() {
        return numerator;
    }

    public int getDenominator() {
        return denominator;
    }

    public static Rational zero() throws DivisionByZero {
        return new Rational(0, 1);
    }

    public static Rational one() throws DivisionByZero {
        return new Rational(1, 1);
    }

    private static int NWD(int a, int b) {
        a = Math.abs(a);
        b = Math.abs(b);
        int c;
        while (b != 0) {
            c = a % b;
            a = b;
            b = c;
        }
        return a;
    }

    private static void reduceRational(Rational x) {
        int nwd = NWD(x.numerator, x.denominator);
        x.numerator /= nwd;
        x.denominator /= nwd;
    }

    public Rational add(Rational x) throws DivisionByZero {
        int denominatorResult = this.denominator * x.denominator;
        int numeratorResult = x.numerator * this.denominator + this.numerator * x.denominator;
        Rational rational = new Rational(numeratorResult, denominatorResult);
        reduceRational(rational);
        return rational;
    }

    public Rational subtract(Rational x) throws DivisionByZero {
        int denominatorResult = this.denominator * x.denominator;
        int numeratorResult = this.numerator * x.denominator - x.numerator * this.denominator;
        Rational rational = new Rational(numeratorResult, denominatorResult);
        reduceRational(rational);
        return rational;
    }

    public Rational multiply(Rational x) throws DivisionByZero {
        int denominatorResult = this.denominator * x.denominator;
        int numeratorResult = this.numerator * x.numerator;
        Rational rational = new Rational(numeratorResult, denominatorResult);
        reduceRational(rational);
        return rational;
    }

    public Rational divide(Rational x) throws DivisionByZero {
        Rational rational = new Rational(x.denominator, x.numerator);
        if (x.numerator == 0) {
            throw new DivisionByZero("Division by zero!");
        }
        return this.multiply(rational);
    }

    public Rational opposite() throws DivisionByZero {
        return new Rational(this.numerator * (-1), this.denominator);
    }

    public Rational inverse() throws DivisionByZero {
        if (this.numerator == 0) {
            throw new DivisionByZero("Division by zero!");
        }
        return new Rational(this.denominator, this.numerator);
    }

    public int compare(Rational x) {
        if (x.numerator == this.numerator && x.denominator == this.denominator) {
            return 0;
        } else {
            int rational1 = this.numerator / this.denominator;
            int rational2 = x.numerator / x.denominator;
            return rational1 < rational2 ? -1 : 1;
        }
    }

    @Override
    public String toString() {
        return numerator + "/" + denominator;
    }
}
