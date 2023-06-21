package com.company.rational;

public class main {

    public static void main(String[] args) throws DivisionByZero {
        Rational rational1 = new Rational(1, 2);
        Rational rational2 = new Rational(2, 1);
        Rational negative1 = new Rational(-2, 3);
        System.out.println(rational1 + " + " + rational2 + " = " + rational1.add(rational2));
        System.out.println(rational1 + " - " + rational2 + " = " + rational1.subtract(rational2));
        System.out.println(rational1 + " * " + rational2 + " = " + rational1.multiply(rational2));
        System.out.println(rational1 + " : " + rational2 + " = " + rational1.divide(rational2));
        System.out.println(rational1 + " * (-1) = " + rational1.opposite());
        System.out.println("(" + rational1 + ")^(-1) = " + rational1.inverse());
        System.out.println("Sign of " + rational1 + " = " + rational1.getSign());
        System.out.println("Sign of " + negative1 + " = " + negative1.getSign());
        System.out.println("Sign of " + Rational.zero() + " = " + Rational.zero().getSign());
        System.out.println(rational1.compare(rational2));

        Rational zero = Rational.zero();
        // ERROR 1
        Rational rational_error = new Rational(1,0);
        // ERROR 2
//        rational1.divide(zero);
        // ERROR 3
//        zero.inverse();
    }
}
