package com.company.kolokwia.bajaderki;

public class Strona {
    private int numerStrony;
    private String jakisTekst;

    public Strona(int numerStrony, String jakisTekst) {
        this.numerStrony = numerStrony;
        this.jakisTekst = jakisTekst;
    }

    public int getNumerStrony() {
        return numerStrony;
    }

    public String getJakisTekst() {
        return jakisTekst;
    }
}
