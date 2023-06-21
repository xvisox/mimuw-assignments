package com.company.kolokwia.bajaderki;

public class Dzielo {
    private Strona[] strony;
    private int S; // ile stron ma dzielo

    public Dzielo(Strona[] strony) {
        this.strony = strony;
        this.S = strony.length;
    }

    public Strona[] getStrony() {
        return strony;
    }
}
