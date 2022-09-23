package com.company.rolnik.warzywa;

public class Ogrod {
    private Warzywo[] warzywa;
    private int iloscWarzyw;

    public Ogrod(int iloscWarzyw) {
        this.iloscWarzyw = iloscWarzyw;
        this.warzywa = new Warzywo[iloscWarzyw];
    }

    public Warzywo[] getWarzywa() {
        return warzywa;
    }

    public int getIloscWarzyw() {
        return iloscWarzyw;
    }
}
