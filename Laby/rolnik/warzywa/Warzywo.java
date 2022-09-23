package com.company.rolnik.warzywa;

public abstract class Warzywo {
    protected String nazwa;
    protected int koszt;
    protected int wartosc;
    protected long kiedyPosadzono;

    public Warzywo(String nazwa, int koszt) {
        this.nazwa = nazwa;
        this.koszt = koszt;
        this.kiedyPosadzono = System.currentTimeMillis();
        this.wartosc = 0;
    }

    public abstract int zwrocWartoscWarzywa();

    public void setWartosc(int wartosc) {
        this.wartosc = wartosc;
    }

    public String getNazwa() {
        return nazwa;
    }

    public int getKoszt() {
        return koszt;
    }

    public int getWartosc() {
        return wartosc;
    }

    @Override
    public String toString() {
        return nazwa + " (wartosc: " + wartosc + " PLN)";
    }
}
