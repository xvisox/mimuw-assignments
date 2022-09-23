package com.company.kolokwia.wirus;

public abstract class Wirus {
    protected char[] kwasNukleinowy;
    protected int dlugoscKwasu;
    protected int mutacjeWMiesiac;

    public Wirus(char[] kwasNukleinowy, int dlugoscKwasu, int mutacjeWMiesiac) {
        this.kwasNukleinowy = kwasNukleinowy;
        this.dlugoscKwasu = dlugoscKwasu;
        this.mutacjeWMiesiac = mutacjeWMiesiac;
    }

    public abstract void mutuj();
}
