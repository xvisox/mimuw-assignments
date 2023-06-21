package com.company.kolokwia.zlotejablka;

public class Firma {
    private Statek[] statki;
    private int ilePestek;

    public Firma(Statek[] statki) {
        this.statki = statki;
        this.ilePestek = 0;
    }

    public Statek[] getStatki() {
        return statki;
    }

    public int getIlePestek() {
        return ilePestek;
    }

    public void policzPestki() {
        for (Statek statek : statki) {
            for (Jablko jablko : statek.getLadowania()) {
                ilePestek += jablko.getPestki();
            }
        }
    }
}
