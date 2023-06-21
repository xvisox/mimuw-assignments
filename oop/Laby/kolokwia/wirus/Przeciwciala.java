package com.company.kolokwia.wirus;

public class Przeciwciala {
    private char[] ciagNukleotydow;

    public Przeciwciala(char[] ciagNukleotydow) {
        this.ciagNukleotydow = ciagNukleotydow;
    }

    public boolean czyRozpoznajeWirusa(Wirus wirus) {
        int j;
        for (int i = 0; i < wirus.dlugoscKwasu - ciagNukleotydow.length; i++) {
            j = 0;
            while (wirus.kwasNukleinowy[i + j] == ciagNukleotydow[j]) {
                j++;
            }
            if (ciagNukleotydow.length == j + 1) {
                return true;
            }
        }
        return false;
    }
}
