package com.company.kolokwia.wirus;

import java.util.Random;

public class WirusSpecyficzny extends Wirus {
    int[] ktorePozycje;
    char[] jakieNukleotydy;

    public WirusSpecyficzny(char[] kwasNukleinowy, int dlugoscKwasu, int mutacjeWMiesiac, int[] ktorePozycje, char[] jakieNukleotydy) {
        super(kwasNukleinowy, dlugoscKwasu, mutacjeWMiesiac);
        this.ktorePozycje = ktorePozycje;
        this.jakieNukleotydy = jakieNukleotydy;
    }

    @Override
    public void mutuj() {
        Random random = new Random();
        int ileNukleotydow = jakieNukleotydy.length;
        for (int j = 0; j < mutacjeWMiesiac; j++) {
            for (int i = 0; i < ileNukleotydow; i++) {
                kwasNukleinowy[ktorePozycje[i]] = jakieNukleotydy[random.nextInt(ileNukleotydow)];
            }
        }
    }
}
