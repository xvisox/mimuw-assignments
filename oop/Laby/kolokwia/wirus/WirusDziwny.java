package com.company.kolokwia.wirus;

import java.util.Random;

public class WirusDziwny extends Wirus {


    public WirusDziwny(char[] kwasNukleinowy, int dlugoscKwasu, int mutacjeWMiesiac) {
        super(kwasNukleinowy, dlugoscKwasu, mutacjeWMiesiac);
    }

    private void zamien2Losowe() {
        Random random = new Random();
        int doZamiany1 = random.nextInt(dlugoscKwasu);
        int doZamiany2 = random.nextInt(dlugoscKwasu);
        char temp = kwasNukleinowy[doZamiany1];
        kwasNukleinowy[doZamiany1] = kwasNukleinowy[doZamiany2];
        kwasNukleinowy[doZamiany2] = temp;
    }

    @Override
    public void mutuj() {
        for (int i = 0; i < mutacjeWMiesiac; i++) {
            zamien2Losowe();
        }
    }
}
