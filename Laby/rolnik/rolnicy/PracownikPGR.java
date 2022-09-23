package com.company.rolnik.rolnicy;

public class PracownikPGR extends Rolnik {
    public PracownikPGR(int ileMiejsc) {
        super(ileMiejsc);
    }

    private void zbierzWszystkieWarzywa() {
        for (int i = 0; i < ogrod.getIloscWarzyw(); i++) {
            zbierzWarzywo(i);
        }
    }

    @Override
    public void wykonajStrategie(int czas) {
        int sekunda = 1000;
        long poczatekSymulacji = System.currentTimeMillis();
        posadzWarzywaLosowo();

        while ((System.currentTimeMillis() - poczatekSymulacji) / sekunda < czas) {
            try {
                Thread.sleep(sekunda * 10);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            zbierzWszystkieWarzywa();
            posadzWarzywaLosowo();
        }
    }


}
