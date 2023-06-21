package com.company.rolnik.rolnicy;

import com.company.rolnik.warzywa.Warzywo;

public class Gospodarz extends Rolnik {

    public Gospodarz(int ileMiejsc) {
        super(ileMiejsc);
    }

    private boolean zbierzWybraneWarzywa(int[] tablicaWartosci) {
        boolean czyZebrano = false;
        Warzywo[] warzywa = ogrod.getWarzywa();
        Warzywo aktualneWarzywo;
        for (int i = 0; i < ogrod.getIloscWarzyw(); i++) {
            aktualneWarzywo = warzywa[i];
            if (tablicaWartosci[i] > aktualneWarzywo.zwrocWartoscWarzywa() ||
                    (aktualneWarzywo.getNazwa().equals("Ziemniak")) && aktualneWarzywo.zwrocWartoscWarzywa() > 0) {
                zbierzWarzywo(i);
                tablicaWartosci[i] = 0;
                czyZebrano = true;
            } else {
                tablicaWartosci[i] = aktualneWarzywo.zwrocWartoscWarzywa();
            }
        }
        return czyZebrano;
    }

    @Override
    protected void wykonajStrategie(int czas) {
        boolean czyZebrano = false;
        int sekunda = 1000;
        long poczatekSymulacji = System.currentTimeMillis();
        int[] tablicaWartosci = new int[ogrod.getIloscWarzyw()];
        posadzWarzywaLosowo();

        while ((System.currentTimeMillis() - poczatekSymulacji) / sekunda < czas) {
            try {
                Thread.sleep(sekunda);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            czyZebrano = zbierzWybraneWarzywa(tablicaWartosci);
            if (czyZebrano) {
                posadzWarzywaLosowo();
            }
        }
    }


}
