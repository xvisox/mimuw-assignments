package com.company.kolokwia.zlotejablka;

public class Archipelag {
    private Wyspa[] wyspy;

    public Archipelag(Wyspa[] wyspy) {
        this.wyspy = wyspy;
    }

    public Wyspa[] getWyspy() {
        return wyspy;
    }

    public int[] przeprowadzTydzien(Firma[] firmy) {
        int[] liczbaPestek = new int[firmy.length];
        for (Wyspa wyspa : wyspy) {
            wyspa.generujJablka();
        }

        for (int i = 0; i < 7; i++) {
            for (Firma firma : firmy) {
                for (Statek statek : firma.getStatki()) {
                    if (statek.getPojemnosc() >= i + 1) {
                        statek.wybierzJablko(wyspy[statek.getPlanPodrozy()[i]]);
                    }
                }
            }
        }

        int i = 0;
        for (Firma firma : firmy) {
            firma.policzPestki();
            liczbaPestek[i] = firma.getIlePestek();
            i++;
        }
        return liczbaPestek;
    }
}
