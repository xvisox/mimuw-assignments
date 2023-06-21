package com.company.kolokwia.blyskawica;

import java.util.ArrayList;

public class Gra {
    private int pula;
    private ArrayList<Gracz> gracze;
    private Talia talia;
    private int stawka;

    public Gra(ArrayList<Gracz> gracze, Talia talia, int stawka) {
        this.pula = 0;
        this.gracze = gracze;
        this.talia = talia;
        this.stawka = stawka;
    }

    private void dodajDoPuli(int ile) {
        pula += ile;
    }

    private void zabierzCaloscZPuli(Gracz gracz) {
        gracz.zwiekszStanKonta(pula);
        pula = 0;
    }

    private void symulujRozdanie() {
        for (Gracz gracz : gracze) {
            dodajDoPuli(stawka);
            gracz.zmniejszStanKonta(stawka);
        }

        Talia talia = new Talia();
        for (int i = 0; i < 5; i++) {
            talia.tasuj();
        }
        rozdajKarty();

        int maksymalna = -1;
        Gracz wygranyGracz = null;
        for (Gracz gracz : gracze) {
            if (gracz.wartoscNajlepszejKarty() > maksymalna) {
                maksymalna = gracz.wartoscNajlepszejKarty();
                wygranyGracz = gracz;
            }
        }
        zabierzCaloscZPuli(wygranyGracz);
        // Wypisanie raportu
        for (Gracz gracz : gracze) {
            gracz.wyrzucKarty();
        }

    }

    private void rozdajKarty() {
        for (int i = 0; i < gracze.size(); i++) {
            for (int j = 0; j < 5; j++) {
                gracze.get(i).dodajKarte(talia.getKarty()[i + 5 * j]);
            }
        }
    }

    public void symulujGre() {
        boolean czyGramy = true;
        for (Gracz gracz : gracze) {
            czyGramy = czyGramy && !gracz.czyRezygnuje(stawka);
        }
        while (czyGramy) {
            symulujRozdanie();
            for (Gracz gracz : gracze) {
                czyGramy = czyGramy && !gracz.czyRezygnuje(stawka);
            }
        }
    }


}
