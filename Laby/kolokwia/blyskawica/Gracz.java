package com.company.kolokwia.blyskawica;

import java.util.ArrayList;

public class Gracz {
    private int stanKonta;
    private ArrayList<Karta> kartyGracza;

    public Gracz(int stanKonta) {
        this.stanKonta = stanKonta;
        this.kartyGracza = new ArrayList<>();
    }

    public boolean czyRezygnuje(int stawka) {
        return stanKonta <= stawka;
    }

    public void dodajKarte(Karta karta) {
        this.kartyGracza.add(karta);
    }

    public void wyrzucKarty() {
        this.kartyGracza.clear();
    }

    public void zwiekszStanKonta(int ile) {
        this.stanKonta += ile;
    }

    public void zmniejszStanKonta(int ile) {
        this.stanKonta -= ile;
    }

    public int wartoscNajlepszejKarty() {
        int maksymalna = -1;
        for (Karta karta : kartyGracza) {
            maksymalna = Math.max(maksymalna, karta.zwrocWartoscKarty());
        }
        return maksymalna;
    }
}
