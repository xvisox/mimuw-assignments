package com.company.kolokwia.wirus;

public class Szczepionka {
    private char[] nukleotydy;

    public Przeciwciala tworzPrzeciwciala() {
        Przeciwciala przeciwciala = new Przeciwciala(nukleotydy);
        return przeciwciala;
    }

    public boolean czyDajeOdpornosc(Wirus wirus, int liczbaMiesiecy) {
        Przeciwciala przeciwciala = this.tworzPrzeciwciala();
        for (int i = 0; i < liczbaMiesiecy; i++) {
            wirus.mutuj();
        }
        return przeciwciala.czyRozpoznajeWirusa(wirus);
    }
}
