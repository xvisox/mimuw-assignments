package com.company.kolokwia.bajaderki;

public class Skarbiec {
    private Dzielo dzielo;

    public Strona dajStrone(int nrStrony) {
        Strona stronaPrzepisu = dzielo.getStrony()[nrStrony];
        dzielo.getStrony()[nrStrony] = null;
        return stronaPrzepisu;
    }

    public void zabierzStrone(int nrRamki, Mistrz mistrz) {
        Strona stronaDoOddania = mistrz.getRamkiStron()[nrRamki];
        dzielo.getStrony()[stronaDoOddania.getNumerStrony()] = stronaDoOddania;
        mistrz.oddajStrone(nrRamki);
    }
}
