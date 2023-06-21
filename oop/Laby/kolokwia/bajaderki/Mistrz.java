package com.company.kolokwia.bajaderki;

public abstract class Mistrz {
    private Strona[] ramkiStron;
    private int ileRamek;
    private int ileRamekZajete;

    public Mistrz(Strona[] ramkiStron) {
        this.ramkiStron = ramkiStron;
        this.ileRamek = ramkiStron.length;
        this.ileRamekZajete = 0;
    }

    public Strona[] getRamkiStron() {
        return ramkiStron;
    }

    public Strona dajStronePrzepisu(int nrStrony, Skarbiec skarbiec) {
        return skarbiec.dajStrone(nrStrony);
    }

    public void oddajStrone(int nrRamki) {
        ramkiStron[nrRamki] = null;
    }

    public abstract void zamienStrone(int nrStrony);

    public Bajaderka upieczBajderke(Przepis przepis, Skarbiec skarbiec) {
        boolean stronaZnaleziona = false;
        for (int i = 0; i < przepis.getP(); i++) {
            for (Strona strona : ramkiStron) {
                if (strona.getNumerStrony() == przepis.getNumeryStron()[i]) {
                    stronaZnaleziona = true;
                    break;
                }
            }
            if (!stronaZnaleziona) {
                if (ileRamek != ileRamekZajete) {
                    ramkiStron[ileRamekZajete++] = dajStronePrzepisu(przepis.getNumeryStron()[i], skarbiec);
                } else {
                    zamienStrone(przepis.getNumeryStron()[i]);
                }
            }
        }
        // Mozliwe ze ta czesc powinna byc w ciastkarni jako wybieranie odpowiednich stron przez mistrza
        // (zeby miala dostep do skarbca bez parametru w funkcji)
        return new Bajaderka();
    }
}
