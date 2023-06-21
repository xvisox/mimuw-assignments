package com.company.rolnik.rolnicy;

import com.company.rolnik.warzywa.*;

import java.util.ArrayList;
import java.util.Random;

public abstract class Rolnik {
    protected Ogrod ogrod;
    protected ArrayList<Warzywo> zebraneWarzywa;
    protected int ileWydano;

    public Rolnik(int ileMiejsc) {
        this.ogrod = new Ogrod(ileMiejsc);
        this.zebraneWarzywa = new ArrayList<>();
        this.ileWydano = 0;
    }

    protected abstract void wykonajStrategie(int czas);

    public void symulacja(int czas) {
        wykonajStrategie(czas);
        System.out.println("Zakonczono symulacje!");
        wypiszRaport();
    }

    protected Warzywo wybierzLosoweWarzywo() {
        Warzywo[] warzywa = new Warzywo[3];
        warzywa[0] = new Pomidor();
        warzywa[1] = new Ogorek();
        warzywa[2] = new Ziemniak();
        Random generator = new Random();
        return warzywa[generator.nextInt(3)];
    }

    protected void posadzWarzywaLosowo() {
        for (int i = 0; i < ogrod.getIloscWarzyw(); i++) {
            if (ogrod.getWarzywa()[i] == null) {
                ogrod.getWarzywa()[i] = wybierzLosoweWarzywo();
                ileWydano += ogrod.getWarzywa()[i].getKoszt();
            }
        }
    }

    protected void zbierzWarzywo(int miejsce) {
        Warzywo zebraneWarzywo = ogrod.getWarzywa()[miejsce];
        zebraneWarzywo.setWartosc(zebraneWarzywo.zwrocWartoscWarzywa());
        zebraneWarzywa.add(zebraneWarzywo);
        ogrod.getWarzywa()[miejsce] = null;
        System.out.println("Zebrałem: " + zebraneWarzywo);
    }

    public void wypiszRaport() {
        int przychody, ileZiemniak, ilePomidor, ileOgorek;
        przychody = ileZiemniak = ilePomidor = ileOgorek = 0;

        for (Warzywo warzywo : zebraneWarzywa) {
            if (warzywo.getNazwa().equals("Ziemniak")) ileZiemniak++;
            if (warzywo.getNazwa().equals("Ogorek")) ileOgorek++;
            if (warzywo.getNazwa().equals("Pomidor")) ilePomidor++;

            przychody += warzywo.getWartosc();
        }
        System.out.println("Ilosc ziemniakow: " + ileZiemniak);
        System.out.println("Ilosc ogorkow: " + ileOgorek);
        System.out.println("Ilosc pomidorow: " + ilePomidor);
        System.out.println("Laczne przychody: " + przychody);
        System.out.println("Laczne koszta: " + ileWydano);
        System.out.println("Bilans: " + (przychody - ileWydano));
    }
}
