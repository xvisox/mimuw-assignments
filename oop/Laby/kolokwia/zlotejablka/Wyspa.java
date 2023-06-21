package com.company.kolokwia.zlotejablka;

import java.util.ArrayList;

public class Wyspa {
    private Jablon[] jablonie;
    private ArrayList<Jablko> jablka;

    public Wyspa(Jablon[] jablonie) {
        this.jablonie = jablonie;
    }

    public void generujJablka() {
        for (int i = 0; i < jablonie.length; i++) {
            jablka.add(jablonie[i].dajJablko());
        }
    }

    public ArrayList<Jablko> getJablka() {
        return jablka;
    }

    public void zbierzJablko(Jablko jablko) {
        jablka.remove(jablko);
    }
}
