package com.company.kolokwia.zlotejablka;

import java.util.ArrayList;

public class Statek {
    private int[] planPodrozy;
    private int ileDukatow;
    private int pojemnosc;
    private ArrayList<Jablko> ladowania;

    public Statek(int[] planPodrozy, int pojemnosc) {
        this.planPodrozy = planPodrozy;
        this.pojemnosc = pojemnosc;
        this.ladowania = new ArrayList<Jablko>();
        this.ileDukatow = 1000;
    }

    public int[] getPlanPodrozy() {
        return planPodrozy;
    }

    public int getPojemnosc() {
        return pojemnosc;
    }

    public ArrayList<Jablko> getLadowania() {
        return ladowania;
    }

    public void wybierzJablko(Wyspa wyspa) {
        int najwiecej = 0;
        Jablko najdrozsze = null;
        for (Jablko jablko : wyspa.getJablka()) {
            if (jablko.getPestki() > najwiecej && jablko.getPestki() * 40 <= ileDukatow) {
                najwiecej = jablko.getPestki();
                najdrozsze = jablko;
            }
        }
        if (najdrozsze != null) {
            ladowania.add(najdrozsze);
            wyspa.zbierzJablko(najdrozsze);
            ileDukatow -= 40 * najdrozsze.getPestki();
        }
    }
}
