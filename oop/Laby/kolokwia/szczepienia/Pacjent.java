package com.company.kolokwia.szczepienia;

public class Pacjent {
    private boolean czyOdporny;
    private int kiedyWizyta;
    private int adres;
    private int maxOdleglosc;
    private Szczepionka jakaSzczepionka;

    public Pacjent(int adres, Szczepionka jakaSzczepionka, int maxOdleglosc) {
        this.jakaSzczepionka = jakaSzczepionka;
        this.maxOdleglosc = maxOdleglosc;
        this.czyOdporny = false;
        this.kiedyWizyta = -1;
        this.adres = adres;
    }

    public void setWizyta(int data) {
        this.kiedyWizyta = data;
    }

    public void setOdporny() {
        this.czyOdporny = true;
    }

    public int getAdres() {
        return adres;
    }

    public int getMaxOdleglosc() {
        return maxOdleglosc;
    }

    public Szczepionka getJakaSzczepionka() {
        return jakaSzczepionka;
    }
}
