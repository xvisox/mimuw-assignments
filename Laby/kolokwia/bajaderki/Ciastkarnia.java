package com.company.kolokwia.bajaderki;

public class Ciastkarnia {
    private Skarbiec skarbiec;
    private Przepisy przepisy;
    private Mistrz mistrz;

    public Ciastkarnia(Skarbiec skarbiec, Mistrz mistrz) {
        this.skarbiec = skarbiec;
        this.mistrz = mistrz;
        this.przepisy = new Przepisy();
    }

    public void setMistrz(Mistrz mistrz) {
        this.mistrz = mistrz;
    }


}
