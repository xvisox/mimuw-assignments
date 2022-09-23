package com.company.kolokwia.szczepienia;

public class Szczepionka {
    private String nazwa;
    private String producent;
    private int dawka;

    public Szczepionka(String nazwa, String producent, int dawka) {
        this.nazwa = nazwa;
        this.producent = producent;
        this.dawka = dawka;
    }

    public String getNazwa() {
        return nazwa;
    }

    public String getProducent() {
        return producent;
    }
}
