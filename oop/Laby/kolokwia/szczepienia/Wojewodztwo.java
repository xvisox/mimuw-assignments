package com.company.kolokwia.szczepienia;

public class Wojewodztwo {
    private PunktSzczepien[] punktySzczepien;
    private int ilePunktow;

    public Wojewodztwo(PunktSzczepien[] punktySzczepien, int ilePunktow) {
        this.punktySzczepien = punktySzczepien;
        this.ilePunktow = ilePunktow;
    }

    public PunktSzczepien[] getPunktySzczepien() {
        return punktySzczepien;
    }
}
