package com.company.kolokwia.szczepienia;

public class PunktSzczepien {
    private Szczepionka szczepionka;
    private int adres;
    private int ileDziennie;
    private int najblizszyWolny;
    private int[] ileZapisanych;

    public PunktSzczepien(int ileDziennie, int adres, Szczepionka szczepionka) {
        this.adres = adres;
        this.szczepionka = szczepionka;
        this.ileDziennie = ileDziennie;
        this.najblizszyWolny = 0;
        this.ileZapisanych = new int[365];
    }

    public int getAdres() {
        return adres;
    }

    public Szczepionka getSzczepionka() {
        return szczepionka;
    }

    public int getNajblizszyWolny() {
        return najblizszyWolny;
    }

    public void umowWizyte(Pacjent pacjent) {
        ileZapisanych[najblizszyWolny]++;
        pacjent.setWizyta(najblizszyWolny);
        if (ileZapisanych[najblizszyWolny] == ileDziennie + 1) {
            najblizszyWolny++;
        }
    }

    public void zaszczep(Pacjent pacjent, CentralneBiuroSzczepien centralneBiuroSzczepien) {
        pacjent.setOdporny();
        centralneBiuroSzczepien.zwiekszLiczbeZaszczepionych();
    }
}
