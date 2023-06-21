package com.company.kolokwia.szczepienia;

public class CentralneBiuroSzczepien {
    private int ileZaszczepionych;

    public CentralneBiuroSzczepien() {
        this.ileZaszczepionych = 0;
    }

    public void zwiekszLiczbeZaszczepionych() {
        ileZaszczepionych++;
    }

    public PunktSzczepien szukajPunktu(Pacjent pacjent, Wojewodztwa wojewodztwa) {
        Wojewodztwo wojewodztwoPacjenta = wojewodztwa.getWojewodztwo(pacjent.getAdres() / 10000);
        PunktSzczepien znalezionyPunkt = null;
        int wolnyTermin = 366;
        int najmniejszaOdleglosc = 10000;
        int odleglosc = 0;
        for (PunktSzczepien punkt : wojewodztwoPacjenta.getPunktySzczepien()) {
            odleglosc = Math.abs(punkt.getAdres() - pacjent.getAdres());
            if (odleglosc <= pacjent.getMaxOdleglosc() &&
                    punkt.getSzczepionka().getNazwa().equals(pacjent.getJakaSzczepionka().getNazwa())) {
                if (wolnyTermin > punkt.getNajblizszyWolny()) {
                    znalezionyPunkt = punkt;
                    wolnyTermin = punkt.getNajblizszyWolny();
                    najmniejszaOdleglosc = odleglosc;
                } else if (wolnyTermin == punkt.getNajblizszyWolny() && odleglosc < najmniejszaOdleglosc) {
                    znalezionyPunkt = punkt;
                    wolnyTermin = punkt.getNajblizszyWolny();
                    najmniejszaOdleglosc = odleglosc;
                }
            }
        }
        return znalezionyPunkt;
    }
}
