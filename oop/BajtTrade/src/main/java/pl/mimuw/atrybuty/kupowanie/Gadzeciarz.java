package pl.mimuw.atrybuty.kupowanie;

import pl.mimuw.agenci.Robotnik;
import pl.mimuw.atrybuty.zasoby.TypZasoby;
import pl.mimuw.gielda.Gielda;
import pl.mimuw.oferty.OfertaRobotnika;

public class Gadzeciarz extends Zmechanizowany {

    @Override
    public void wystawOfertyKupna(Robotnik robotnik, Gielda gielda) {
        // Wystawia ofertę zmechanizowanego.
        super.wystawOfertyKupna(robotnik, gielda);
        if (robotnik.coDzisProdukuje(gielda).equals(TypZasoby.PROGRAMY)) {
            int ileProduktu = robotnik.getWyprodukowane().getIleWyprodukowano();
            if (ileProduktu == 0) return;
            gielda.dodajOferteKupna(new OfertaRobotnika(TypZasoby.PROGRAMY, ileProduktu, robotnik, 0));
        }
    }
}
