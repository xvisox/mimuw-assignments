package pl.mimuw.atrybuty.kupowanie;

import pl.mimuw.agenci.Robotnik;
import pl.mimuw.atrybuty.zasoby.TypZasoby;
import pl.mimuw.gielda.Gielda;
import pl.mimuw.oferty.OfertaRobotnika;

public class Technofob extends Kupowanie {

    @Override
    public void wystawOfertyKupna(Robotnik robotnik, Gielda gielda) {
        gielda.dodajOferteKupna(new OfertaRobotnika(TypZasoby.JEDZENIE, 100, robotnik, 0));
    }
}
