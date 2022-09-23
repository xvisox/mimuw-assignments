package pl.mimuw.atrybuty.kupowanie;

import pl.mimuw.agenci.Robotnik;
import pl.mimuw.atrybuty.zasoby.TypZasoby;
import pl.mimuw.gielda.Gielda;
import pl.mimuw.oferty.OfertaRobotnika;

public class Czyscioszek extends Technofob {

    @Override
    public void wystawOfertyKupna(Robotnik robotnik, Gielda gielda) {
        // Wystawia ofertę technofoba.
        super.wystawOfertyKupna(robotnik, gielda);
        // Robotnik traci 100 ubrań pod koniec tury, więc jeśli ma mniej niż 200, to mu nie starczy.
        if (robotnik.getZasoby().getUbrania() < 200) {
            gielda.dodajOferteKupna(new OfertaRobotnika(TypZasoby.UBRANIA, 200 - robotnik.getZasoby().getUbrania(), robotnik, 0));
        }
    }
}
