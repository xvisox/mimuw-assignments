package pl.mimuw.atrybuty.kupowanie;

import lombok.Data;
import lombok.EqualsAndHashCode;
import pl.mimuw.agenci.Robotnik;
import pl.mimuw.atrybuty.zasoby.TypZasoby;
import pl.mimuw.gielda.Gielda;
import pl.mimuw.oferty.OfertaRobotnika;

@Data
@EqualsAndHashCode(callSuper = true)
public class Zmechanizowany extends Czyscioszek {
    private int liczba_narzedzi;

    @Override
    public void wystawOfertyKupna(Robotnik robotnik, Gielda gielda) {
        // Wystawia ofertę czyścioszka.
        super.wystawOfertyKupna(robotnik, gielda);
        gielda.dodajOferteKupna(new OfertaRobotnika(TypZasoby.NARZEDZIA, liczba_narzedzi, robotnik, 0));
    }
}
