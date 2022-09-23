package pl.mimuw.atrybuty.produkcja;

import lombok.Data;
import lombok.EqualsAndHashCode;
import pl.mimuw.agenci.Robotnik;
import pl.mimuw.atrybuty.zasoby.TypZasoby;
import pl.mimuw.gielda.Ceny;
import pl.mimuw.gielda.Gielda;

@EqualsAndHashCode(callSuper = true)
@Data
public class Sredniak extends Produkcja {
    private int historia_sredniej_produkcji;

    @Override
    public TypZasoby coDzisProdukuje(Robotnik robotnik, Gielda gielda) {
        int i = gielda.getLiczbaDni();
        int j = historia_sredniej_produkcji;

        Ceny ceny;
        TypZasoby produkt = null;
        double maxSredniaCena = -1;

        while (i > 0 && j > 0) {
            ceny = gielda.getDziennik().get(i - 1).getCeny_srednie();

            if (maxSredniaCena < ceny.getJedzenie()) {
                maxSredniaCena = ceny.getJedzenie();
                produkt = TypZasoby.JEDZENIE;
            }
            if (maxSredniaCena < ceny.getNarzedzia()) {
                maxSredniaCena = ceny.getNarzedzia();
                produkt = TypZasoby.NARZEDZIA;
            }
            if (maxSredniaCena < ceny.getProgramy()) {
                maxSredniaCena = ceny.getProgramy();
                produkt = TypZasoby.PROGRAMY;
            }
            if (maxSredniaCena < ceny.getUbrania()) {
                maxSredniaCena = ceny.getUbrania();
                produkt = TypZasoby.UBRANIA;
            }

            i--;
            j--;
        }
        return produkt;
    }
}
