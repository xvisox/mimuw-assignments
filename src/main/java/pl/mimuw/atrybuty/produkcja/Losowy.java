package pl.mimuw.atrybuty.produkcja;

import lombok.Data;
import lombok.EqualsAndHashCode;
import pl.mimuw.agenci.Robotnik;
import pl.mimuw.atrybuty.zasoby.TypZasoby;
import pl.mimuw.gielda.Gielda;

import static pl.mimuw.Main.random;

@EqualsAndHashCode(callSuper = true)
@Data
public class Losowy extends Produkcja {
    @Override
    public TypZasoby coDzisProdukuje(Robotnik robotnik, Gielda gielda) {
        TypZasoby[] produkty = new TypZasoby[]{TypZasoby.UBRANIA, TypZasoby.DIAMENTY, TypZasoby.JEDZENIE, TypZasoby.NARZEDZIA, TypZasoby.PROGRAMY};
        return produkty[random.nextInt(5)];
    }
}
