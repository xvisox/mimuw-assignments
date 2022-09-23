package pl.mimuw.oferty;

import lombok.Data;
import lombok.EqualsAndHashCode;
import pl.mimuw.agenci.Spekulant;
import pl.mimuw.atrybuty.zasoby.TypZasoby;

import static pl.mimuw.utility.UtilityMath.MINIMALNA_CENA;

@EqualsAndHashCode(callSuper = true)
@Data
public class OfertaSpekulanta extends Oferta {
    private Spekulant spekulant;
    private double cena;

    public OfertaSpekulanta(TypZasoby typ, int liczba, Spekulant spekulant, double cena, int poziom) {
        super(typ, liczba, poziom);
        this.spekulant = spekulant;
        this.cena = Math.max(cena, MINIMALNA_CENA);
    }
}
