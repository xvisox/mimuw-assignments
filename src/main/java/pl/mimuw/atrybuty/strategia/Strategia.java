package pl.mimuw.atrybuty.strategia;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import lombok.Data;
import pl.mimuw.agenci.Spekulant;
import pl.mimuw.atrybuty.zasoby.TypZasoby;
import pl.mimuw.gielda.Gielda;
import pl.mimuw.oferty.OfertaSpekulanta;

import java.util.ArrayList;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.EXISTING_PROPERTY, property = "typ", visible = true)
@JsonSubTypes({
        @JsonSubTypes.Type(value = Sredni.class, name = "sredni"),
        @JsonSubTypes.Type(value = Wypukly.class, name = "wypukly"),
        @JsonSubTypes.Type(value = Regulujacy.class, name = "regulujacy"),
})
@Data
public abstract class Strategia {
    private TypStrategia typ;
    @JsonIgnore
    protected int ILOSC = 100;
    @JsonIgnore
    protected double SELL = 1.1;
    @JsonIgnore
    protected double BUY = 0.9;

    // Wystawia wszystkie oferty sprzedaży produktów po poziomach.
    protected void wystawOfertySprzedazyProduktu(Spekulant spekulant, TypZasoby typ, Gielda gielda, double cena) {
        ArrayList<Integer> iloscPoziomy = spekulant.getZasoby().getPoziomyZasobow().get(typ);
        int najwiekszyPoziom = spekulant.getZasoby().dajNajwiekszyPoziom(typ);
        for (int i = 0; i < najwiekszyPoziom; i++) {
            if (iloscPoziomy.get(i) > 0) {
                gielda.dodajOferteSprzedazy(
                        new OfertaSpekulanta(typ, iloscPoziomy.get(i), spekulant, cena * SELL, i + 1));
            }
        }
    }

    // Wystawia wszystkie oferty sprzedaży i kupna spekulantów.
    public abstract void wystawOferty(Spekulant spekulant, Gielda gielda);

    protected int ileJedzenia(Spekulant spekulant) {
        return spekulant.getZasoby().getJedzenie();
    }
}
