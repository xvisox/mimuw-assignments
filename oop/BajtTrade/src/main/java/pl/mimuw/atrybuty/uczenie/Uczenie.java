package pl.mimuw.atrybuty.uczenie;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import lombok.Data;
import lombok.ToString;
import pl.mimuw.agenci.Robotnik;
import pl.mimuw.gielda.Gielda;

@Data
@ToString(exclude = {"czyPracuje"})
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.EXISTING_PROPERTY, property = "typ", visible = true)
@JsonSubTypes({
        @JsonSubTypes.Type(value = Student.class, name = "student"),
        @JsonSubTypes.Type(value = Okresowy.class, name = "okresowy"),
        @JsonSubTypes.Type(value = Pracus.class, name = "pracus"),
        @JsonSubTypes.Type(value = Oszczedny.class, name = "oszczedny"),
        @JsonSubTypes.Type(value = Rozkladowy.class, name = "rozkladowy")
})
public abstract class Uczenie {
    private TypUczenia typ;
    @JsonIgnore
    private boolean czyPracuje;

    public boolean czyPracuje() {
        return czyPracuje;
    }

    public abstract boolean czyDzisPracuje(Robotnik robotnik, Gielda gielda);
}
