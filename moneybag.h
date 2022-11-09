#ifndef MONEYBAG_H
#define MONEYBAG_H

class Moneybag {
public:
    using coin_number_t = uint64_t;

    Moneybag() = delete; // TODO CHYBA :)

    constexpr Moneybag(coin_number_t livres, coin_number_t soliduses, coin_number_t denieres)
            : livres(livres), soliduses(soliduses), denieres(denieres) {}

    constexpr Moneybag(const Moneybag &other)
            : livres(other.livres), soliduses(other.soliduses), denieres(other.denieres) {}

    constexpr Moneybag(Moneybag &&other) noexcept
            : livres(other.livres), soliduses(other.soliduses), denieres(other.denieres) {}

    constexpr coin_number_t livre_number() const {
        return livres;
    }

    constexpr coin_number_t denier_number() const {
        return denieres;
    }

    constexpr coin_number_t solidus_number() const {
        return soliduses;
    }

    // TODO
    friend std::ostream &operator<<(std::ostream &stream, const Moneybag &moneybag) {
        stream << "(";
        stream << moneybag.livres << " livr";
        if (moneybag.livres != 1) {
            stream << "es";
        }
        stream << ", ";
        stream << moneybag.soliduses << " solidus";
        if (moneybag.soliduses != 1) {
            stream << "es";
        }
        stream << ", ";
        stream << moneybag.denieres << " denier";
        if (moneybag.denieres != 1) {
            stream << "es";
        }
        stream << ")\n";
        return stream;
    }

    ~Moneybag() = default;

private:
    coin_number_t livres;
    coin_number_t denieres;
    coin_number_t soliduses;
};

constinit const Moneybag Livre = Moneybag(1, 0, 0); // TODO constinit
constinit const Moneybag Solidus = Moneybag(0, 1, 0); // TODO constinit
constinit const Moneybag Denier = Moneybag(0, 0, 1); // TODO constinit
// Konstruktory przenoszace (?)

#endif // MONEYBAG_H