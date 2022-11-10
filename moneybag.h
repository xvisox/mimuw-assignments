#ifndef MONEYBAG_H
#define MONEYBAG_H

#include <compare>

class Moneybag {
public:
    using coin_number_t = uint64_t;

    constexpr Moneybag(coin_number_t livresNumber, coin_number_t solidusesNumber, coin_number_t deniersNumber)
            : livres(livresNumber), soliduses(solidusesNumber), deniers(deniersNumber) {}

    // zarąbane od mądrych ludzi
    constexpr Moneybag(const Moneybag &other) = default;

    // wsm nie kazali pisać move constructora
    //constexpr Moneybag(Moneybag &&other) = default;

    constexpr coin_number_t livre_number() const {
        return livres;
    }

    constexpr coin_number_t denier_number() const {
        return deniers;
    }

    constexpr coin_number_t solidus_number() const {
        return soliduses;
    }

    Moneybag() = delete; // TODO CHYBA :)

    friend std::ostream &operator<<(std::ostream &stream, const Moneybag &moneybag) {
        stream << "(";
        stream << printCurrency("livr", "es", moneybag.livres);
        stream << ", ";
        stream << printCurrency("solidus", "es", moneybag.soliduses);
        stream << ", ";
        stream << printCurrency("denier", "s", moneybag.deniers);
        stream << ")\n";

        return stream;
    }

    bool operator==(Moneybag const &moneybag)
        const = default;

    std::partial_ordering operator<=>(Moneybag const & moneybag) const {
        if (livres == moneybag.livres && deniers == moneybag.deniers && soliduses == moneybag.soliduses) {
            return std::partial_ordering::equivalent;
        }
        else if (livres >= moneybag.livres && deniers >= moneybag.deniers && soliduses >= moneybag.soliduses) {
            return std::partial_ordering::less;
        }
        else if (livres <= moneybag.livres && deniers <= moneybag.deniers && soliduses <= moneybag.soliduses) {
            return std::partial_ordering::greater;
        }
        else {
            return std::partial_ordering::unordered;
        }
    }

    constexpr explicit operator bool() const {
        return (livres + soliduses + deniers > 0);
    }

    constexpr const Moneybag &operator+=(const Moneybag &moneybag) {
        livres += moneybag.livres;
        soliduses += moneybag.soliduses;
        deniers += moneybag.deniers;

        return *this;
    }

    constexpr const Moneybag operator+(Moneybag const &moneybag) const {
        return Moneybag(*this) += moneybag;
    }

    constexpr const Moneybag &operator-=(const Moneybag &moneybag) {
        if (livres < moneybag.livres || soliduses < moneybag.soliduses || deniers < moneybag.deniers) {
            throw std::out_of_range(""); //todo - idk jaki mądry komunikat tu dać wsm
            return *this;
        }

        livres -= moneybag.livres;
        soliduses -= moneybag.soliduses;
        deniers -= moneybag.deniers;

        return *this;
    }

    constexpr const Moneybag operator-(Moneybag const &moneybag) const {
        return Moneybag(*this) -= moneybag;
    }

    constexpr const Moneybag &operator*=(uint64_t multiply) {
        livres *= multiply;
        soliduses *= multiply;
        deniers *= multiply;

        return *this;
    }

    ~Moneybag() = default;

private:
    coin_number_t livres;
    coin_number_t soliduses;
    coin_number_t deniers;

    static std::string printCurrency(std::string &&currencyName, std::string &&plural,
                                     coin_number_t currencyCount) {
        std::string result = "";
        result += currencyCount + " " + currencyName;
        if (currencyCount != 1) {
            result += plural;
        }

        return result;
    }
};

//todo - idk czy tu ma być uint64 czy jakieś using gówno
constexpr const Moneybag operator*(const Moneybag &left, const uint64_t right) {
    return Moneybag(left) *= right;
}

constexpr const Moneybag operator*(const uint64_t left, const Moneybag &right) {
    return right * left;
}

// chyba constexpr to to samo co constinit const
// (oba inicjalizowane w czasie kompilacji, ale constinit nie daje consta, a constexpr chyba jo)
constexpr Moneybag Livre = Moneybag(1, 0, 0);
constexpr Moneybag Solidus = Moneybag(0, 1, 0); 
constexpr Moneybag Denier = Moneybag(0, 0, 1);

#endif // MONEYBAG_H