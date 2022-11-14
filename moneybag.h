#ifndef MONEYBAG_H
#define MONEYBAG_H

#include <ostream>
#include <string>
#include <compare>
#include <boost/multiprecision/cpp_int.hpp>

class Moneybag {
public:
    using coin_number_t = uint64_t;

    constexpr Moneybag(coin_number_t livresNumber, coin_number_t solidusesNumber, coin_number_t deniersNumber)
            : livres(livresNumber), soliduses(solidusesNumber), deniers(deniersNumber) {}

    constexpr coin_number_t livre_number() const {
        return livres;
    }

    constexpr coin_number_t denier_number() const {
        return deniers;
    }

    constexpr coin_number_t solidus_number() const {
        return soliduses;
    }

    bool operator==(const Moneybag &moneybag) const = default;

    constexpr std::partial_ordering operator<=>(const Moneybag &moneybag) const {
        if (livres == moneybag.livres && deniers == moneybag.deniers && soliduses == moneybag.soliduses) {
            return std::partial_ordering::equivalent;
        } else if (livres >= moneybag.livres && deniers >= moneybag.deniers && soliduses >= moneybag.soliduses) {
            return std::partial_ordering::greater;
        } else if (livres <= moneybag.livres && deniers <= moneybag.deniers && soliduses <= moneybag.soliduses) {
            return std::partial_ordering::less;
        } else {
            return std::partial_ordering::unordered;
        }
    }

    constexpr explicit operator bool() const {
        return livres | soliduses | deniers;
    }

    constexpr const Moneybag &operator+=(const Moneybag &moneybag) {
        if ((INT64_MAX - livres) < moneybag.livres ||
            (INT64_MAX - soliduses) < moneybag.soliduses ||
            (INT64_MAX - deniers) < moneybag.deniers) {
            throw std::out_of_range("Unexpected addition!");
        }

        livres += moneybag.livres;
        soliduses += moneybag.soliduses;
        deniers += moneybag.deniers;

        return *this;
    }

    constexpr Moneybag operator+(const Moneybag &moneybag) const {
        return Moneybag(*this) += moneybag;
    }

    constexpr const Moneybag &operator-=(const Moneybag &moneybag) {
        if (livres < moneybag.livres ||
            soliduses < moneybag.soliduses ||
            deniers < moneybag.deniers) {
            throw std::out_of_range("Unexpected subtraction!");
        }

        livres -= moneybag.livres;
        soliduses -= moneybag.soliduses;
        deniers -= moneybag.deniers;

        return *this;
    }

    constexpr Moneybag operator-(const Moneybag &moneybag) const {
        return Moneybag(*this) -= moneybag;
    }

    constexpr const Moneybag &operator*=(coin_number_t multiply) {
        if ((INT64_MAX / multiply) < livres ||
            (INT64_MAX / multiply) < soliduses ||
            (INT64_MAX / multiply) < deniers) {
            throw std::out_of_range("Unexpected multiplication!");
        }

        livres *= multiply;
        soliduses *= multiply;
        deniers *= multiply;

        return *this;
    }

private:
    coin_number_t livres;
    coin_number_t soliduses;
    coin_number_t deniers;
};

inline std::ostream &operator<<(std::ostream &stream, const Moneybag &moneybag) {
    static auto printCurrency =
    [](std::string &&currencyName, std::string &&plural, Moneybag::coin_number_t currencyCount) -> std::string {
        std::string result = std::to_string(currencyCount);
        result += (' ' + currencyName);
        if (currencyCount != 1) {
            result += plural;
        }
        return result;
    };

    stream << '(';
    stream << printCurrency("livr", "es", moneybag.livre_number());
    stream << ", ";
    stream << printCurrency("solidus", "es", moneybag.solidus_number());
    stream << ", ";
    stream << printCurrency("denier", "s", moneybag.denier_number());
    stream << ')';

    return stream;
}

// Przy wykonywaniu mnożenia nie wiemy, czy skalar będzie po lewej, czy po prawej stronie
// (w operatorze deklarowanym w klasie, domyślnie skalar byłby po lewej).
constexpr Moneybag operator*(const Moneybag &left, Moneybag::coin_number_t right) {
    return Moneybag(left) *= right;
}

constexpr Moneybag operator*(Moneybag::coin_number_t left, const Moneybag &right) {
    return right * left;
}

constinit const Moneybag Livre = Moneybag(1, 0, 0);
constinit const Moneybag Solidus = Moneybag(0, 1, 0);
constinit const Moneybag Denier = Moneybag(0, 0, 1);

class Value {
public:
    using coin_value_t = boost::multiprecision::uint128_t;

    Value(Moneybag moneybag) :
            deniers((coin_value_t) moneybag.denier_number() +
                    (coin_value_t) moneybag.solidus_number() * SOLIDUS_TO_DENIER +
                    (coin_value_t) moneybag.livre_number() * LIVR_TO_DENIER) {}

    constexpr Value(coin_value_t deniersNumber = 0) : deniers(deniersNumber) {}

    bool operator==(const Value &value) const = default;

    bool operator==(coin_value_t value) {
        return value == deniers;
    };

    std::strong_ordering operator<=>(const Value &value) const {
        if (deniers == value.deniers) {
            return std::strong_ordering::equivalent;
        } else if (deniers > value.deniers) {
            return std::strong_ordering::greater;
        } else {
            return std::strong_ordering::less;
        }
    }

    std::strong_ordering operator<=>(coin_value_t value) const {
        if (deniers == value) {
            return std::strong_ordering::equivalent;
        } else if (deniers > value) {
            return std::strong_ordering::greater;
        } else {
            return std::strong_ordering::less;
        }
    }

    explicit operator std::string() const {
        return deniers.str();
    }

private:
    coin_value_t deniers;
    static constexpr coin_value_t LIVR_TO_DENIER = 240;
    static constexpr coin_value_t SOLIDUS_TO_DENIER = 12;
};

#endif // MONEYBAG_H