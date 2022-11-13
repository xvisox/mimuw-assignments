#ifndef MONEYBAG_H
#define MONEYBAG_H

#include <ostream>
#include <string>
#include <compare>

class Moneybag {
public:
    using coin_number_t = uint64_t;

    constexpr Moneybag(coin_number_t livresNumber, coin_number_t solidusesNumber, coin_number_t deniersNumber)
            : livres(livresNumber), soliduses(solidusesNumber), deniers(deniersNumber) {}

    constexpr Moneybag(const Moneybag &other) = default;

    Moneybag() = delete;

    ~Moneybag() = default;

    constexpr coin_number_t livre_number() const {
        return livres;
    }

    constexpr coin_number_t denier_number() const {
        return deniers;
    }

    constexpr coin_number_t solidus_number() const {
        return soliduses;
    }

    friend std::ostream &operator<<(std::ostream &stream, const Moneybag &moneybag) {
        stream << '(';
        stream << printCurrency("livr", "es", moneybag.livres);
        stream << ", ";
        stream << printCurrency("solidus", "es", moneybag.soliduses);
        stream << ", ";
        stream << printCurrency("denier", "s", moneybag.deniers);
        stream << ')';

        return stream;
    }

    bool operator==(const Moneybag &moneybag) const = default;

    std::partial_ordering operator<=>(const Moneybag &moneybag) const {
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
        return (livres + soliduses + deniers > 0);
    }

    // TODO - out_of_range (?)
    constexpr const Moneybag &operator+=(const Moneybag &moneybag) {
        livres += moneybag.livres;
        soliduses += moneybag.soliduses;
        deniers += moneybag.deniers;

        return *this;
    }

    constexpr Moneybag operator+(const Moneybag &moneybag) const {
        return Moneybag(*this) += moneybag;
    }

    constexpr const Moneybag &operator-=(const Moneybag &moneybag) {
        if (livres < moneybag.livres || soliduses < moneybag.soliduses || deniers < moneybag.deniers) {
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

    constexpr const Moneybag &operator*=(uint64_t multiply) {
        livres *= multiply;
        soliduses *= multiply;
        deniers *= multiply;

        return *this;
    }

private:
    coin_number_t livres;
    coin_number_t soliduses;
    coin_number_t deniers;

    // TODO - czy to nie przekazuje kopii (?)
    static std::string printCurrency(std::string &&currencyName, std::string &&plural, coin_number_t currencyCount) {
        std::string result = std::to_string(currencyCount);
        result += (' ' + currencyName);
        if (currencyCount != 1) {
            result += plural;
        }

        return result;
    }
};

class Value {
public:
    using coin_number_t = uint64_t;

    explicit Value(Moneybag moneybag) :
            deniers(moneybag.denier_number() +
                    moneybag.solidus_number() * SOLIDUS_TO_DENIER +
                    moneybag.livre_number() * LIVR_TO_DENIER) {}

    explicit Value(coin_number_t deniersNumber) : deniers(deniersNumber) {}

    Value(const Value &other) = default;

    Value() = default;

    ~Value() = default;

    bool operator==(const Value &value) const = default;

    std::partial_ordering operator<=>(const Value &value) const {
        if (deniers == value.deniers) {
            return std::partial_ordering::equivalent;
        } else if (deniers > value.deniers) {
            return std::partial_ordering::greater;
        } else if (deniers < value.deniers) {
            return std::partial_ordering::less;
        } else {
            return std::partial_ordering::unordered;
        }
    }

    bool operator==(uint64_t value) const {
        return value == deniers;
    }

    std::partial_ordering operator<=>(uint64_t value) const {
        if (deniers == value) {
            return std::partial_ordering::equivalent;
        } else if (deniers > value) {
            return std::partial_ordering::greater;
        } else if (deniers < value) {
            return std::partial_ordering::less;
        } else {
            return std::partial_ordering::unordered;
        }
    }

//    operator unsigned long long() const {
//        return deniers;
//    }

    explicit operator std::string() const {
        return std::to_string(deniers);
    }

private:
    coin_number_t deniers;
    static constexpr coin_number_t LIVR_TO_DENIER = 240;
    static constexpr coin_number_t SOLIDUS_TO_DENIER = 12;
};

// TODO - Czy tu ma być uint64?
constexpr Moneybag operator*(const Moneybag &left, const uint64_t right) {
    return Moneybag(left) *= right;
}

constexpr Moneybag operator*(const uint64_t left, const Moneybag &right) {
    return right * left;
}

constexpr Moneybag Livre = Moneybag(1, 0, 0);
constexpr Moneybag Solidus = Moneybag(0, 1, 0);
constexpr Moneybag Denier = Moneybag(0, 0, 1);

#endif // MONEYBAG_H