#ifndef JNP_TASK4_ORGANISM_H
#define JNP_TASK4_ORGANISM_H

#include <cstdint>
#include <optional>
#include <tuple>
#include <concepts>

using vitality_t = uint64_t;

template<typename species_t, bool can_eat_meat, bool can_eat_plants>
requires std::equality_comparable<species_t>
class Organism {
private:
    species_t m_species;
    vitality_t m_vitality;
public:
    constexpr Organism(const species_t &species, vitality_t vitality)
            : m_species(species), m_vitality(vitality) {}

    constexpr vitality_t get_vitality() const {
        return m_vitality;
    }

    const constexpr species_t &get_species() const {
        return m_species;
    }

    constexpr bool is_dead() const {
        return m_vitality == 0;
    }
};

template<typename T>
using Carnivore = Organism<T, true, false>;
template<typename T>
using Omnivore = Organism<T, true, true>;
template<typename T>
using Herbivore = Organism<T, false, true>;
template<typename T>
using Plant = Organism<T, false, false>;

template<typename species_t, bool eat_m, bool eat_p>
constexpr vitality_t given_vitality(const Organism<species_t, eat_m, eat_p> &organism) {
    return organism.get_vitality() / 2;
}

template<typename species_t>
constexpr vitality_t given_vitality(const Plant<species_t> &organism) {
    return organism.get_vitality();
}

template<typename species_t, bool sp1_eats_m, bool sp1_eats_p, bool sp2_eats_m, bool sp2_eats_p>
requires (sp1_eats_m == sp2_eats_m && sp1_eats_p == sp2_eats_p)
constexpr std::optional<Organism<species_t, sp1_eats_m, sp1_eats_p>>
get_child(Organism<species_t, sp1_eats_m, sp1_eats_p> organism1,
          Organism<species_t, sp2_eats_m, sp2_eats_p> organism2) {
    if (organism1.get_species() == organism2.get_species()) {
        return Organism<species_t, sp1_eats_m, sp1_eats_p>
                (organism1.get_species(), (organism1.get_vitality() + organism2.get_vitality()) / 2);
    } else {
        return std::nullopt;
    }
}

template<typename species_t, bool sp1_eats_m, bool sp1_eats_p, bool sp2_eats_m, bool sp2_eats_p>
requires (sp1_eats_m != sp2_eats_m || sp1_eats_p != sp2_eats_p)
constexpr std::optional<Organism<species_t, sp1_eats_m, sp1_eats_p>>
get_child(Organism<species_t, sp1_eats_m, sp1_eats_p> organism1,
          Organism<species_t, sp2_eats_m, sp2_eats_p> organism2) {
    return std::nullopt;
}

template<bool eats_m, bool eats_p>
concept is_herbivore = !eats_m && eats_p;

template<bool eats_m, bool eats_p>
concept is_carnivore = eats_m && !eats_p;

template<bool eats_m, bool eats_p>
concept is_omnivore = eats_m && eats_p;

template<bool eats_m, bool eats_p>
concept is_plant = !eats_m && !eats_p;

template<bool sp1_eats_m, bool sp1_eats_p, bool sp2_eats_m, bool sp2_eats_p>
concept can_eat_each_other = sp1_eats_m && sp2_eats_m;

template<bool sp1_eats_m, bool sp1_eats_p, bool sp2_eats_m, bool sp2_eats_p>
concept neither_can_eat_other = (is_herbivore<sp1_eats_m, sp1_eats_p> && is_herbivore<sp2_eats_m, sp2_eats_p>) ||
                                (is_carnivore<sp1_eats_m, sp1_eats_p> && is_plant<sp2_eats_m, sp2_eats_p>) ||
                                (is_plant<sp1_eats_m, sp1_eats_p> && is_carnivore<sp2_eats_m, sp2_eats_p>);

template<bool sp1_eats_m, bool sp1_eats_p, bool sp2_eats_m, bool sp2_eats_p>
concept left_can_eat_right = (sp1_eats_p && is_plant<sp2_eats_m, sp2_eats_p>) ||
                             (sp1_eats_m && is_herbivore<sp2_eats_m, sp2_eats_p>);

template<bool sp1_eats_m, bool sp1_eats_p, bool sp2_eats_m, bool sp2_eats_p>
concept right_can_eat_left = left_can_eat_right<sp2_eats_m, sp2_eats_p, sp1_eats_m, sp1_eats_p>;

// 1. Pierwsza reguła encounter jest sprawdzana w ten sposób,
//    że nie istnieje template encounter z odpowiednimi wymaganiami,
//    który zmatchuje spotkanie organizmów o różnych typach.
// 2. Druga reguła jest sprawdzana analogicznie.
// 6. W poniższej funkcji rozpatrzona jest walka dwóch zwierząt,
//    jeśli mogą się one nawzajem zjadać.
template<typename species_t, bool sp1_eats_m, bool sp1_eats_p, bool sp2_eats_m, bool sp2_eats_p>
requires can_eat_each_other<sp1_eats_m, sp1_eats_p, sp2_eats_m, sp2_eats_p>
constexpr std::tuple<
        Organism<species_t, sp1_eats_m, sp1_eats_p>,
        Organism<species_t, sp2_eats_m, sp2_eats_p>,
        std::optional<Organism<species_t, sp1_eats_m, sp1_eats_p>>>
encounter(Organism<species_t, sp1_eats_m, sp1_eats_p> organism1,
          Organism<species_t, sp2_eats_m, sp2_eats_p> organism2) {
    // 3. Sprawdzenie, czy któryś z organizmów nie jest martwy.
    if (organism1.is_dead() || organism2.is_dead()) {
        return std::tuple(organism1, organism2, std::nullopt);
    }

    // 4. Jeśli między zwierzętami doszło do godów,
    //    to funkcja get_child zwraca nowy organizm.
    auto child = get_child(organism1, organism2);
    if (child.has_value()) {
        return std::tuple(organism1, organism2, child.value());
    }

    using organism1_t = Organism<species_t, sp1_eats_m, sp1_eats_p>;
    using organism2_t = Organism<species_t, sp2_eats_m, sp2_eats_p>;

    // 6. Walka zwierząt.
    if (organism1.get_vitality() == organism2.get_vitality()) {
        organism1_t dead1(organism1.get_species(), 0);
        organism2_t dead2(organism2.get_species(), 0);
        return std::tuple(dead1, dead2, std::nullopt);
    } else if (organism1.get_vitality() > organism2.get_vitality()) {
        organism1_t winner1(organism1.get_species(),
                            organism1.get_vitality() + organism2.get_vitality() / 2);
        organism2_t dead2(organism2.get_species(), 0);
        return std::tuple(winner1, dead2, std::nullopt);
    } else {
        organism1_t dead1(organism1.get_species(), 0);
        organism2_t winner2(organism2.get_species(),
                            organism2.get_vitality() + organism1.get_vitality() / 2);
        return std::tuple(dead1, winner2, std::nullopt);
    }
}

// 5. Jeśli organizmy nie potrafią się zjadać, to jest wywoływana poniższa
//    funkcja, która zwraca organizmy w nienaruszonym stanie.
template<typename species_t, bool sp1_eats_m, bool sp1_eats_p, bool sp2_eats_m, bool sp2_eats_p>
requires neither_can_eat_other<sp1_eats_m, sp1_eats_p, sp2_eats_m, sp2_eats_p>
constexpr std::tuple<Organism<species_t, sp1_eats_m, sp1_eats_p>,
        Organism<species_t, sp2_eats_m, sp2_eats_p>,
        std::optional<Organism<species_t, sp1_eats_m, sp1_eats_p>>>
encounter(Organism<species_t, sp1_eats_m, sp1_eats_p> organism1,
          Organism<species_t, sp2_eats_m, sp2_eats_p> organism2) {
    // 3. Sprawdzenie, czy któryś z organizmów nie jest martwy.
    if (organism1.is_dead() || organism2.is_dead()) {
        return std::tuple(organism1, organism2, std::nullopt);
    }

    // 4. Jeśli między zwierzętami doszło do godów,
    //    to funkcja get_child zwraca nowy organizm.
    auto child = get_child(organism1, organism2);
    if (child.has_value()) {
        return std::tuple(organism1, organism2, child.value());
    }

    return std::tuple(organism1, organism2, std::nullopt);
}

// 7. 8. Oba warunki są rozpatrywane w dwóch następnych funkcjach,
//       gdzie lewy organizm może zjeść prawy organizm i na odwrót.
//       Reguły 7 i 8 różnią się jedynie zyskiwaną witalnością
//       przez "zjadającego", stąd funkcja given_vitality(organism).
template<typename species_t, bool sp1_eats_m, bool sp1_eats_p, bool sp2_eats_m, bool sp2_eats_p>
requires left_can_eat_right<sp1_eats_m, sp1_eats_p, sp2_eats_m, sp2_eats_p>
constexpr std::tuple<
        Organism<species_t, sp1_eats_m, sp1_eats_p>,
        Organism<species_t, sp2_eats_m, sp2_eats_p>,
        std::optional<Organism<species_t, sp1_eats_m, sp1_eats_p>>>
encounter(Organism<species_t, sp1_eats_m, sp1_eats_p> organism1,
          Organism<species_t, sp2_eats_m, sp2_eats_p> organism2) {
    // 3. Sprawdzenie, czy któryś z organizmów nie jest martwy.
    if (organism1.is_dead() || organism2.is_dead()) {
        return std::tuple(organism1, organism2, std::nullopt);
    }

    // 4. Jeśli między zwierzętami doszło do godów,
    //    to funkcja get_child zwraca nowy organizm.
    auto child = get_child(organism1, organism2);
    if (child.has_value()) {
        return std::tuple(organism1, organism2, child.value());
    }

    if (organism1.get_vitality() > organism2.get_vitality() || (!sp2_eats_m && !sp2_eats_p)) {
        Organism<species_t, sp1_eats_m, sp1_eats_p> winner1(organism1.get_species(),
                                                            organism1.get_vitality() + given_vitality(organism2));
        Organism<species_t, sp2_eats_m, sp2_eats_p> dead2(organism2.get_species(), 0);
        return std::tuple(winner1, dead2, std::nullopt);
    } else {
        return std::tuple(organism1, organism2, std::nullopt);
    }
}

template<typename species_t, bool sp1_eats_m, bool sp1_eats_p, bool sp2_eats_m, bool sp2_eats_p>
requires right_can_eat_left<sp1_eats_m, sp1_eats_p, sp2_eats_m, sp2_eats_p>
constexpr std::tuple<
        Organism<species_t, sp1_eats_m, sp1_eats_p>,
        Organism<species_t, sp2_eats_m, sp2_eats_p>,
        std::optional<Organism<species_t, sp1_eats_m, sp1_eats_p>>>
encounter(Organism<species_t, sp1_eats_m, sp1_eats_p> organism1,
          Organism<species_t, sp2_eats_m, sp2_eats_p> organism2) {
    // 3. Sprawdzenie, czy któryś z organizmów nie jest martwy.
    if (organism1.is_dead() || organism2.is_dead()) {
        return std::tuple(organism1, organism2, std::nullopt);
    }

    // 4. Jeśli między zwierzętami doszło do godów,
    //    to funkcja get_child zwraca nowy organizm.
    auto child = get_child(organism1, organism2);
    if (child.has_value()) {
        return std::tuple(organism1, organism2, child.value());
    }

    if (organism2.get_vitality() > organism1.get_vitality() || (!sp1_eats_m && !sp1_eats_p)) {
        Organism<species_t, sp1_eats_m, sp1_eats_p> dead1(organism1.get_species(), 0);
        Organism<species_t, sp2_eats_m, sp2_eats_p> winner2(organism2.get_species(),
                                                            organism2.get_vitality() + given_vitality(organism1));
        return std::tuple(dead1, winner2, std::nullopt);
    } else {
        return std::tuple(organism1, organism2, std::nullopt);
    }
}

template<typename species_t, bool o1_eat_m, bool o1_eat_p, bool o2_eat_m, bool o2_eat_p>
constexpr Organism<species_t, o1_eat_m, o1_eat_p> operator+(const Organism<species_t, o1_eat_m, o1_eat_p> &o1,
                                                            const Organism<species_t, o2_eat_m, o2_eat_p> &o2) {
    return std::get<0>(encounter(o1, o2));
}

template<typename species_t, bool sp1_eats_m, bool sp1_eats_p, typename ... Args>
constexpr Organism<species_t, sp1_eats_m, sp1_eats_p>
encounter_series(Organism<species_t, sp1_eats_m, sp1_eats_p> organism1, Args ... args) {
    return (organism1 + ... + args);
}

#endif //JNP_TASK4_ORGANISM_H
