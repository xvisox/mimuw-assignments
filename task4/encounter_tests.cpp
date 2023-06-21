#include "organism.h"
#include <cassert>
#include <string>
#include <iostream>

using namespace std;

using species_id_t = std::uint64_t;

const species_id_t maize_id = 1;
const species_id_t wheat_id = 2;
const species_id_t human_id = 3;
const species_id_t giraffe_id = 4;
const species_id_t panda_id = 5;
const species_id_t lion_id = 6;
const species_id_t black_panter_id = 7;
const species_id_t rhino_id = 8;

int main() {
    constexpr Plant<species_id_t> maize(maize_id, 5);
    constexpr Plant<species_id_t> wheat(wheat_id, 4);
    constexpr Omnivore<species_id_t> human(human_id, 100);
    constexpr Herbivore<species_id_t> male_giraffe(giraffe_id, 55);
    constexpr Herbivore<species_id_t> female_giraffe(giraffe_id, 33);
    constexpr Herbivore<species_id_t> panda(panda_id, 21);
    constexpr Carnivore<species_id_t> lion(lion_id, 200);
    constexpr Carnivore<species_id_t> black_panther(black_panter_id, 200);
    constexpr Herbivore<species_id_t> rhino(rhino_id, 300);
    // Dwie rośliny nie mogą się spotkać
//     encounter(maize, wheat);

    // Spotkanie wszystkożercy z rośliną
    constexpr auto encounter_result1 = encounter(wheat, human);
    constexpr auto wheat_result1 = get<0>(encounter_result1);
    constexpr auto human_result1 = get<1>(encounter_result1);
    constexpr auto child_result1 = get<2>(encounter_result1);
    static_assert(wheat_result1.get_vitality() == 0);
    static_assert(human_result1.get_vitality() == 104);
    static_assert(!child_result1.has_value());

    // Spotkanie rośliny z wszystkożercą
    constexpr auto encounter_result2 = encounter(human, wheat);
    constexpr auto human_result2 = get<0>(encounter_result2);
    constexpr auto wheat_result2 = get<1>(encounter_result2);
    constexpr auto child_result2 = get<2>(encounter_result2);
    static_assert(human_result2.get_vitality() == 104);
    static_assert(wheat_result2.get_vitality() == 0);
    static_assert(!child_result2.has_value());

    // Spotkanie roślinożercy z roślinożercą o różnych gatunkach
    constexpr auto encounter_result3 = encounter(male_giraffe, panda);
    constexpr auto giraffe_result3 = get<0>(encounter_result3);
    constexpr auto panda_result3 = get<1>(encounter_result3);
    constexpr auto child_result3 = get<2>(encounter_result3);
    static_assert(giraffe_result3.get_vitality() == 55);
    static_assert(panda_result3.get_vitality() == 21);
    static_assert(!child_result3.has_value());

    // Spotkanie roślinożerców o tych samych gatunkach
    constexpr auto encounter_result4 = encounter(male_giraffe, female_giraffe);
    constexpr auto male_giraffe_result4 = get<0>(encounter_result4);
    constexpr auto female_giraffe_result4 = get<1>(encounter_result4);
    constexpr auto child_result4 = get<2>(encounter_result4);
    static_assert(male_giraffe_result4.get_vitality() == 55);
    static_assert(female_giraffe_result4.get_vitality() == 33);
    static_assert(child_result4->get_vitality() == 44);
    static_assert(child_result4->get_species() == 4);

    // Spotkanie mięsożercy z roślinożercą
    constexpr auto encounter_result5 = encounter(lion, male_giraffe);
    constexpr auto lion_result5 = get<0>(encounter_result5);
    constexpr auto male_giraffe_result5 = get<1>(encounter_result5);
    constexpr auto child_result5 = get<2>(encounter_result5);
    static_assert(lion_result5.get_vitality() == 227);
    static_assert(male_giraffe_result5.get_vitality() == 0);
    static_assert(!child_result5.has_value());

    // Spotkanie roślinożercy z mięsożercą
    constexpr auto encounter_result6 = encounter(panda, lion);
    constexpr auto panda_result6 = get<0>(encounter_result6);
    constexpr auto lion_result6 = get<1>(encounter_result6);
    constexpr auto child_result6 = get<2>(encounter_result6);
    static_assert(panda_result6.get_vitality() == 0);
    static_assert(lion_result6.get_vitality() == 210);
    static_assert(!child_result6.has_value());

    // Wyniszczająca walka dwóch mięsożerców
    constexpr auto encounter_result7 = encounter(black_panther, lion);
    constexpr auto black_panther_result7 = get<0>(encounter_result7);
    constexpr auto lion_result7 = get<1>(encounter_result7);
    constexpr auto child_result7 = get<2>(encounter_result7);
    static_assert(black_panther_result7.get_vitality() == 0);
    static_assert(lion_result7.get_vitality() == 0);
    static_assert(!child_result7.has_value());

    // Spotkanie wszystkożercy z silnym roślinożercą
    constexpr auto encounter_result8 = encounter(human, rhino);
    constexpr auto human_result8 = get<0>(encounter_result8);
    constexpr auto rhino_result8 = get<1>(encounter_result8);
    constexpr auto child_result8 = get<2>(encounter_result8);
    static_assert(human_result8.get_vitality() == 100);
    static_assert(rhino_result8.get_vitality() == 300);
    static_assert(!child_result8.has_value());

    // Spotkanie roślinożercy ze zjedzoną rośliną
    constexpr auto encounter_result9 = encounter(panda, wheat_result1);
    constexpr auto panda_result9 = get<0>(encounter_result9);
    constexpr auto wheat_result1_9 = get<1>(encounter_result9);
    constexpr auto child_result9 = get<2>(encounter_result9);
    static_assert(panda_result9.get_vitality() == 21);
    static_assert(wheat_result1_9.get_vitality() == 0);
    static_assert(!child_result9.has_value());

    return 0;
}
