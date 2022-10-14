#include <iostream>
#include <regex>
#include <unordered_map>
#include <unordered_set>
#include <set>

#define ROZMIAR_NOTOWANIA 7

using namespace std;
using pair_64_32 = pair<uint64_t, uint32_t>;

auto cmp = [](pair_64_32 a, pair_64_32 b) {
    if (a.first != b.first) {
        return a.first < b.first;
    } else {
        return a.second > b.second;
    }
};

using umap32_8 = unordered_map<uint32_t, int8_t>;
using umap32_64 = unordered_map<uint32_t, uint64_t>;
using uset_32 = unordered_set<uint32_t>;
using oset_pair_64_32 = set<pair<uint64_t, uint32_t>, decltype(cmp)>;

void aktualizujGlosowanie(umap32_64 &glosowanie, uset_32 &glos) {
    for (uint32_t numerUtworu: glos) {
        glosowanie[numerUtworu]++;
    }
}

void aktualizujGlosowanieOgolne(umap32_64 &glosowanieOgolne, oset_pair_64_32 &notowanie) {
    size_t ilePkt = ROZMIAR_NOTOWANIA - notowanie.size() + 1;

    for (auto [punkty, numerUtworu]: notowanie) {
        glosowanieOgolne[numerUtworu] += ilePkt;
        ilePkt++;
    }
}

oset_pair_64_32 stworzNotowanie(umap32_64 &glosowanie) {
    // Zapisuje pary (liczba głosów, numer utworu) w kolejności niemalejącej według
    // głosów i malejącej według numerów utworów.
    oset_pair_64_32 notowanie;

    for (auto [numerUtworu, liczbaGlosow]: glosowanie) {
        if (notowanie.size() < ROZMIAR_NOTOWANIA) {
            notowanie.insert({liczbaGlosow, numerUtworu});
        } else {
            // Utwór, który w danym momencie posiada najmniej głosów,
            // ma największy numer i jest w notowaniu.
            auto najgorszyUtwor = *notowanie.begin();
            if (cmp(najgorszyUtwor, {liczbaGlosow, numerUtworu})) {
                notowanie.erase(notowanie.begin());
                notowanie.insert({liczbaGlosow, numerUtworu});
            }
        }
    }

    return notowanie;
}

void wypiszNotowanie(oset_pair_64_32 &notowanie, umap32_8 &archiwum) {
    uint32_t numerUtworu;
    int8_t miejsce = 1;

    for (auto it = notowanie.rbegin(); it != notowanie.rend(); it++) {
        numerUtworu = it->second;
        if (archiwum.find(numerUtworu) != archiwum.end()) {
            cout << numerUtworu << ' ' << archiwum[numerUtworu] - miejsce << endl;
        } else {
            cout << numerUtworu << " -" << endl;
        }
        miejsce++;
    }
}

void usunUtwory(oset_pair_64_32 &notowanie, umap32_8 &archiwum, uset_32 &usunieteUtwory) {
    uint32_t numerUtworu;

    for (const auto &it: notowanie) {
        numerUtworu = it.second;
        // Oznaczamy w archiwum utwory, które znalazły się w nowym notowaniu.
        if (archiwum.find(numerUtworu) != archiwum.end()) {
            archiwum[numerUtworu] = 0;
        }
    }
    for (auto &it: archiwum) {
        // Usuwamy utwory, które nie zostały oznaczone jako znalezione.
        if (it.second != 0) {
            usunieteUtwory.insert(it.first);
        }
    }
}

umap32_8 stworzArchiwum(oset_pair_64_32 &notowanie) {
    auto miejsce = (int8_t) notowanie.size();
    umap32_8 archiwum;

    for (auto [liczbaGlosow, numerUtworu]: notowanie) {
        archiwum[numerUtworu] = miejsce;
        miejsce--;
    }

    return archiwum;
}

bool prawidlowyGlos(stringstream &ss, uset_32 &wybraneUtwory,
                    uset_32 &usunieteUtwory, uint32_t aktualnyMax) {
    uint32_t numerUtworu;

    while (ss >> numerUtworu) {
        if (numerUtworu > aktualnyMax)
            return false;
        if (wybraneUtwory.find(numerUtworu) != wybraneUtwory.end() ||
            usunieteUtwory.find(numerUtworu) != usunieteUtwory.end()) {
            return false;
        }
        wybraneUtwory.insert(numerUtworu);
    }

    return true;
}

void wypiszError(const string &input, size_t line) {
    cerr << "Error in line " << line << ": " << input << endl;
}

bool prawidlowyMax(uint32_t nowyMax, uint32_t aktualnyMax) {
    return aktualnyMax <= nowyMax;
}

// Funkcja zwraca true, jeśli oddanie głosów się powiodło, w.p.p. false.
bool oddajGlosy(stringstream &ss, umap32_64 &glosowanie, uset_32 &usunieteUtwory,
                uint32_t aktualnyMax) {
    unordered_set<uint32_t> wybraneUtwory;

    if (prawidlowyGlos(ss, wybraneUtwory, usunieteUtwory, aktualnyMax)) {
        aktualizujGlosowanie(glosowanie, wybraneUtwory);
        return true;
    }

    return false;
}

bool rozpocznijNoweGlosowanie(stringstream &ss, umap32_64 &glosowanieOgolne,
                              uset_32 &usunieteUtwory, umap32_64 &glosowanie,
                              umap32_8 &archiwumNotowania, uint32_t &aktualnyMax) {
    string komenda;
    uint32_t nowyMax;
    ss >> komenda >> nowyMax;

    if (prawidlowyMax(nowyMax, aktualnyMax)) {
        if (aktualnyMax != 0) {
            oset_pair_64_32 notowanie = stworzNotowanie(glosowanie);
            aktualizujGlosowanieOgolne(glosowanieOgolne, notowanie);
            wypiszNotowanie(notowanie, archiwumNotowania);
            usunUtwory(notowanie, archiwumNotowania, usunieteUtwory);
            archiwumNotowania = stworzArchiwum(notowanie);
            glosowanie.clear();
        }
        aktualnyMax = nowyMax;
        return true;
    }

    return false;
}

void wypiszPodsumowanie(umap32_8 &archiwumOgolne, umap32_64 &glosowanieOgolne) {
    oset_pair_64_32 notowanieOgolne = stworzNotowanie(glosowanieOgolne);
    wypiszNotowanie(notowanieOgolne, archiwumOgolne);
    archiwumOgolne = stworzArchiwum(notowanieOgolne);
}

int main() {
    regex wzorzecGlosu(R"(\s*([1-9][0-9]{0,7}\s*)+)");
    regex wzorzecNowegoGlosowania(R"(\s*NEW\s+[1-9][0-9]{0,7}\s*)");
    regex wzorzecPodsumowania(R"(\s*TOP\s*)");

    size_t numerLinii = 1;
    string liniaWejscia;

    // Zbiór utworów, które były notowane w jakimś notowaniu listy przebojów i
    // nie znalazły się w kolejnym notowaniu.
    uset_32 usunieteUtwory;

    // Słowniki, gdzie klucz to numer utworu, a wartość to liczba głosów / punktów.
    umap32_64 glosowanie, glosowanieOgolne;

    // Słowniki, gdzie klucz to numer utworu, a wartość to miejsce w ostatnim
    // notowaniu.
    umap32_8 archiwumNotowania, archiwumPodsumowania;

    // Maksymalny numer utworu, który jest dopuszczalny.
    uint32_t aktualnyMax = 0;

    while (getline(cin, liniaWejscia)) {
        // Ignoruj puste linie.
        if (!liniaWejscia.empty()) {
            stringstream ss;
            ss.str(liniaWejscia);
            if (regex_match(liniaWejscia, wzorzecGlosu)) {
                if (!oddajGlosy(ss, glosowanie, usunieteUtwory, aktualnyMax)) {
                    wypiszError(liniaWejscia, numerLinii);
                }
            } else if (regex_match(liniaWejscia, wzorzecNowegoGlosowania)) {
                if (!rozpocznijNoweGlosowanie(ss, glosowanieOgolne, usunieteUtwory,
                                              glosowanie, archiwumNotowania,
                                              aktualnyMax)) {
                    wypiszError(liniaWejscia, numerLinii);
                }
            } else if (regex_match(liniaWejscia, wzorzecPodsumowania)) {
                wypiszPodsumowanie(archiwumPodsumowania, glosowanieOgolne);
            } else {
                wypiszError(liniaWejscia, numerLinii++);
            }
        }
        numerLinii++;
    }

    return 0;
}
