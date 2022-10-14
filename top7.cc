#include <unordered_map>
#include <unordered_set>
#include <set>
#include <iostream>
#include <regex>

#define endl '\n'
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

void aktualizujGlosowanie(umap32_64 &glosowanie, uset_32 &wybranePiosenki) {
    for (uint32_t piosenka: wybranePiosenki) {
        glosowanie[piosenka]++;
    }
}

void aktualizujGlosowanieOgolne(umap32_64 &glosowanieOgolne, oset_pair_64_32 &notowanie) {
    int ilePkt = ROZMIAR_NOTOWANIA - notowanie.size() + 1;
    for (auto [punkty, piosenka]: notowanie) {
        glosowanieOgolne[piosenka] += ilePkt;
        ilePkt++;
    }
}

oset_pair_64_32 stworzNotowanie(umap32_64 &glosowanie) {
    oset_pair_64_32 notowanie;
    for (auto [piosenka, glosy]: glosowanie) {
        if (notowanie.size() < ROZMIAR_NOTOWANIA) {
            notowanie.insert({glosy, piosenka});
        } else {
            // Piosenka, która w danym momencie posiada najmniej punktów i jest w notowaniu.
            auto najgorszaPiosenka = *notowanie.begin();
            if (cmp(najgorszaPiosenka, {glosy, piosenka})) {
                notowanie.erase(notowanie.begin());
                notowanie.insert({glosy, piosenka});
            }
        }
    }
    return notowanie;
}

void wypiszNotowanie(oset_pair_64_32 &notowanie, umap32_8 &archiwum) {
    uint32_t piosenka;
    int8_t miejsce = 1;
    for (auto it = notowanie.rbegin(); it != notowanie.rend(); it++) {
        piosenka = it->second;
        if (archiwum.find(piosenka) != archiwum.end()) {
            cout << piosenka << ' ' << archiwum[piosenka] - miejsce << endl;
        } else {
            cout << piosenka << " -" << endl;
        }
        miejsce++;
    }
}

void usunPiosenki(oset_pair_64_32 &notowanie, umap32_8 &archiwum, uset_32 &usunietePiosenki) {
    uint32_t piosenka;
    for (const auto &it: notowanie) {
        piosenka = it.second;
        // Oznaczamy w archiwum piosenki, które znalazły się w nowym notowaniu.
        if (archiwum.find(piosenka) != archiwum.end()) {
            archiwum[piosenka] = 0;
        }
    }
    for (auto &it: archiwum) {
        // Usuwamy piosenki, które nie zostały oznaczone jako znalezione.
        if (it.second != 0) {
            usunietePiosenki.insert(it.first);
        }
    }
}

umap32_8 stworzArchiwum(oset_pair_64_32 &notowanie) {
    int8_t miejsce = notowanie.size();
    umap32_8 archiwum;
    for (auto [glosy, piosenka]: notowanie) {
        archiwum[piosenka] = miejsce;
        miejsce--;
    }
    return archiwum;
}

bool prawidloweGlosy(stringstream &ss, uset_32 &wybranePiosenki, uset_32 &usunietePiosenki, uint32_t aktualnyMax) {
    uint32_t glos;
    while (ss >> glos) {
        if (glos > aktualnyMax) return false;

        if (wybranePiosenki.find(glos) == wybranePiosenki.end() && usunietePiosenki.find(glos) == usunietePiosenki.end()) {
            wybranePiosenki.insert(glos);
        } else {
            return false;
        }
    }
    return true;
}

void printError(const string &input, size_t line) {
    cerr << "Error in line " << line << ": " << input << endl;
}

bool prawidlowyMax(uint32_t nowyMax, uint32_t aktualnyMax) {
    return aktualnyMax <= nowyMax;
}

// Funkcja zwraca true, jeśli oddanie głosów się powiodło, w.p.p. false;
bool oddajGlosy(stringstream &ss, umap32_64 &glosowanie, uset_32 &usunietePiosenki, uint32_t aktualnyMax) {
    unordered_set<uint32_t> wybranePiosenki;
    if (prawidloweGlosy(ss, wybranePiosenki, usunietePiosenki, aktualnyMax)) {
        aktualizujGlosowanie(glosowanie, wybranePiosenki);
        return true;
    }
    return false;
}

// TODO: trzeba ładnie złamać linie (ja nie wiem jak) i użyłem wskaźnika (a nie wiem czy można)
bool rozpocznijNoweGlosowanie(stringstream &ss, umap32_64 &glosowanieOgolne, uset_32 &usunietePiosenki,
                              umap32_64 &glosowanie, umap32_8 &archiwumNotowania, uint32_t *aktualnyMax) {
    string komenda;
    uint32_t nowyMax;
    ss >> komenda >> nowyMax;
    if (prawidlowyMax(nowyMax, *aktualnyMax)) {
        if (*aktualnyMax != 0) {
            oset_pair_64_32 notowanie = stworzNotowanie(glosowanie);
            aktualizujGlosowanieOgolne(glosowanieOgolne, notowanie);
            wypiszNotowanie(notowanie, archiwumNotowania);
            usunPiosenki(notowanie, archiwumNotowania, usunietePiosenki);
            archiwumNotowania = stworzArchiwum(notowanie);
            glosowanie.clear();
        }
        *aktualnyMax = nowyMax;
        return true;
    }
    return false;
}

void wypiszNotowanieOgolne(umap32_8 &archiwumOgolne, umap32_64 &glosowanieOgolne) {
    oset_pair_64_32 notowanieOgolne = stworzNotowanie(glosowanieOgolne);
    wypiszNotowanie(notowanieOgolne, archiwumOgolne);
    archiwumOgolne = stworzArchiwum(notowanieOgolne);
}

int main() {
    regex voteRegex(R"(\s*([1-9][0-9]{0,7}\s*)+)");
    regex newVoteRegex(R"(\s*NEW\s+[1-9][0-9]{0,7}\s*)");
    regex topRegex(R"(\s*TOP\s*)");

    size_t line = 1;
    string input;

    uset_32 usunietePiosenki;
    umap32_64 glosowanie, glosowanieOgolne;
    umap32_8 archiwumNotowania, archiwumOgolne;

    uint32_t aktualnyMax = 0;

    while (getline(cin, input)) {
        if (!input.empty()) {
            stringstream ss;
            ss.str(input);
            if (regex_match(input, voteRegex)) {
                if (!oddajGlosy(ss, glosowanie, usunietePiosenki, aktualnyMax)) {
                    printError(input, line);
                }
            } else if (regex_match(input, newVoteRegex)) {
                if (!rozpocznijNoweGlosowanie(ss, glosowanieOgolne, usunietePiosenki, glosowanie, archiwumNotowania, &aktualnyMax)) {
                    printError(input, line);
                }
            } else if (regex_match(input, topRegex)) {
                wypiszNotowanieOgolne(archiwumOgolne, glosowanieOgolne);
            } else {
                printError(input, line++);
            }
        }
        line++;
    }
    return 0;
}
