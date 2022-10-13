#include <bits/stdc++.h>
#include <sstream>

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

void oddajGlos(umap32_64 &glosowanie, uset_32 &wybranePiosenki) {
    for (uint32_t piosenka: wybranePiosenki) {
        glosowanie[piosenka]++;
    }
}

oset_pair_64_32 stworzNotowanie(umap32_64 &glosowanie) {
    oset_pair_64_32 notowanie;
    for (auto [piosenka, glosy]: glosowanie) {
        if (notowanie.size() < ROZMIAR_NOTOWANIA) {
            notowanie.insert({glosy, piosenka});
        } else {
            auto pierwsza = *notowanie.begin();
            if (cmp(pierwsza, {glosy, piosenka})) {
                notowanie.erase(notowanie.begin());
                notowanie.insert({glosy, piosenka});
            }
        }
    }
    return notowanie;
}

void aktualizujrankingOgolny(umap32_64 &rankingOgolny, oset_pair_64_32 &notowanie) {
    int i = 1;
    for (auto [punkty, piosenka]: notowanie) {
        rankingOgolny[piosenka] += i;
        i++;
    }
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
    cout << endl;
}

void usunPiosenki(oset_pair_64_32 &notowanie, umap32_8 &archiwum, uset_32 &usuniete) {
    uint32_t piosenka;
    for (const auto &it: notowanie) {
        piosenka = it.second;
        if (archiwum.find(piosenka) != archiwum.end()) {
            archiwum[piosenka] = 0;
        }
    }
    for (auto &it: archiwum) {
        if (it.second != 0) {
            usuniete.insert(it.first);
        }
    }
}

umap32_8 stworzArchiwum(oset_pair_64_32 &notowanie) {
    uint8_t miejsce = notowanie.size();
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

int main() {
    regex voteRegex(R"(\s*([1-9][0-9]{0,7}\s*)+)");
    regex newVoteRegex(R"(\s*NEW\s+[1-9][0-9]{0,7}\s*)");
    regex topRegex(R"(\s*TOP\s*)");

    size_t line = 1;
    string input;

    uset_32 usunietePiosenki;
    umap32_64 glosowanie, rankingOgolny;
    umap32_8 archiwumNotowania, archiwumOgolne;

    uint32_t aktualnyMax = 0;

    while (getline(cin, input)) {
        if (!input.empty()) {
            stringstream ss;
            ss.str(input);
            if (regex_match(input, voteRegex)) {
                unordered_set<uint32_t> wybranePiosenki;
                if (prawidloweGlosy(ss, wybranePiosenki, usunietePiosenki, aktualnyMax)) {
                    oddajGlos(glosowanie, wybranePiosenki);
                } else {
                    printError(input, line);
                    continue;
                }
            } else if (regex_match(input, newVoteRegex)) {
                string komenda;
                ss >> komenda;
                uint32_t nowyMax;
                ss >> nowyMax;
                if (prawidlowyMax(nowyMax, aktualnyMax)) {
                    if (aktualnyMax != 0) {
                        oset_pair_64_32 notowanie = stworzNotowanie(glosowanie);
                        aktualizujrankingOgolny(rankingOgolny, notowanie);
                        wypiszNotowanie(notowanie, archiwumNotowania);
                        usunPiosenki(notowanie, archiwumNotowania, usunietePiosenki);
                        archiwumNotowania = stworzArchiwum(notowanie);
                        glosowanie.clear();
                    }
                    aktualnyMax = nowyMax;
                } else {
                    printError(input, line);
                    continue;
                }
            } else if (regex_match(input, topRegex)) {
                oset_pair_64_32 notowanieOgolne = stworzNotowanie(rankingOgolny);
                wypiszNotowanie(notowanieOgolne, archiwumOgolne);
            } else {
                printError(input, line);
            }
        }
        line++;
    }
    return 0;
}
