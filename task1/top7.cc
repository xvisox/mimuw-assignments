#include <iostream>
#include <regex>
#include <unordered_map>
#include <unordered_set>
#include <set>

using namespace std;

using sstream = stringstream;
using songId_t = uint32_t;
using voteNum_t = uint64_t;
using rank_t = int8_t;
using voteCount_t = pair<voteNum_t, songId_t>;

constexpr rank_t CHART_SIZE = 7;

auto cmp = [](voteCount_t v1, voteCount_t v2) {
    if (v1.first != v2.first) {
        return v1.first < v2.first;
    } else {
        return v1.second > v2.second;
    }
};

using songRank_t = unordered_map<songId_t, rank_t>;
using songPoll_t = unordered_map<songId_t, voteNum_t>;
using songComp_t = unordered_set<songId_t>;
using songChart_t = set<pair<voteNum_t, songId_t>, decltype(cmp)>;

void updatePoll(songPoll_t &poll, songComp_t &vote) {
    for (auto songId: vote) {
        poll[songId]++;
    }
}

void updateGenPoll(songPoll_t &genPoll, songChart_t &chart) {
    size_t pointNum = CHART_SIZE - chart.size() + 1;

    for (auto [points, songId]: chart) {
        genPoll[songId] += pointNum;
        pointNum++;
    }
}

songChart_t createChart(songPoll_t &poll) {
    // Records pairs (amount of votes, song ID) in non-decreasing order by the
    // amount of votes and in decreasing order by song IDs.
    songChart_t chart;

    for (auto [songId, voteNum]: poll) {
        if (chart.size() < CHART_SIZE) {
            chart.insert({voteNum, songId});
        } else {
            // Song, which in a given moment has the least votes, the greatest ID
            // and is on the chart.
            auto worstSong = *chart.begin();
            if (cmp(worstSong, {voteNum, songId})) {
                chart.erase(chart.begin());
                chart.insert({voteNum, songId});
            }
        }
    }

    return chart;
}

void printChart(songChart_t &chart, songRank_t &archive) {
    songId_t songId;
    rank_t rank = 1;

    for (auto it = chart.rbegin(); it != chart.rend(); it++) {
        songId = it->second;
        if (archive.find(songId) != archive.end()) {
            cout << songId << ' ' << archive[songId] - rank << "\n";
        } else {
            cout << songId << " -\n";
        }
        rank++;
    }
}

void deleteSongs(songChart_t &chart, songRank_t &archive, songComp_t &delSongs) {
    songId_t songId;

    for (const auto &it: chart) {
        songId = it.second;
        // We label the songs in the archive, which are on the new chart.
        if (archive.find(songId) != archive.end()) {
            archive[songId] = 0;
        }
    }
    for (auto &it: archive) {
        // We delete the songs, which were not labelled.
        if (it.second != 0) {
            delSongs.insert(it.first);
        }
    }
}

songRank_t createArchive(songChart_t &chart) {
    auto rank = (rank_t) chart.size();
    songRank_t archive;

    for (auto [voteNum, songId]: chart) {
        archive[songId] = rank;
        rank--;
    }

    return archive;
}

bool isValidVote(sstream &ss, songComp_t &comp, songComp_t &del, songId_t currMax) {
    songId_t songId;

    while (ss >> songId) {
        if (songId > currMax)
            return false;
        if (comp.find(songId) != comp.end() || del.find(songId) != del.end()) {
            return false;
        }
        comp.insert(songId);
    }

    return true;
}

void printError(const string &input, size_t line) {
    cerr << "Error in line " << line << ": " << input;
}

bool isValidMax(songId_t newMax, songId_t currMax) {
    return currMax <= newMax;
}

// Returns true, if casting votes was successful, false otherwise.
bool castVotes(sstream &ss, songPoll_t &poll, songComp_t &del, songId_t currMax) {
    songComp_t comp;

    if (isValidVote(ss, comp, del, currMax)) {
        updatePoll(poll, comp);
        return true;
    }

    return false;
}

bool startNewPoll(sstream &ss, songPoll_t &genPoll, songComp_t &del, songPoll_t &poll,
                  songRank_t &archive, songId_t &currMax) {
    string command;
    songId_t newMax;
    ss >> command >> newMax;

    if (isValidMax(newMax, currMax)) {
        if (currMax != 0) {
            songChart_t chart = createChart(poll);
            updateGenPoll(genPoll, chart);
            printChart(chart, archive);
            deleteSongs(chart, archive, del);
            archive = createArchive(chart);
            poll.clear();
        }
        currMax = newMax;
        return true;
    }

    return false;
}

void printSummary(songRank_t &genArchive, songPoll_t &genPoll) {
    songChart_t genChart = createChart(genPoll);
    printChart(genChart, genArchive);
    genArchive = createArchive(genChart);
}

// Checks, whether the give line has only whitespaces.
bool isEmptyLine(string &line) {
    auto isBlankFunc = [](char c) { return isblank(c); };
    return line.empty() || all_of(line.begin(), line.end(), isBlankFunc);
}

int main() {
    regex voteExpr(R"(\s*([1-9][0-9]{0,7}\s+)+)");
    regex newPollExpr(R"(\s*NEW\s+[1-9][0-9]{0,7}\s*)");
    regex summaryExpr(R"(\s*TOP\s*)");

    size_t lineNum = 1;
    string line;

    // Compilation of songs, which were on the chart at some point and did not
    // end up on the following one.
    songComp_t delSongs;

    // Dictionaries, where the key is the song ID and the value is the amount of
    // votes / points.
    songPoll_t poll, genPoll;

    // Dictionaries, where the key is the song ID and the value is the rank on
    // the last chart.
    songRank_t chartArchive, genChartArchive;

    // The maximum valid song ID.
    songId_t currMax = 0;

    while (getline(cin, line)) {
        // Ignore empty lines.
        if (!isEmptyLine(line)) {
            line += '\n';
            stringstream ss;
            ss.str(line);
            if (regex_match(line, voteExpr)) {
                if (!castVotes(ss, poll, delSongs, currMax)) {
                    printError(line, lineNum);
                }
            } else if (regex_match(line, newPollExpr)) {
                if (!startNewPoll(ss, genPoll, delSongs, poll, chartArchive, currMax)) {
                    printError(line, lineNum);
                }
            } else if (regex_match(line, summaryExpr)) {
                printSummary(genChartArchive, genPoll);
            } else {
                printError(line, lineNum);
            }
        }
        lineNum++;
    }

    return 0;
}
