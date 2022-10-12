#include <bits/stdc++.h>

using namespace std;

int main() {
    string input;
    regex voteRegex(R"(\s*([1-9][0-9]*\s*)+)");
    regex newVoteRegex(R"(\s*NEW\s+[1-9][0-9]{0,7}\s*)");
    regex topRegex(R"(\s*TOP\s*)");

    size_t line = 0;
    while (getline(cin, input)) {
        if (!input.empty()) {
            if (regex_match(input, voteRegex)) {
                // check for duplicates
            } else if (regex_match(input, newVoteRegex)) {
                // check if newMAX >= MAX
            } else if (regex_match(input, topRegex)) {
                // no additional conditions?
            } else {
                cerr << "Error in line " << line << ": " << input << endl;
            }
            line++;
        }
    }


    return 0;
}
