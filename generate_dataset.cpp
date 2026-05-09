#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <random>
#include <algorithm>
#include <stdexcept>

static std::string luhn_complete(const std::string& fifteen) {
    int sum = 0;
    for (int i = 0; i < 15; ++i) {
        int d = fifteen[i] - '0';
        if (i % 2 == 0) {
            d *= 2;
            if (d > 9) d -= 9;
        }
        sum += d;
    }
    return fifteen + char('0' + (10 - (sum % 10)) % 10);
}

static std::vector<std::string> generate_universe(size_t n, uint64_t seed) {
    std::mt19937_64 rng(seed);
    std::uniform_int_distribution<uint64_t> dist(0, 99999999999999ULL);

    std::vector<std::string> universe;
    universe.reserve(n);

    do{
        while (universe.size() < n) {
            // 14 random digits padded to 14 chars, prefixed with "4" = 15 digits
            std::string suffix = std::to_string(dist(rng));
            suffix = std::string(14 - suffix.size(), '0') + suffix;
            std::string card = luhn_complete("4" + suffix);
            universe.push_back(card);
        }

        // deduplicate
        std::sort(universe.begin(), universe.end());
        universe.erase(std::unique(universe.begin(), universe.end()), universe.end());
    } while(universe.size() < n);
    

    return universe;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: ./generate_dataset <count> <output_file>\n";
        std::cerr << "Example: ./generate_dataset 1000 cards.txt\n";
        return 1;
    }

    size_t n = std::stoull(argv[1]);
    std::string path = argv[2];

    auto universe = generate_universe(n, /*seed=*/42);

    std::ofstream out(path);
    if (!out) { std::cerr << "Failed to open " << path << "\n"; return 1; }

    for (const auto& card : universe)
        out << card << "\n";

    std::cout << "Generated " << universe.size() << " cards → " << path << "\n";
    return 0;
}
