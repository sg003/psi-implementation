#include "../config.hpp"
#include "../net.hpp"
#include "../gm.hpp"
#include "../timing.hpp"

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <random>
#include <algorithm>
#include <stdexcept>


static std::vector<std::string> load_dataset(const std::string& path, size_t sample_size, uint64_t seed) {
    std::ifstream in(path);
    if (!in) throw std::runtime_error("Failed to open dataset: " + path);

    std::vector<std::string> universe;
    std::string line;
    while (std::getline(in, line))
        if (!line.empty()) universe.push_back(line);

    if (UNIVERSE_SIZE > 0 && UNIVERSE_SIZE < universe.size())
        universe.resize(UNIVERSE_SIZE);

    if (sample_size > universe.size())
        throw std::runtime_error("Sample size exceeds universe size.");

    std::mt19937_64 rng(seed);
    std::shuffle(universe.begin(), universe.end(), rng);
    universe.resize(sample_size);
    return universe;
}

int                      client_psi_ca (sock_t fd, GM& gm, const GMPublicKey& pk, const GMSecretKey& sk, const std::vector<std::string>& Y, uint32_t v, ClientTiming* timing = nullptr);
std::vector<std::string> client_psi    (sock_t fd, GM& gm, const GMPublicKey& pk, const GMSecretKey& sk, const std::vector<std::string>& Y, uint32_t v, ClientTiming* timing = nullptr);
int                      client_apsi_ca(sock_t fd, GM& gm, const GMPublicKey& pk, const GMSecretKey& sk, const std::vector<std::string>& Y, uint32_t v, const std::string& ca_host, int ca_port, ClientTiming* timing = nullptr);
std::vector<std::string> client_apsi   (sock_t fd, GM& gm, const GMPublicKey& pk, const GMSecretKey& sk, const std::vector<std::string>& Y, uint32_t v, const std::string& ca_host, int ca_port, ClientTiming* timing = nullptr);

GM gm;
GMPublicKey pk;
GMSecretKey sk;

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: ./client <protocol> [ca_host ca_port]\n";
        std::cerr << "Protocols: psi_ca | psi | apsi_ca | apsi\n";
        std::cerr << "For apsi_ca or apsi, provide CA host and port as extra arguments.\n";
        return 1;
    }
    std::string protocol = argv[1];

#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    sock_t fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(PSI_PORT);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (connect(fd, (sockaddr*)&addr, sizeof(addr)) < 0) { perror("connect"); return 1; }
    std::cout << "Connected to server.\n";

    std::vector<std::string> Y = load_dataset(DATASET_PATH, CLIENT_SET_SIZE, CLIENT_SEED);
    { std::ofstream f("client_set.txt"); for (const auto& s : Y) f << s << "\n"; }

    gm.keygen(GM_KEY_BITS, pk, sk);
    send_mpz(fd, pk.n);
    send_mpz(fd, pk.u);
    uint32_t v;
    recv_all(fd, &v, sizeof(v));
    std::cout << "Received v from server.\n";

    if (protocol == "psi_ca") {
        int cardinality = client_psi_ca(fd, gm, pk, sk, Y, v);
        std::cout << "Cardinality: " << cardinality << "\n";
    }
    else if (protocol == "psi") {
        auto intersection = client_psi(fd, gm, pk, sk, Y, v);
        std::cout << "Intersection size: " << intersection.size() << "\n";
        std::ofstream f("psi_intersection.txt");
        for (const auto& e : intersection) {
            std::cout << "  " << e << "\n";
            f << e << "\n";
        }
        std::cout << "Intersection written to psi_intersection.txt\n";
    }
    else if (protocol == "apsi_ca") {
        if (argc < 4) {
            std::cerr << "For apsi_ca, provide CA host and port as arguments.\n";
            CLOSE_SOCKET(fd);
            return 1;
        }
        client_apsi_ca(fd, gm, pk, sk, Y, v, argv[2], std::stoi(argv[3]));
    }
    else if (protocol == "apsi") {
        if (argc < 4) {
            std::cerr << "For apsi_ca, provide CA host and port as arguments.\n";
            CLOSE_SOCKET(fd);
            return 1;
        }
        auto intersection = client_apsi(fd, gm, pk, sk, Y, v, argv[2], std::stoi(argv[3]));
        std::cout << "Intersection size: " << intersection.size() << "\n";
        std::ofstream f("apsi_intersection.txt");
        for (const auto& e : intersection) {
            std::cout << "  " << e << "\n";
            f << e << "\n";
        }
        std::cout << "Intersection written to apsi_intersection.txt\n";
    }
    else { std::cerr << "Unknown protocol: " << protocol << "\n"; CLOSE_SOCKET(fd); return 1; }

    CLOSE_SOCKET(fd);
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}