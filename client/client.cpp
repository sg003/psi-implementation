#include "../net.hpp"
#include "../gm.hpp"

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <random>
#include <algorithm>

const uint64_t SEED = 4;

static std::vector<std::string> load_dataset(const std::string& path, size_t sample_size, uint64_t seed) {
    std::ifstream in(path);
    if (!in) throw std::runtime_error("Failed to open dataset: " + path);

    std::vector<std::string> universe;
    std::string line;
    while (std::getline(in, line))
        if (!line.empty()) universe.push_back(line);

    if (sample_size > universe.size())
        throw std::runtime_error("Sample size exceeds universe size.");

    std::mt19937_64 rng(seed);
    std::shuffle(universe.begin(), universe.end(), rng);
    universe.resize(sample_size);
    return universe;
}

int  client_psi_ca (sock_t fd, GM& gm, const GMPublicKey& pk, const GMSecretKey& sk, const std::vector<std::string>& Y, uint32_t v);
void client_psi    (sock_t fd, GM& gm, const GMPublicKey& pk, const GMSecretKey& sk, const std::vector<std::string>& Y, uint32_t v);
void client_apsi_ca(sock_t fd, GM& gm, const GMPublicKey& pk, const GMSecretKey& sk, const std::vector<std::string>& Y, uint32_t v);
void client_apsi   (sock_t fd, GM& gm, const GMPublicKey& pk, const GMSecretKey& sk, const std::vector<std::string>& Y, uint32_t v);

GM gm;
GMPublicKey pk;
GMSecretKey sk;

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: ./client <protocol>\n";
        std::cerr << "Protocols: psi_ca | psi | apsi_ca | apsi\n";
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

    std::vector<std::string> Y = load_dataset("cards.txt", 50, SEED);

    gm.keygen(2048, pk, sk);
    send_mpz(fd, pk.n);
    send_mpz(fd, pk.u);
    uint32_t v;
    recv_all(fd, &v, sizeof(v));
    std::cout << "Received v from server.\n";
    if      (protocol == "psi_ca") {
        int cardinality = client_psi_ca(fd, gm, pk, sk, Y, v);
        std::cout << "Cardinality: " << cardinality << "\n";
    }
    else if (protocol == "psi")     client_psi(fd, gm, pk, sk, Y, v);
    else if (protocol == "apsi_ca") client_apsi_ca(fd, gm, pk, sk, Y, v);
    else if (protocol == "apsi")    client_apsi(fd, gm, pk, sk, Y, v);
    else { std::cerr << "Unknown protocol: " << protocol << "\n"; return 1; }

    CLOSE_SOCKET(fd);
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
