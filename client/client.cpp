#include "../net.hpp"
#include "../gm.hpp"

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <random>
#include <algorithm>
#include <stdexcept>

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
void client_apsi_ca(sock_t fd, GM& gm, const GMPublicKey& pk, const GMSecretKey& sk, const std::vector<std::string>& Y, uint32_t v, const std::string& ca_host, int ca_port);
void client_apsi   (sock_t fd, GM& gm, const GMPublicKey& pk, const GMSecretKey& sk, const std::vector<std::string>& Y, uint32_t v, const std::string& ca_host, int ca_port);

GM gm;
GMPublicKey pk;
GMSecretKey sk;

static sock_t connect_to_server(const std::string& host = "127.0.0.1", uint16_t port = PSI_PORT) {
    sock_t fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) throw std::runtime_error("socket() failed");
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        CLOSE_SOCKET(fd);
        throw std::runtime_error("inet_pton() failed for host: " + host);
    }
    if (connect(fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        CLOSE_SOCKET(fd);
        throw std::runtime_error("connect() failed");
    }
    return fd;
}

static uint32_t send_public_key_and_recv_v(sock_t fd, const GMPublicKey& pk) {
    send_mpz(fd, pk.n);
    send_mpz(fd, pk.u);
    uint32_t v;
    recv_all(fd, &v, sizeof(v));
    return v;
}

static void prepare_keys_and_dataset(GM& gm, GMPublicKey& pk, GMSecretKey& sk, std::vector<std::string>& Y) {
    Y = load_dataset("cards.txt", 50, SEED);
    gm.keygen(2048, pk, sk);
}

static int run_protocol(const std::string& protocol, sock_t fd, GM& gm, const GMPublicKey& pk, const GMSecretKey& sk, const std::vector<std::string>& Y, uint32_t v, const std::string& ca_host = "", int ca_port = 0) {
    if (protocol == "psi_ca") {
        int cardinality = client_psi_ca(fd, gm, pk, sk, Y, v);
        std::cout << "Cardinality: " << cardinality << "\n";
        return cardinality;
    } else if (protocol == "psi") {
        client_psi(fd, gm, pk, sk, Y, v);
    } else if (protocol == "apsi") {
        client_apsi(fd, gm, pk, sk, Y, v, ca_host, ca_port);
    } else if (protocol == "apsi_ca") {
        client_apsi_ca(fd, gm, pk, sk, Y, v, ca_host, ca_port);
    } else {
        throw std::invalid_argument("Unknown protocol: " + protocol);
    }
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: ./client <protocol> [ca_host ca_port]\n";
        std::cerr << "Protocols: psi_ca | psi | apsi_ca | apsi\n";
        std::cerr << "For apsi_ca, provide CA host and port as extra arguments.\n";
        return 1;
    }
    std::string protocol = argv[1];

#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    std::string ca_host;
    int ca_port = 0;
    if (protocol == "apsi_ca" || protocol == "apsi") {
        if (argc < 4) {
            std::cerr << "For apsi_ca or apsi, provide CA host and port as arguments.\n";
            return 1;
        }
        ca_host = argv[2];
        ca_port = std::stoi(argv[3]);
    }

    try {
        std::vector<std::string> Y;
        prepare_keys_and_dataset(gm, pk, sk, Y);

        sock_t fd = connect_to_server("127.0.0.1", PSI_PORT);
        std::cout << "Connected to server.\n";

        uint32_t v = send_public_key_and_recv_v(fd, pk);
        std::cout << "Received v from server.\n";

        run_protocol(protocol, fd, gm, pk, sk, Y, v, ca_host, ca_port);

        CLOSE_SOCKET(fd);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}