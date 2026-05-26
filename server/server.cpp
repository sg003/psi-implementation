#include "../config.hpp"
#include "../net.hpp"
#include "../gm.hpp"
#include "../bloom_filter.hpp"
#include "../timing.hpp"

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <random>
#include <algorithm>


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

void server_psi_ca (sock_t fd, const std::vector<std::string>& X, const GMPublicKey& pk, uint32_t v, ServerTiming* timing = nullptr);
void server_psi    (sock_t fd, const std::vector<std::string>& X, const GMPublicKey& pk, uint32_t v, ServerTiming* timing = nullptr);
void server_apsi_ca(sock_t fd, const std::vector<std::string>& X, const GMPublicKey& pk, uint32_t v, ServerTiming* timing = nullptr);
void server_apsi   (sock_t fd, const std::vector<std::string>& X, const GMPublicKey& pk, uint32_t v);

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

    sock_t listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(PSI_PORT);

    if (bind(listen_fd, (sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); return 1; }
    if (listen(listen_fd, 1) < 0) { perror("listen"); return 1; }

    std::cout << "Server listening on port " << PSI_PORT << "...\n";

    sock_t conn_fd = accept(listen_fd, nullptr, nullptr);
    if (conn_fd < 0) { perror("accept"); return 1; }
    std::cout << "Client connected.\n";

    std::vector<std::string> X = load_dataset(DATASET_PATH, SERVER_SET_SIZE, SERVER_SEED);
    { std::ofstream f("server_set.txt"); for (const auto& s : X) f << s << "\n"; }

    GMPublicKey pk;
    recv_mpz(conn_fd, pk.n);
    recv_mpz(conn_fd, pk.u);
    std::cout << "Received n and u from client.\n";

    uint32_t v = static_cast<uint32_t>(X.size());
    send_all(conn_fd, &v, sizeof(v));

    if      (protocol == "psi_ca")  server_psi_ca(conn_fd, X, pk, v);
    else if (protocol == "psi")     server_psi(conn_fd, X, pk, v);
    else if (protocol == "apsi_ca") server_apsi_ca(conn_fd, X, pk, v);
    else if (protocol == "apsi")    server_apsi(conn_fd, X, pk, v);
    else { std::cerr << "Unknown protocol: " << protocol << "\n"; return 1; }

    CLOSE_SOCKET(conn_fd);
    CLOSE_SOCKET(listen_fd);
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
