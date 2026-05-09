#include "../net.hpp"
#include "../gm.hpp"

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <random>
#include <algorithm>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

const uint64_t SEED = 2;
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

int main(int argc, char* argv[]) {
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(PSI_PORT);

    if (bind(listen_fd, (sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); return 1; }
    if (listen(listen_fd, 1) < 0) { perror("listen"); return 1; }

    std::cout << "Server listening on port " << PSI_PORT << "...\n";

    int conn_fd = accept(listen_fd, nullptr, nullptr);
    if (conn_fd < 0) { perror("accept"); return 1; }
    std::cout << "Client connected.\n";

    // TODO: pass dataset path and sample size via argv
    std::vector<std::string> X = load_dataset("cards.txt", 100, SEED);

    // receive public key from client
    GMPublicKey pk;
    recv_mpz(conn_fd, pk.n);
    recv_mpz(conn_fd, pk.u);

    // send server set size
    // TODO: load server set X from dataset file
    uint32_t v = static_cast<uint32_t>(X.size());
    send_all(conn_fd, &v, sizeof(v));

    // --- server-side PSI-CA logic goes here ---

    close(conn_fd);
    close(listen_fd);
    return 0;
}
