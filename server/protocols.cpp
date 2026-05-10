#include "../net.hpp"
#include "../gm.hpp"
#include "../bloom_filter.hpp"

#include <iostream>
#include <vector>
#include <string>

void server_psi_ca(sock_t fd, const std::vector<std::string>& X, const GMPublicKey& pk, uint32_t v) {
    uint32_t m32 = 0;
    recv_all(fd, &m32, sizeof(m32));
    size_t m = static_cast<size_t>(m32);

    std::vector<mpz_class> encrypted_bf(m);
    for (size_t i = 0; i < m; i++) {
        recv_mpz(fd, encrypted_bf[i]);
    }

    GM gm;
    for (const auto& item : X) {
        for (size_t j = 0; j < K; j++) {
            size_t index = bf_hash(item, j, m);
            mpz_class rerandomized = gm.rerandomize(pk, encrypted_bf[index]);
            send_mpz(fd, rerandomized);
        }
    }
}

void server_psi(sock_t fd, const std::vector<std::string>& X, const GMPublicKey& pk, uint32_t v) {}

void server_apsi_ca(sock_t fd, const std::vector<std::string>& X, const GMPublicKey& pk, uint32_t v) {}

void server_apsi(sock_t fd, const std::vector<std::string>& X, const GMPublicKey& pk, uint32_t v) {}
