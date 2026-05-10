#include "../gm.hpp"
#include "../net.hpp"
#include "../bloom_filter.hpp"
#include <string>
#include <vector>

/** 
* Builds the bf then encrypts it
*/
std::vector<mpz_class> build_and_encrypt_bf(GM& gm, const GMPublicKey& pk, const std::vector<std::string>& Y, size_t m, size_t k){
    BloomFilter bf = bf_init(m, k);
    for (const auto& item : Y){
        bf_add(bf, item);
    }
    std::vector<mpz_class> encrypted_bf;
    for( size_t t = 0; t<m;t++){
        encrypted_bf.push_back(gm.encrypt_bit(pk, bf.bits[t]));
    }
    return encrypted_bf;
}

void send_encrypted_bf(sock_t fd, const std::vector<mpz_class>& encrypted_bf){
    uint32_t size = encrypted_bf.size();
    send_all(fd, &size, sizeof(size));
    for (const auto& b : encrypted_bf)
        send_mpz(fd, b);
}

std::vector<std::vector<mpz_class>> recv_server_response(sock_t fd, size_t v, size_t k) {
    std::vector<std::vector<mpz_class>> response;
    response.reserve(v);
    for (size_t i = 0; i < v; i++) {
        std::vector<mpz_class> e_si(k);
        for (size_t j = 0; j < k; j++)
            recv_mpz(fd, e_si[j]);
        response.push_back(std::move(e_si));
    }
    return response;
}

int client_psi_ca(sock_t fd, GM& gm, const GMPublicKey& pk, const GMSecretKey& sk, const std::vector<std::string>& Y, uint32_t v) {
    size_t m = bf_optimal_size(v, K);
    std::vector<mpz_class> encrypted_bf = build_and_encrypt_bf(gm, pk, Y, m, K);
    send_encrypted_bf(fd, encrypted_bf);
    std::vector<std::vector<mpz_class>> response = recv_server_response(fd, v, K);
    int cardinality = 0;
    for (const auto& e_si : response) {
        bool all_zero = true;
        for (const auto& ciphertext : e_si) {
            if (gm.decrypt_bit(sk, ciphertext) != 0) {
                all_zero = false;
                break;
            }
        }
        if (all_zero) cardinality++;
    }
    return cardinality;
}

void client_psi(sock_t fd, GM& gm, const GMPublicKey& pk, const GMSecretKey& sk, const std::vector<std::string>& Y, uint32_t v) {}

void client_apsi_ca(sock_t fd, GM& gm, const GMPublicKey& pk, const GMSecretKey& sk, const std::vector<std::string>& Y, uint32_t v) {}

void client_apsi(sock_t fd, GM& gm, const GMPublicKey& pk, const GMSecretKey& sk, const std::vector<std::string>& Y, uint32_t v) {}
