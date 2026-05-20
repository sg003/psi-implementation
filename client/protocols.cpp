#include "../gm.hpp"
#include "../net.hpp"
#include "../bloom_filter.hpp"
#include <string>
#include <vector>
#include <unordered_map>
#include <iostream>

static std::unordered_map<std::string, std::string> build_phi_map(const std::vector<std::string>& Y) {
    std::unordered_map<std::string, std::string> phi_map;
    for (const auto& ci : Y) {
        std::string phi_ci(K, '0');
        for (size_t j = 0; j < K; j++)
            phi_ci[j] = '0' + phi_bit(ci, j);
        phi_map[phi_ci] = ci;
    }
    return phi_map;
}

static std::string decrypt_group(GM& gm, const GMSecretKey& sk, const std::vector<mpz_class>& group) {
    std::string bits(K, '0');
    for (size_t j = 0; j < K; j++)
        bits[j] = '0' + gm.decrypt_bit(sk, group[j]);
    return bits;
}

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

void client_psi(sock_t fd, GM& gm, const GMPublicKey& pk, const GMSecretKey& sk, const std::vector<std::string>& Y, uint32_t v) {
    size_t m = bf_optimal_size(v, K);
    std::vector<mpz_class> encrypted_bf = build_and_encrypt_bf(gm, pk, Y, m, K);
    send_encrypted_bf(fd, encrypted_bf);
    std::vector<std::vector<mpz_class>> response = recv_server_response(fd, v, K);

    auto phi_map = build_phi_map(Y);

    std::vector<std::string> intersection;
    for (const auto& e_si : response) {
        auto it = phi_map.find(decrypt_group(gm, sk, e_si));
        if (it != phi_map.end())
            intersection.push_back(it->second);
    }

    std::cout << "Intersection size: " << intersection.size() << "\n";
    for (const auto& elem : intersection)
        std::cout << "  " << elem << "\n";
}


void send_bytes(sock_t fd, const std::vector<unsigned char>& data) {
    uint32_t size = static_cast<uint32_t>(data.size());
    send_all(fd, &size, sizeof(size));
    if (size > 0) send_all(fd, data.data(), size);
}

void send_string(sock_t fd, const std::string& s) {
    uint32_t size = static_cast<uint32_t>(s.size());
    send_all(fd, &size, sizeof(size));
    if (size > 0) send_all(fd, s.data(), size);
}

std::string recv_string(sock_t fd) {
    uint32_t size = 0;
    recv_all(fd, &size, sizeof(size));

    std::string s(size, '\0');
    if (size > 0) recv_all(fd, s.data(), size);
    return s;
}


void client_apsi_ca(sock_t fd, GM& gm, const GMPublicKey& pk, const GMSecretKey& sk, const std::vector<std::string>& Y, uint32_t v, const std::string& ca_host, int ca_port) {
    sock_t ca_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (ca_fd < 0) { perror("socket"); exit(1); }
    sockaddr_in ca_addr{};
    ca_addr.sin_family = AF_INET;
    ca_addr.sin_port = htons(ca_port);
    if (inet_pton(AF_INET, ca_host.c_str(), &ca_addr.sin_addr) <= 0) {
        std::cerr << "Invalid CA host address\n";
        exit(1);
    }
    if (connect(ca_fd, (sockaddr*)&ca_addr, sizeof(ca_addr)) < 0) { perror("connect to CA"); exit(1); }

    // Send public key and set to CA
    send_mpz(ca_fd, pk.n);
    send_mpz(ca_fd, pk.u);
    uint32_t m = static_cast<uint32_t>(bf_optimal_size(v, K));
    send_all(ca_fd, &m, sizeof(m));
    uint32_t y_size = Y.size();
    send_all(ca_fd, &y_size, sizeof(y_size));
    for (const auto& item : Y) {
        uint32_t len = item.size();
        send_all(ca_fd, &len, sizeof(len));
        send_all(ca_fd, item.data(), len);
    }

    // Receive signature
    uint32_t sig_size = 0;
    recv_all(ca_fd, &sig_size, sizeof(sig_size));
    std::vector<unsigned char> signature(sig_size);
    recv_all(ca_fd, signature.data(), sig_size);

    // Receive encrypted BF
    uint32_t bf_size = 0;
    recv_all(ca_fd, &bf_size, sizeof(bf_size));
    std::vector<mpz_class> encrypted_bf(bf_size);
    for (uint32_t i = 0; i < bf_size; ++i) {
        recv_mpz(ca_fd, encrypted_bf[i]);
    }

    std::string ca_public_key_pem = recv_string(ca_fd);

    CLOSE_SOCKET(ca_fd);

    // Send to server
    send_string(fd, ca_public_key_pem);
    send_bytes(fd, signature);
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
    std::cout << "APSI-CA cardinality: " << cardinality << "\n";
}

void client_apsi(sock_t fd, GM& gm, const GMPublicKey& pk, const GMSecretKey& sk, const std::vector<std::string>& Y, uint32_t v) {}
