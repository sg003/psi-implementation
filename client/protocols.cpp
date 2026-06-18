#include "../gm.hpp"
#include "../net.hpp"
#include "../bloom_filter.hpp"
#include "../timing.hpp"

#include <string>
#include <vector>
#include <unordered_map>
#include <iostream>
#include <chrono>

using Clock = std::chrono::high_resolution_clock;
using ms_f  = std::chrono::duration<double, std::milli>;

static double elapsed_ms(Clock::time_point a, Clock::time_point b) {
    return ms_f(b - a).count();
}

static std::unordered_map<std::string, std::vector<std::string>> build_phi_map(const std::vector<std::string>& Y) {
    std::unordered_map<std::string, std::vector<std::string>> phi_map;
    for (const auto& ci : Y) {
        std::string phi_ci(K, '0');
        for (size_t j = 0; j < K; j++)
            phi_ci[j] = '0' + phi_bit(ci, j);
        phi_map[phi_ci].push_back(ci);
    }
    return phi_map;
}

static std::string decrypt_group(GM& gm, const GMSecretKey& sk, const std::vector<mpz_class>& group) {
    std::string bits(K, '0');
    for (size_t j = 0; j < K; j++)
        bits[j] = '0' + gm.decrypt_bit(sk, group[j]);
    return bits;
}

static std::string recv_string(sock_t fd) {
    uint32_t size = 0;
    recv_all(fd, &size, sizeof(size));
    std::string s(size, '\0');
    if (size > 0) recv_all(fd, s.data(), size);
    return s;
}

std::vector<mpz_class> build_and_encrypt_bf(GM& gm, const GMPublicKey& pk, const std::vector<std::string>& Y, size_t m, size_t k) {
    BloomFilter bf = bf_init(m, k);
    for (const auto& item : Y)
        bf_add(bf, item);
    std::vector<mpz_class> encrypted_bf;
    for (size_t t = 0; t < m; t++)
        encrypted_bf.push_back(gm.encrypt_bit(pk, bf.bits[t]));
    return encrypted_bf;
}

void send_encrypted_bf(sock_t fd, const std::vector<mpz_class>& encrypted_bf) {
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

static void send_bytes(sock_t fd, const std::vector<unsigned char>& data) {
    uint32_t size = static_cast<uint32_t>(data.size());
    send_all(fd, &size, sizeof(size));
    if (size > 0) send_all(fd, data.data(), size);
}

static void send_string(sock_t fd, const std::string& s) {
    uint32_t size = static_cast<uint32_t>(s.size());
    send_all(fd, &size, sizeof(size));
    if (size > 0) send_all(fd, s.data(), size);
}

int client_psi_ca(sock_t fd, GM& gm, const GMPublicKey& pk, const GMSecretKey& sk,
                  const std::vector<std::string>& Y, uint32_t v, ClientTiming* timing) {
    ClientTiming _t;
    if (!timing) timing = &_t;

    auto t_total = Clock::now();

    size_t m = bf_optimal_size(Y.size(), K);

    auto t0 = Clock::now();
    std::vector<mpz_class> encrypted_bf = build_and_encrypt_bf(gm, pk, Y, m, K);
    auto t1 = Clock::now();
    timing->bf_build_ms = elapsed_ms(t0, t1);

    auto t2 = Clock::now();
    send_encrypted_bf(fd, encrypted_bf);
    auto t3 = Clock::now();
    timing->send_ms = elapsed_ms(t2, t3);
    timing->bytes_sent = sizeof(uint32_t);
    for (const auto& c : encrypted_bf) timing->bytes_sent += mpz_wire_bytes(c);

    auto t4 = Clock::now();
    std::vector<std::vector<mpz_class>> response = recv_server_response(fd, v, K);
    auto t5 = Clock::now();
    timing->recv_ms = elapsed_ms(t4, t5);
    for (const auto& g : response) for (const auto& c : g) timing->bytes_recv += mpz_wire_bytes(c);

    auto t6 = Clock::now();
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
    auto t7 = Clock::now();
    timing->decrypt_ms = elapsed_ms(t6, t7);
    timing->total_ms   = elapsed_ms(t_total, t7);

    return cardinality;
}

std::vector<std::string> client_psi(sock_t fd, GM& gm, const GMPublicKey& pk, const GMSecretKey& sk,
                                    const std::vector<std::string>& Y, uint32_t v, ClientTiming* timing) {
    ClientTiming _t;
    if (!timing) timing = &_t;

    auto t_total = Clock::now();

    size_t m = bf_optimal_size(Y.size(), K);

    auto t0 = Clock::now();
    std::vector<mpz_class> encrypted_bf = build_and_encrypt_bf(gm, pk, Y, m, K);
    auto t1 = Clock::now();
    timing->bf_build_ms = elapsed_ms(t0, t1);

    auto t2 = Clock::now();
    send_encrypted_bf(fd, encrypted_bf);
    auto t3 = Clock::now();
    timing->send_ms = elapsed_ms(t2, t3);
    timing->bytes_sent = sizeof(uint32_t);
    for (const auto& c : encrypted_bf) timing->bytes_sent += mpz_wire_bytes(c);

    auto t4 = Clock::now();
    std::vector<std::vector<mpz_class>> response = recv_server_response(fd, v, K);
    auto t5 = Clock::now();
    timing->recv_ms = elapsed_ms(t4, t5);
    for (const auto& g : response) for (const auto& c : g) timing->bytes_recv += mpz_wire_bytes(c);

    auto phi_map = build_phi_map(Y);

    auto t6 = Clock::now();
    std::vector<std::string> intersection;
    for (const auto& e_si : response) {
        auto it = phi_map.find(decrypt_group(gm, sk, e_si));
        if (it != phi_map.end())
            for (const auto& elem : it->second)
                intersection.push_back(elem);
    }
    auto t7 = Clock::now();
    timing->decrypt_ms = elapsed_ms(t6, t7);
    timing->total_ms   = elapsed_ms(t_total, t7);

    return intersection;
}

int client_apsi_ca(sock_t fd, GM& gm, const GMPublicKey& pk, const GMSecretKey& sk,
                   const std::vector<std::string>& Y, uint32_t v,
                   const std::string& ca_host, int ca_port, ClientTiming* timing) {
    ClientTiming _t;
    if (!timing) timing = &_t;

    auto t_total = Clock::now();

    // ── CA round-trip (connect, send set, receive certified BF) ──────────────
    auto t0 = Clock::now();
    sock_t ca_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (ca_fd < 0) { perror("socket"); exit(1); }
    sockaddr_in ca_addr{};
    ca_addr.sin_family = AF_INET;
    ca_addr.sin_port   = htons(ca_port);
    if (inet_pton(AF_INET, ca_host.c_str(), &ca_addr.sin_addr) <= 0) {
        std::cerr << "Invalid CA host address\n"; exit(1);
    }
    if (connect(ca_fd, (sockaddr*)&ca_addr, sizeof(ca_addr)) < 0) {
        perror("connect to CA"); exit(1);
    }

    send_mpz(ca_fd, pk.n);
    send_mpz(ca_fd, pk.u);
    uint32_t m = static_cast<uint32_t>(bf_optimal_size(Y.size(), K));
    send_all(ca_fd, &m, sizeof(m));
    uint32_t y_size = Y.size();
    send_all(ca_fd, &y_size, sizeof(y_size));
    for (const auto& item : Y) {
        uint32_t len = item.size();
        send_all(ca_fd, &len, sizeof(len));
        send_all(ca_fd, item.data(), len);
    }

    uint32_t sig_size = 0;
    recv_all(ca_fd, &sig_size, sizeof(sig_size));
    std::vector<unsigned char> signature(sig_size);
    recv_all(ca_fd, signature.data(), sig_size);

    uint32_t bf_size = 0;
    recv_all(ca_fd, &bf_size, sizeof(bf_size));
    std::vector<mpz_class> encrypted_bf(bf_size);
    for (uint32_t i = 0; i < bf_size; ++i)
        recv_mpz(ca_fd, encrypted_bf[i]);

    std::string ca_public_key_pem = recv_string(ca_fd);
    CLOSE_SOCKET(ca_fd);
    auto t1 = Clock::now();
    timing->bf_build_ms = elapsed_ms(t0, t1);

    timing->bytes_ca_send = mpz_wire_bytes(pk.n) + mpz_wire_bytes(pk.u)
                          + sizeof(uint32_t)   // m
                          + sizeof(uint32_t);  // y_size
    for (const auto& item : Y)
        timing->bytes_ca_send += sizeof(uint32_t) + item.size();
    timing->bytes_ca_recv = sizeof(uint32_t) + sig_size
                          + sizeof(uint32_t);  // bf_size
    for (const auto& c : encrypted_bf) timing->bytes_ca_recv += mpz_wire_bytes(c);
    timing->bytes_ca_recv += sizeof(uint32_t) + ca_public_key_pem.size();

    // ── Send certified BF to PSI server ──────────────────────────────────────
    auto t2 = Clock::now();
    send_string(fd, ca_public_key_pem);
    send_bytes(fd, signature);
    send_encrypted_bf(fd, encrypted_bf);
    auto t3 = Clock::now();
    timing->send_ms = elapsed_ms(t2, t3);
    timing->bytes_sent = sizeof(uint32_t) + ca_public_key_pem.size()
                       + sizeof(uint32_t) + signature.size()
                       + sizeof(uint32_t);
    for (const auto& c : encrypted_bf) timing->bytes_sent += mpz_wire_bytes(c);

    // ── Receive PSI server response ───────────────────────────────────────────
    auto t4 = Clock::now();
    std::vector<std::vector<mpz_class>> response = recv_server_response(fd, v, K);
    auto t5 = Clock::now();
    timing->recv_ms = elapsed_ms(t4, t5);
    for (const auto& g : response) for (const auto& c : g) timing->bytes_recv += mpz_wire_bytes(c);

    // ── Decrypt ───────────────────────────────────────────────────────────────
    auto t6 = Clock::now();
    int cardinality = 0;
    for (const auto& e_si : response) {
        bool all_zero = true;
        for (const auto& ciphertext : e_si) {
            if (gm.decrypt_bit(sk, ciphertext) != 0) { all_zero = false; break; }
        }
        if (all_zero) cardinality++;
    }
    auto t7 = Clock::now();
    timing->decrypt_ms = elapsed_ms(t6, t7);
    timing->total_ms   = elapsed_ms(t_total, t7);

    std::cout << "APSI-CA cardinality: " << cardinality << "\n";
    return cardinality;
}

std::vector<std::string> client_apsi(sock_t fd, GM& gm, const GMPublicKey& pk, const GMSecretKey& sk, const std::vector<std::string>& Y, uint32_t v, const std::string& ca_host, int ca_port, ClientTiming* timing) {
    ClientTiming _t;
    if (!timing) timing = &_t;

    auto t_total = Clock::now();

    // ── CA round-trip (connect, send set, receive certified BF) ──────────────
    auto t0 = Clock::now();
    sock_t ca_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (ca_fd < 0) { perror("socket"); exit(1); }

    sockaddr_in ca_addr{};
    ca_addr.sin_family = AF_INET;
    ca_addr.sin_port   = htons(ca_port);
    if (inet_pton(AF_INET, ca_host.c_str(), &ca_addr.sin_addr) <= 0) {
        std::cerr << "Invalid CA host address\n";
        exit(1);
    }
    if (connect(ca_fd, (sockaddr*)&ca_addr, sizeof(ca_addr)) < 0) {
        perror("connect to CA");
        exit(1);
    }

    // 1. Build the mapping: K-bit string -> Raw string
    auto phi_map = build_phi_map(Y);

    // 2. Extract strictly the K-bit strings to send to the CA
    std::vector<std::string> Y_hashed;
    Y_hashed.reserve(phi_map.size());
    for (const auto& pair : phi_map)
        Y_hashed.push_back(pair.first);

    send_mpz(ca_fd, pk.n);
    send_mpz(ca_fd, pk.u);

    uint32_t m = static_cast<uint32_t>(bf_optimal_size(Y_hashed.size(), K));
    send_all(ca_fd, &m, sizeof(m));

    uint32_t y_size = static_cast<uint32_t>(Y_hashed.size());
    send_all(ca_fd, &y_size, sizeof(y_size));
    for (const auto& item : Y_hashed) {
        uint32_t len = static_cast<uint32_t>(item.size());
        send_all(ca_fd, &len, sizeof(len));
        send_all(ca_fd, item.data(), len);
    }

    uint32_t sig_size = 0;
    recv_all(ca_fd, &sig_size, sizeof(sig_size));
    std::vector<unsigned char> signature(sig_size);
    recv_all(ca_fd, signature.data(), sig_size);

    uint32_t bf_size = 0;
    recv_all(ca_fd, &bf_size, sizeof(bf_size));
    std::vector<mpz_class> encrypted_bf(bf_size);
    for (uint32_t i = 0; i < bf_size; ++i)
        recv_mpz(ca_fd, encrypted_bf[i]);

    uint32_t pem_size = 0;
    recv_all(ca_fd, &pem_size, sizeof(pem_size));
    std::string ca_public_key_pem(pem_size, '\0');
    if (pem_size > 0)
        recv_all(ca_fd, ca_public_key_pem.data(), pem_size);

    CLOSE_SOCKET(ca_fd);
    auto t1 = Clock::now();
    timing->bf_build_ms = elapsed_ms(t0, t1);

    timing->bytes_ca_send = mpz_wire_bytes(pk.n) + mpz_wire_bytes(pk.u)
                          + sizeof(uint32_t)   // m
                          + sizeof(uint32_t);  // y_size
    for (const auto& item : Y_hashed)
        timing->bytes_ca_send += sizeof(uint32_t) + item.size();
    timing->bytes_ca_recv = sizeof(uint32_t) + sig_size
                          + sizeof(uint32_t);  // bf_size
    for (const auto& c : encrypted_bf) timing->bytes_ca_recv += mpz_wire_bytes(c);
    timing->bytes_ca_recv += sizeof(uint32_t) + ca_public_key_pem.size();

    // ── Send certified BF to PSI server ──────────────────────────────────────
    auto t2 = Clock::now();
    send_string(fd, ca_public_key_pem);
    send_bytes(fd, signature);
    send_encrypted_bf(fd, encrypted_bf);
    auto t3 = Clock::now();
    timing->send_ms = elapsed_ms(t2, t3);
    timing->bytes_sent = sizeof(uint32_t) + ca_public_key_pem.size()
                       + sizeof(uint32_t) + signature.size()
                       + sizeof(uint32_t);
    for (const auto& c : encrypted_bf) timing->bytes_sent += mpz_wire_bytes(c);

    // ── Receive PSI server response ──────────────────────────────────────────
    auto t4 = Clock::now();
    std::vector<std::vector<mpz_class>> response = recv_server_response(fd, v, K);
    auto t5 = Clock::now();
    timing->recv_ms = elapsed_ms(t4, t5);
    for (const auto& g : response) for (const auto& c : g) timing->bytes_recv += mpz_wire_bytes(c);

    // ── Decrypt ───────────────────────────────────────────────────────────────
    auto t6 = Clock::now();
    std::vector<std::string> intersection;
    for (const auto& e_si : response) {
        std::string d = decrypt_group(gm, sk, e_si);
        auto it = phi_map.find(d);
        if (it != phi_map.end())
            for (const auto& s : it->second)
                intersection.push_back(s);
    }

    auto t7 = Clock::now();
    timing->decrypt_ms = elapsed_ms(t6, t7);
    timing->total_ms   = elapsed_ms(t_total, t7);

    return intersection;
}