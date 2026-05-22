#include "../net.hpp"
#include "../gm.hpp"
#include "../bloom_filter.hpp"
#include "../ca/ca.hpp"
#include "../crypto/signature.hpp"
#include "../timing.hpp"

#include <iostream>
#include <vector>
#include <string>
#include <chrono>

using Clock = std::chrono::high_resolution_clock;
using ms_f  = std::chrono::duration<double, std::milli>;

static double elapsed_ms(Clock::time_point a, Clock::time_point b) {
    return ms_f(b - a).count();
}

static std::vector<mpz_class> xor_bf_with_phi(GM& gm, const GMPublicKey& pk,
    const std::vector<mpz_class>& encrypted_bf, const std::string& si, size_t m) {
    std::vector<mpz_class> result(K);
    for (size_t j = 0; j < K; j++) {
        size_t index = bf_hash(si, j, m);
        int phi = phi_bit(si, j);
        result[j] = phi
            ? gm.homomorphic_xor(pk, encrypted_bf[index], gm.encrypt_bit(pk, 1))
            : gm.rerandomize(pk, encrypted_bf[index]);
    }
    return result;
}

static std::vector<unsigned char> recv_bytes(sock_t fd) {
    uint32_t size = 0;
    recv_all(fd, &size, sizeof(size));
    std::vector<unsigned char> data(size);
    if (size > 0) recv_all(fd, data.data(), size);
    return data;
}

static std::string recv_string(sock_t fd) {
    uint32_t size = 0;
    recv_all(fd, &size, sizeof(size));
    std::string s(size, '\0');
    if (size > 0) recv_all(fd, s.data(), size);
    return s;
}

static std::vector<mpz_class> recv_encrypted_bf(sock_t fd) {
    uint32_t m32 = 0;
    recv_all(fd, &m32, sizeof(m32));
    std::vector<mpz_class> encrypted_bf(m32);
    for (size_t i = 0; i < m32; i++)
        recv_mpz(fd, encrypted_bf[i]);
    return encrypted_bf;
}

static void process_encrypted_bf_for_cardinality(sock_t fd, const std::vector<std::string>& X,
                                                  const GMPublicKey& pk,
                                                  const std::vector<mpz_class>& encrypted_bf) {
    size_t m = encrypted_bf.size();
    GM gm;
    for (const auto& item : X)
        for (size_t j = 0; j < K; j++)
            send_mpz(fd, gm.rerandomize(pk, encrypted_bf[bf_hash(item, j, m)]));
}

void server_psi_ca(sock_t fd, const std::vector<std::string>& X, const GMPublicKey& pk,
                   uint32_t v, ServerTiming* timing) {
    ServerTiming _t;
    if (!timing) timing = &_t;

    auto t_total = Clock::now();

    auto t0 = Clock::now();
    uint32_t m32 = 0;
    recv_all(fd, &m32, sizeof(m32));
    size_t m = static_cast<size_t>(m32);
    std::vector<mpz_class> encrypted_bf(m);
    for (size_t i = 0; i < m; i++)
        recv_mpz(fd, encrypted_bf[i]);
    auto t1 = Clock::now();
    timing->recv_bf_ms = elapsed_ms(t0, t1);
    timing->bytes_recv = sizeof(uint32_t);
    for (const auto& c : encrypted_bf) timing->bytes_recv += mpz_wire_bytes(c);

    GM gm;

    auto t2 = Clock::now();
    std::vector<std::vector<mpz_class>> all_responses;
    all_responses.reserve(X.size());
    for (const auto& item : X) {
        std::vector<mpz_class> resp(K);
        for (size_t j = 0; j < K; j++) {
            size_t index = bf_hash(item, j, m);
            resp[j] = gm.rerandomize(pk, encrypted_bf[index]);
        }
        all_responses.push_back(std::move(resp));
    }
    auto t3 = Clock::now();
    timing->compute_ms = elapsed_ms(t2, t3);

    auto t4 = Clock::now();
    for (const auto& resp : all_responses)
        for (const auto& c : resp)
            send_mpz(fd, c);
    auto t5 = Clock::now();
    timing->send_ms  = elapsed_ms(t4, t5);
    timing->total_ms = elapsed_ms(t_total, t5);
    for (const auto& resp : all_responses) for (const auto& c : resp) timing->bytes_sent += mpz_wire_bytes(c);
}

void server_psi(sock_t fd, const std::vector<std::string>& X, const GMPublicKey& pk,
                uint32_t v, ServerTiming* timing) {
    ServerTiming _t;
    if (!timing) timing = &_t;

    auto t_total = Clock::now();

    auto t0 = Clock::now();
    uint32_t m32 = 0;
    recv_all(fd, &m32, sizeof(m32));
    size_t m = static_cast<size_t>(m32);
    std::vector<mpz_class> encrypted_bf(m);
    for (size_t i = 0; i < m; i++)
        recv_mpz(fd, encrypted_bf[i]);
    auto t1 = Clock::now();
    timing->recv_bf_ms = elapsed_ms(t0, t1);
    timing->bytes_recv = sizeof(uint32_t);
    for (const auto& c : encrypted_bf) timing->bytes_recv += mpz_wire_bytes(c);

    GM gm;

    auto t2 = Clock::now();
    std::vector<std::vector<mpz_class>> all_responses;
    all_responses.reserve(X.size());
    for (const auto& si : X)
        all_responses.push_back(xor_bf_with_phi(gm, pk, encrypted_bf, si, m));
    auto t3 = Clock::now();
    timing->compute_ms = elapsed_ms(t2, t3);

    auto t4 = Clock::now();
    for (const auto& resp : all_responses)
        for (const auto& c : resp)
            send_mpz(fd, c);
    auto t5 = Clock::now();
    timing->send_ms  = elapsed_ms(t4, t5);
    timing->total_ms = elapsed_ms(t_total, t5);
    for (const auto& resp : all_responses) for (const auto& c : resp) timing->bytes_sent += mpz_wire_bytes(c);
}

void server_apsi_ca(sock_t fd, const std::vector<std::string>& X, const GMPublicKey& pk, uint32_t v) {
    std::string ca_public_key_pem = recv_string(fd);
    std::vector<unsigned char> signature = recv_bytes(fd);
    std::vector<mpz_class> encrypted_bf = recv_encrypted_bf(fd);

    std::vector<unsigned char> message = serialize_encrypted_bf(encrypted_bf);
    if (!verify_signature(ca_public_key_pem, message, signature)) {
        std::cerr << "APSI-CA signature verification failed. Aborting.\n";
        return;
    }
    std::cout << "APSI-CA signature verified.\n";
    process_encrypted_bf_for_cardinality(fd, X, pk, encrypted_bf);
}

void server_apsi(sock_t fd, const std::vector<std::string>& X, const GMPublicKey& pk, uint32_t v) {}
