//
// experiment.cpp — PSI protocol experiment runner
//
// Runs both client and server in-process (separate threads over localhost TCP).
// Measures per-step timing, verifies intersection correctness, and writes
// results to a CSV file.
//
// Usage:
//   ./experiment [options]
//   --protocol/-p  <psi|psi_ca|apsi|apsi_ca>
//   --client/-c    <size>
//   --server/-s    <size>
//   -k             <uint>
//   --universe     <size>
//   --runs/-r      <count>
//   --output/-o    <file.csv>
//   --dataset/-d   <path>
//   --client-seed  <uint64>
//   --server-seed  <uint64>
//   --help/-h
//

#include "config.hpp"
#include "net.hpp"
#include "gm.hpp"
#include "bloom_filter.hpp"
#include "timing.hpp"
#include "ca/ca.hpp"
#include "crypto/signature.hpp"

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <set>
#include <unordered_set>
#include <algorithm>
#include <random>
#include <thread>
#include <future>
#include <chrono>
#include <iomanip>
#include <stdexcept>

using Clock = std::chrono::high_resolution_clock;
using ms_f  = std::chrono::duration<double, std::milli>;

static double elapsed_ms(Clock::time_point a, Clock::time_point b) {
    return ms_f(b - a).count();
}

// ── Forward declarations from protocol files ──────────────────────────────────

int                      client_psi_ca (sock_t, GM&, const GMPublicKey&, const GMSecretKey&, const std::vector<std::string>&, uint32_t, ClientTiming* = nullptr);
std::vector<std::string> client_psi    (sock_t, GM&, const GMPublicKey&, const GMSecretKey&, const std::vector<std::string>&, uint32_t, ClientTiming* = nullptr);
int                      client_apsi_ca(sock_t, GM&, const GMPublicKey&, const GMSecretKey&, const std::vector<std::string>&, uint32_t, const std::string&, int, ClientTiming* = nullptr);
std::vector<std::string> client_apsi   (sock_t, GM&, const GMPublicKey&, const GMSecretKey&, const std::vector<std::string>&, uint32_t, const std::string&, int, ClientTiming* = nullptr);

void server_psi_ca (sock_t, const std::vector<std::string>&, const GMPublicKey&, uint32_t, ServerTiming* = nullptr);
void server_psi    (sock_t, const std::vector<std::string>&, const GMPublicKey&, uint32_t, ServerTiming* = nullptr);
void server_apsi_ca(sock_t, const std::vector<std::string>&, const GMPublicKey&, uint32_t, ServerTiming* = nullptr);
void server_apsi   (sock_t, const std::vector<std::string>&, const GMPublicKey&, uint32_t, ServerTiming* = nullptr);

// ── Config & result structs ───────────────────────────────────────────────────

struct ExperimentConfig {
    std::string protocol          = EXP_PROTOCOL;
    size_t      client_size       = CLIENT_SET_SIZE;
    size_t      server_size       = SERVER_SET_SIZE;
    int         runs              = EXP_RUNS;
    std::string output_file       = EXP_OUTPUT;
    std::string dataset           = DATASET_PATH;
    uint64_t    client_seed       = CLIENT_SEED;
    uint64_t    server_seed       = SERVER_SEED;
    bool        client_seed_fixed = false;
    bool        server_seed_fixed = false;
    size_t      k                 = K;
    size_t      universe_size     = 0;   // 0 = full dataset
};

struct RunResult {
    int                      run;
    uint64_t                 client_seed;
    uint64_t                 server_seed;
    double                   keygen_ms;
    ClientTiming             client;
    ServerTiming             server;
    int                      result_size;       // cardinality or intersection count
    int                      true_intersection;
    int                      false_positives;
    int                      false_negatives;
    double                   fp_rate;
    std::vector<std::string> intersection;      // populated for psi / apsi
};

// ── Dataset loading ───────────────────────────────────────────────────────────

static std::vector<std::string> load_dataset(const std::string& path, size_t n, uint64_t seed,
                                              size_t universe_size = 0) {
    std::ifstream in(path);
    if (!in) throw std::runtime_error("Cannot open dataset: " + path);
    std::vector<std::string> all;
    std::string line;
    while (std::getline(in, line))
        if (!line.empty()) all.push_back(line);
    if (universe_size > 0 && universe_size < all.size())
        all.resize(universe_size);
    if (n > all.size())
        throw std::runtime_error("Sample size " + std::to_string(n) +
                                 " exceeds universe size " + std::to_string(all.size()));
    std::mt19937_64 rng(seed);
    std::shuffle(all.begin(), all.end(), rng);
    all.resize(n);
    return all;
}

// ── Ground truth ─────────────────────────────────────────────────────────────

static std::set<std::string> compute_ground_truth(
    const std::vector<std::string>& X,
    const std::vector<std::string>& Y)
{
    std::unordered_set<std::string> sx(X.begin(), X.end());
    std::set<std::string> gt;
    for (const auto& y : Y)
        if (sx.count(y)) gt.insert(y);
    return gt;
}

// ── Single experiment run ─────────────────────────────────────────────────────

static RunResult run_experiment(int run_idx, const ExperimentConfig& cfg,
                                const std::vector<std::string>& X,
                                const std::vector<std::string>& Y,
                                const std::set<std::string>& ground_truth)
{
    RunResult res{};
    res.run              = run_idx;
    res.true_intersection = static_cast<int>(ground_truth.size());

    // ── Key generation ────────────────────────────────────────────────────────
    GM          gm;
    GMPublicKey pk;
    GMSecretKey sk;
    auto t_kg0 = Clock::now();
    gm.keygen(GM_KEY_BITS, pk, sk);
    auto t_kg1 = Clock::now();
    res.keygen_ms = elapsed_ms(t_kg0, t_kg1);

    // ── Server socket (bind + listen before spawning thread) ──────────────────
    sock_t listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) throw std::runtime_error("socket() failed");
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
    sockaddr_in saddr{};
    saddr.sin_family      = AF_INET;
    saddr.sin_addr.s_addr = INADDR_ANY;
    saddr.sin_port        = htons(PSI_PORT);
    if (bind(listen_fd, (sockaddr*)&saddr, sizeof(saddr)) < 0)
        throw std::runtime_error("bind() failed");
    if (listen(listen_fd, 1) < 0)
        throw std::runtime_error("listen() failed");

    // ── CA socket (apsi_ca / apsi) ────────────────────────────────────────────
    sock_t ca_listen_fd = (sock_t)-1;
    if (cfg.protocol == "apsi_ca" || cfg.protocol == "apsi") {
        ca_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (ca_listen_fd < 0) throw std::runtime_error("CA socket() failed");
        int ca_opt = 1;
        setsockopt(ca_listen_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&ca_opt, sizeof(ca_opt));
        sockaddr_in ca_saddr{};
        ca_saddr.sin_family      = AF_INET;
        ca_saddr.sin_addr.s_addr = INADDR_ANY;
        ca_saddr.sin_port        = htons(CA_PORT);
        if (bind(ca_listen_fd, (sockaddr*)&ca_saddr, sizeof(ca_saddr)) < 0)
            throw std::runtime_error("CA bind() failed");
        if (listen(ca_listen_fd, 1) < 0)
            throw std::runtime_error("CA listen() failed");
    }

    // ── Server thread ─────────────────────────────────────────────────────────
    std::promise<ServerTiming> srv_promise;
    auto srv_future = srv_promise.get_future();

    std::thread server_thread([&]() {
        try {
            sock_t conn_fd = accept(listen_fd, nullptr, nullptr);
            if (conn_fd < 0) throw std::runtime_error("accept() failed");

            GMPublicKey srv_pk;
            recv_mpz(conn_fd, srv_pk.n);
            recv_mpz(conn_fd, srv_pk.u);

            uint32_t v = static_cast<uint32_t>(X.size());
            send_all(conn_fd, &v, sizeof(v));

            ServerTiming st;
            if      (cfg.protocol == "psi_ca")  server_psi_ca (conn_fd, X, srv_pk, v, &st);
            else if (cfg.protocol == "psi")      server_psi    (conn_fd, X, srv_pk, v, &st);
            else if (cfg.protocol == "apsi_ca")  server_apsi_ca(conn_fd, X, srv_pk, v, &st);
            else if (cfg.protocol == "apsi")     server_apsi   (conn_fd, X, srv_pk, v, &st);

            CLOSE_SOCKET(conn_fd);
            srv_promise.set_value(st);
        } catch (...) {
            srv_promise.set_exception(std::current_exception());
        }
    });

    // ── CA thread (apsi_ca / apsi) ──────────────────────────────────────────────
    std::thread ca_thread;
    std::exception_ptr ca_exception;
    if (cfg.protocol == "apsi_ca" || cfg.protocol == "apsi") {
        ca_thread = std::thread([ca_listen_fd, &ca_exception]() {
            try {
                sock_t ca_client_fd = accept(ca_listen_fd, nullptr, nullptr);
                if (ca_client_fd < 0) throw std::runtime_error("CA accept() failed");

                GM ca_gm;
                SignatureKeyPair ca_keys = generate_signature_keypair();

                GMPublicKey ca_pk;
                recv_mpz(ca_client_fd, ca_pk.n);
                recv_mpz(ca_client_fd, ca_pk.u);

                uint32_t m_ca = 0;
                recv_all(ca_client_fd, &m_ca, sizeof(m_ca));

                uint32_t y_size = 0;
                recv_all(ca_client_fd, &y_size, sizeof(y_size));

                std::vector<std::string> Y_ca;
                for (uint32_t i = 0; i < y_size; i++) {
                    uint32_t len = 0;
                    recv_all(ca_client_fd, &len, sizeof(len));
                    std::string item(len, '\0');
                    recv_all(ca_client_fd, item.data(), len);
                    Y_ca.push_back(item);
                }

                CertifiedEncryptedBF cert = ca_certify_client_set_with_keys(
                    ca_gm, ca_pk, Y_ca, m_ca, K, ca_keys);

                uint32_t sig_size = static_cast<uint32_t>(cert.signature.size());
                send_all(ca_client_fd, &sig_size, sizeof(sig_size));
                send_all(ca_client_fd, cert.signature.data(), sig_size);

                uint32_t bf_size = static_cast<uint32_t>(cert.encrypted_bf.size());
                send_all(ca_client_fd, &bf_size, sizeof(bf_size));
                for (const auto& c : cert.encrypted_bf)
                    send_mpz(ca_client_fd, c);

                uint32_t pem_size = static_cast<uint32_t>(cert.ca_public_key_pem.size());
                send_all(ca_client_fd, &pem_size, sizeof(pem_size));
                send_all(ca_client_fd, cert.ca_public_key_pem.data(), pem_size);

                CLOSE_SOCKET(ca_client_fd);
            } catch (...) {
                ca_exception = std::current_exception();
            }
        });
    }

    // ── Client side (main thread) ─────────────────────────────────────────────
    sock_t client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_fd < 0) { server_thread.join(); throw std::runtime_error("client socket() failed"); }

    sockaddr_in caddr{};
    caddr.sin_family = AF_INET;
    caddr.sin_port   = htons(PSI_PORT);
    inet_pton(AF_INET, "127.0.0.1", &caddr.sin_addr);
    if (connect(client_fd, (sockaddr*)&caddr, sizeof(caddr)) < 0)
        throw std::runtime_error("connect() failed");

    send_mpz(client_fd, pk.n);
    send_mpz(client_fd, pk.u);

    uint32_t v = 0;
    recv_all(client_fd, &v, sizeof(v));

    ClientTiming ct;

    if (cfg.protocol == "psi_ca") {
        res.result_size = client_psi_ca(client_fd, gm, pk, sk, Y, v, &ct);
        res.false_positives = std::max(0, res.result_size - res.true_intersection);
        res.false_negatives = std::max(0, res.true_intersection - res.result_size);
        res.fp_rate = res.result_size > 0
            ? static_cast<double>(res.false_positives) / res.result_size : 0.0;
    }
    else if (cfg.protocol == "psi") {
        res.intersection = client_psi(client_fd, gm, pk, sk, Y, v, &ct);
        res.result_size  = static_cast<int>(res.intersection.size());

        std::set<std::string> output_set(res.intersection.begin(), res.intersection.end());
        for (const auto& elem : res.intersection)
            if (!ground_truth.count(elem)) res.false_positives++;
        for (const auto& elem : ground_truth)
            if (!output_set.count(elem))   res.false_negatives++;

        res.fp_rate = res.result_size > 0
            ? static_cast<double>(res.false_positives) / res.result_size : 0.0;
    }
    else if (cfg.protocol == "apsi_ca") {
        res.result_size = client_apsi_ca(client_fd, gm, pk, sk, Y, v, "127.0.0.1", CA_PORT, &ct);
        res.false_positives = std::max(0, res.result_size - res.true_intersection);
        res.false_negatives = std::max(0, res.true_intersection - res.result_size);
        res.fp_rate = res.result_size > 0
            ? static_cast<double>(res.false_positives) / res.result_size : 0.0;
    }
    else if (cfg.protocol == "apsi") {
        res.intersection = client_apsi(client_fd, gm, pk, sk, Y, v, "127.0.0.1", CA_PORT, &ct);
        res.result_size  = static_cast<int>(res.intersection.size());

        std::set<std::string> output_set(res.intersection.begin(), res.intersection.end());
        for (const auto& elem : res.intersection)
            if (!ground_truth.count(elem)) res.false_positives++;
        for (const auto& elem : ground_truth)
            if (!output_set.count(elem))   res.false_negatives++;

        res.fp_rate = res.result_size > 0
            ? static_cast<double>(res.false_positives) / res.result_size : 0.0;
    }

    res.client = ct;

    CLOSE_SOCKET(client_fd);

    server_thread.join();
    if (ca_thread.joinable()) {
        ca_thread.join();
        if (ca_exception) std::rethrow_exception(ca_exception);
    }
    CLOSE_SOCKET(listen_fd);
    if (ca_listen_fd != (sock_t)-1) CLOSE_SOCKET(ca_listen_fd);

    res.server = srv_future.get();   // rethrows if server thread threw
    return res;
}

// ── Output helpers ────────────────────────────────────────────────────────────

static void print_run_summary(const ExperimentConfig& cfg, const RunResult& r) {
    std::cout << "\n=== Run " << r.run << " | " << cfg.protocol
              << " | client=" << cfg.client_size << " server=" << cfg.server_size << " ===\n"
              << std::fixed << std::setprecision(2)
              << "  Keygen:           " << r.keygen_ms          << " ms\n"
              << "  BF build+encrypt: " << r.client.bf_build_ms << " ms\n"
              << "  Client send BF:   " << r.client.send_ms      << " ms\n"
              << "  Server recv BF:   " << r.server.recv_bf_ms   << " ms\n"
              << "  Server compute:   " << r.server.compute_ms   << " ms\n"
              << "  Server send resp: " << r.server.send_ms      << " ms\n"
              << "  Client recv resp: " << r.client.recv_ms      << " ms\n"
              << "  Client decrypt:   " << r.client.decrypt_ms   << " ms\n"
              << "  Total client:     " << r.client.total_ms     << " ms\n"
              << "  Total server:     " << r.server.total_ms     << " ms\n"
              << "  Client->Server:   " << r.client.bytes_sent / 1024.0 << " KB\n"
              << "  Server->Client:   " << r.server.bytes_sent / 1024.0 << " KB\n"
              << (r.client.bytes_ca_send > 0
                  ? "  Client->CA:       " + std::to_string(r.client.bytes_ca_send / 1024.0) + " KB\n"
                    "  CA->Client:       " + std::to_string(r.client.bytes_ca_recv / 1024.0) + " KB\n"
                  : "")
              << "  Total comm:       " << (r.client.bytes_sent + r.server.bytes_sent
                                          + r.client.bytes_ca_send + r.client.bytes_ca_recv) / 1024.0 << " KB\n"
              << "  Result size:      " << r.result_size          << "\n"
              << "  True intersect:   " << r.true_intersection    << "\n"
              << "  False positives:  " << r.false_positives      << "\n"
              << "  False negatives:  " << r.false_negatives      << "\n"
              << std::setprecision(6)
              << "  FP rate:          " << r.fp_rate              << "\n";
}

static void write_intersection_file(const RunResult& r, const ExperimentConfig& cfg) {
    if (r.intersection.empty()) return;
    std::string fname = "intersection_" + cfg.protocol
        + "_c" + std::to_string(cfg.client_size)
        + "_s" + std::to_string(cfg.server_size)
        + "_run" + std::to_string(r.run) + ".txt";
    std::ofstream f(fname);
    for (const auto& e : r.intersection) f << e << "\n";
    std::cout << "  Intersection written to " << fname << "\n";
}

static void write_csv_header(std::ofstream& f) {
    f << "protocol,k,client_size,server_size,run,client_seed,server_seed,"
         "keygen_ms,bf_build_ms,client_send_ms,"
         "server_recv_ms,server_compute_ms,server_send_ms,"
         "client_recv_ms,decrypt_ms,total_client_ms,total_server_ms,"
         "bytes_client_to_server,bytes_server_to_client,bytes_client_to_ca,bytes_ca_to_client,total_bytes,"
         "result_size,true_intersection,false_positives,false_negatives,fp_rate\n";
}

static void write_csv_row(std::ofstream& f, const ExperimentConfig& cfg, const RunResult& r) {
    f << cfg.protocol    << ","
      << cfg.k          << ","
      << cfg.client_size << ","
      << cfg.server_size << ","
      << r.run           << ","
      << r.client_seed   << ","
      << r.server_seed   << ","
      << std::fixed << std::setprecision(3)
      << r.keygen_ms             << ","
      << r.client.bf_build_ms    << ","
      << r.client.send_ms        << ","
      << r.server.recv_bf_ms     << ","
      << r.server.compute_ms     << ","
      << r.server.send_ms        << ","
      << r.client.recv_ms        << ","
      << r.client.decrypt_ms     << ","
      << r.client.total_ms       << ","
      << r.server.total_ms       << ","
      << r.client.bytes_sent     << ","
      << r.server.bytes_sent     << ","
      << r.client.bytes_ca_send  << ","
      << r.client.bytes_ca_recv  << ","
      << (r.client.bytes_sent + r.server.bytes_sent
        + r.client.bytes_ca_send + r.client.bytes_ca_recv) << ","
      << r.result_size           << ","
      << r.true_intersection     << ","
      << r.false_positives       << ","
      << r.false_negatives       << ","
      << std::setprecision(8)
      << r.fp_rate               << "\n";
}

static void write_csv_avg_row(std::ofstream& f, const ExperimentConfig& cfg,
                              const std::vector<RunResult>& results) {
    if (results.empty()) return;
    double n = static_cast<double>(results.size());
    double keygen = 0, bf_build = 0, c_send = 0, s_recv = 0, s_compute = 0,
           s_send = 0, c_recv = 0, decrypt = 0, c_total = 0, s_total = 0,
           bytes_cs = 0, bytes_sc = 0, bytes_ca_s = 0, bytes_ca_r = 0, total_b = 0,
           res_sz = 0, true_int = 0, fp = 0, fn = 0, fp_rate = 0;
    for (const auto& r : results) {
        keygen    += r.keygen_ms;
        bf_build  += r.client.bf_build_ms;
        c_send    += r.client.send_ms;
        s_recv    += r.server.recv_bf_ms;
        s_compute += r.server.compute_ms;
        s_send    += r.server.send_ms;
        c_recv    += r.client.recv_ms;
        decrypt   += r.client.decrypt_ms;
        c_total   += r.client.total_ms;
        s_total   += r.server.total_ms;
        bytes_cs  += static_cast<double>(r.client.bytes_sent);
        bytes_sc  += static_cast<double>(r.server.bytes_sent);
        bytes_ca_s += static_cast<double>(r.client.bytes_ca_send);
        bytes_ca_r += static_cast<double>(r.client.bytes_ca_recv);
        total_b   += static_cast<double>(r.client.bytes_sent + r.server.bytes_sent
                                       + r.client.bytes_ca_send + r.client.bytes_ca_recv);
        res_sz    += r.result_size;
        true_int  += r.true_intersection;
        fp        += r.false_positives;
        fn        += r.false_negatives;
        fp_rate   += r.fp_rate;
    }
    // seed columns: fixed seed value if all runs used the same seed, blank otherwise
    std::string cs_col = cfg.client_seed_fixed ? std::to_string(cfg.client_seed) : "";
    std::string ss_col = cfg.server_seed_fixed ? std::to_string(cfg.server_seed) : "";
    f << cfg.protocol    << ","
      << cfg.k          << ","
      << cfg.client_size << ","
      << cfg.server_size << ","
      << "avg"           << ","
      << cs_col          << ","
      << ss_col          << ","
      << std::fixed << std::setprecision(3)
      << keygen   / n << ","
      << bf_build / n << ","
      << c_send   / n << ","
      << s_recv   / n << ","
      << s_compute/ n << ","
      << s_send   / n << ","
      << c_recv   / n << ","
      << decrypt  / n << ","
      << c_total  / n << ","
      << s_total  / n << ","
      << std::setprecision(1)
      << bytes_cs   / n << ","
      << bytes_sc   / n << ","
      << bytes_ca_s / n << ","
      << bytes_ca_r / n << ","
      << total_b    / n << ","
      << std::setprecision(3)
      << res_sz   / n << ","
      << true_int / n << ","
      << fp       / n << ","
      << fn       / n << ","
      << std::setprecision(8)
      << fp_rate  / n << "\n";
}

// ── Argument parsing ──────────────────────────────────────────────────────────

static void print_usage(const char* prog) {
    std::cerr
        << "Usage: " << prog << " [options]\n"
        << "  --protocol/-p  <psi|psi_ca|apsi|apsi_ca>  (default: " << EXP_PROTOCOL     << ")\n"
        << "  --client/-c    <size>                      (default: " << CLIENT_SET_SIZE   << ")\n"
        << "  --server/-s    <size>                      (default: " << SERVER_SET_SIZE   << ")\n"
        << "  -k             <uint>                      (default: " << K                 << ")\n"
        << "  --universe     <size>                      (default: full dataset)\n"
        << "  --runs/-r      <count>                     (default: " << EXP_RUNS          << ")\n"
        << "  --output/-o    <file.csv>                  (default: " << EXP_OUTPUT        << ")\n"
        << "  --dataset/-d   <path>                      (default: " << DATASET_PATH      << ")\n"
        << "  --client-seed  <uint64>                    (default: random per run)\n"
        << "  --server-seed  <uint64>                    (default: random per run)\n"
        << "  --help/-h\n";
}

static ExperimentConfig parse_args(int argc, char* argv[]) {
    ExperimentConfig cfg;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if      ((a == "--protocol"    || a == "-p") && i+1 < argc) cfg.protocol    =           argv[++i];
        else if ((a == "--client"      || a == "-c") && i+1 < argc) cfg.client_size = std::stoul(argv[++i]);
        else if ((a == "--server"      || a == "-s") && i+1 < argc) cfg.server_size = std::stoul(argv[++i]);
        else if ((a == "--runs"        || a == "-r") && i+1 < argc) cfg.runs        = std::stoi (argv[++i]);
        else if ((a == "--output"      || a == "-o") && i+1 < argc) cfg.output_file =           argv[++i];
        else if ((a == "--dataset"     || a == "-d") && i+1 < argc) cfg.dataset     =           argv[++i];
        else if  (a == "--client-seed"               && i+1 < argc) { cfg.client_seed = std::stoull(argv[++i]); cfg.client_seed_fixed = true; }
        else if  (a == "--server-seed"               && i+1 < argc) { cfg.server_seed = std::stoull(argv[++i]); cfg.server_seed_fixed = true; }
        else if  (a == "-k"                          && i+1 < argc)   cfg.k             = std::stoul(argv[++i]);
        else if  (a == "--universe"                  && i+1 < argc)   cfg.universe_size = std::stoul(argv[++i]);
        else if (a == "--help" || a == "-h") { print_usage(argv[0]); exit(0); }
        else { std::cerr << "Unknown argument: " << a << "\n"; print_usage(argv[0]); exit(1); }
    }
    return cfg;
}

// ── Main ──────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    ExperimentConfig cfg = parse_args(argc, argv);
    K = cfg.k;  // propagate to all protocol TUs via inline global

    std::cout << "=== PSI Experiment Runner ===\n"
              << "Protocol:    " << cfg.protocol    << "\n"
              << "K:           " << cfg.k           << "\n"
              << "Client size: " << cfg.client_size << "\n"
              << "Server size: " << cfg.server_size << "\n"
              << "Universe:    " << (cfg.universe_size > 0 ? std::to_string(cfg.universe_size) : "full") << "\n"
              << "Runs:        " << cfg.runs        << "\n"
              << "Output:      " << cfg.output_file << "\n"
              << "Dataset:     " << cfg.dataset     << "\n"
              << "Client seed: " << (cfg.client_seed_fixed ? std::to_string(cfg.client_seed) : "random") << "\n"
              << "Server seed: " << (cfg.server_seed_fixed ? std::to_string(cfg.server_seed) : "random") << "\n\n";

    // Used only when seeds are not fixed; provides independent samples across runs
    std::random_device rd;
    std::mt19937_64 seed_rng(rd());

    // Derive avg filename: "results.csv" -> "results_avg.csv"
    std::string avg_file = cfg.output_file;
    auto dot = avg_file.rfind('.');
    if (dot != std::string::npos)
        avg_file.insert(dot, "_avg");
    else
        avg_file += "_avg";

    // Open per-run CSV (append; write header only for new files)
    bool is_new = !std::ifstream(cfg.output_file).good();
    std::ofstream csv(cfg.output_file, std::ios::app);
    if (!csv) throw std::runtime_error("Cannot open output file: " + cfg.output_file);
    if (is_new) write_csv_header(csv);

    // Open avg CSV (append; write header only for new files)
    bool avg_is_new = !std::ifstream(avg_file).good();
    std::ofstream avg_csv(avg_file, std::ios::app);
    if (!avg_csv) throw std::runtime_error("Cannot open avg output file: " + avg_file);
    if (avg_is_new) write_csv_header(avg_csv);

    int failed = 0;
    std::vector<RunResult> all_results;
    all_results.reserve(cfg.runs);

    for (int run = 1; run <= cfg.runs; run++) {
        // Fixed seed: same dataset every run (timing reproducibility).
        // Random seed: fresh sample every run (statistical averaging).
        uint64_t run_client_seed = cfg.client_seed_fixed ? cfg.client_seed : seed_rng();
        uint64_t run_server_seed = cfg.server_seed_fixed ? cfg.server_seed : seed_rng();

        auto X = load_dataset(cfg.dataset, cfg.server_size, run_server_seed, cfg.universe_size);
        auto Y = load_dataset(cfg.dataset, cfg.client_size, run_client_seed, cfg.universe_size);
        auto ground_truth = compute_ground_truth(X, Y);

        std::cout << "[Run " << run << "] client_seed=" << run_client_seed
                  << " server_seed=" << run_server_seed
                  << " ground_truth=" << ground_truth.size() << "\n";

        try {
            RunResult result = run_experiment(run, cfg, X, Y, ground_truth);
            result.client_seed = run_client_seed;
            result.server_seed = run_server_seed;
            print_run_summary(cfg, result);
            write_csv_row(csv, cfg, result);
            if (cfg.protocol == "psi" || cfg.protocol == "apsi")
                write_intersection_file(result, cfg);
            all_results.push_back(result);
        } catch (const std::exception& e) {
            std::cerr << "[ERROR] Run " << run << " failed: " << e.what() << "\n";
            failed++;
        }
    }

    if (!all_results.empty())
        write_csv_avg_row(avg_csv, cfg, all_results);

    std::cout << "\nPer-run results appended to " << cfg.output_file << "\n"
              << "Averaged results appended to " << avg_file << "\n";
    if (failed) std::cerr << failed << " run(s) failed.\n";

#ifdef _WIN32
    WSACleanup();
#endif
    return failed ? 1 : 0;
}
