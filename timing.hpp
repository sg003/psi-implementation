#ifndef TIMING_HPP
#define TIMING_HPP

struct ClientTiming {
    double bf_build_ms   = 0;
    double send_ms       = 0;
    double recv_ms       = 0;
    double decrypt_ms    = 0;
    double total_ms      = 0;
    size_t bytes_sent    = 0;  // client → PSI server (encrypted BF)
    size_t bytes_recv    = 0;  // PSI server → client (protocol response)
    size_t bytes_ca_send = 0;  // client → CA (apsi/apsi_ca only)
    size_t bytes_ca_recv = 0;  // CA → client (apsi/apsi_ca only)
};

struct ServerTiming {
    double recv_bf_ms  = 0;
    double compute_ms  = 0;
    double send_ms     = 0;
    double total_ms    = 0;
    size_t bytes_recv  = 0;  // client → server (encrypted BF)
    size_t bytes_sent  = 0;  // server → client (protocol response)
};

#endif
