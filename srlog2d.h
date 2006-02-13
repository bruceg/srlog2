#ifndef SRLOG2D__H
#define SRLOG2D__H

#include <str/str.h>

#define STATS_INTERVAL 10000

extern uint64 stats_next;
extern uint64 packets_received;
extern uint64 packets_sent;
extern uint64 bytes_received;
extern uint64 bytes_sent;
extern uint64 msg_retransmits;
extern uint64 msg_valid;
extern uint64 ini_queued;
extern uint64 ini_too_many;
extern uint64 ini_invalid;
extern uint64 ini_unknown_sender;
extern uint64 ini_unknown_parameter;
extern uint64 ini_failed_auth;
extern uint64 ini_missing_key;
extern uint64 ini_valid;
extern uint64 lines_written;
extern uint64 bytes_written;

extern int sock;
extern ipv4addr ip;
extern ipv4port port;

extern str line;
extern str packet;
extern str tmp;

extern void send_packet(void);

extern void show_stats(void);
extern void handle_srq(void);

#endif
