#ifndef SRLOG2D__H
#define SRLOG2D__H

#include <str/str.h>

#define STATS_INTERVAL 10000

/* Set this to 1 when testing log rotation, and it will rotate logs
   every second instead of every hour */
#define ROLLOVER_SECOND 0

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
extern str sender;

extern str auth_name;
extern str keyex_name;
extern str keyhash_name;
extern str encr_name;
extern str compr_name;

extern struct keylist server_secrets;

extern void send_packet(void);
extern void reopen(struct connections_entry* c, const struct timestamp* ts);
extern int tslt(const struct timestamp* a, const struct timestamp* b);

/* srlog2d-ini.c */
extern void handle_ini(void);

/* srlog2d-msg.c */
extern void handle_msg(void);

/* srlog2d-prf.c */
extern void handle_prq(void);

/* srlog2d-stats.c */
extern void show_stats(void);
extern void handle_srq(void);

#endif
