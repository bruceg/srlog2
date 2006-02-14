#ifndef SRLOG2D__H
#define SRLOG2D__H

#include "srlog2.h"

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

/* connections.c */
struct connection_key
{
  ipv4port port;
  ipv4addr ip;
};

struct connection_data
{
  time_t rotate_at;
  uint64 next_seq;
  uint64 last_seq;
  struct timestamp last_timestamp;
  int fd;
  AUTH_CTX authenticator;
  DECR_CTX decryptor;
  unsigned long last_count;
  str dir;
};

GHASH_DECL(connections,struct connection_key,struct connection_data);

extern struct ghash connections;
void msg_connection(const struct connections_entry* c, const char* a, const char* b);
void error_connection(const struct connections_entry* c, const char* s);
void error_connection3(const struct connections_entry* c, const char* s,
		   uint64 u1, uint64 u2);
void warn_connection(const struct connections_entry* c, const char* s);
void warn_connection3(const struct connections_entry* c, const char* s,
		  uint64 u1, uint64 u2);

/* senders.c */
struct sender_key
{
  str sender;
  str service;
};

struct sender_data
{
  DECR_CTX decryptor;
  str dir;
  struct connection_key* connection;
  struct keylist keys;
};

GHASH_DECL(senders,struct sender_key,struct sender_data);

extern struct ghash senders;
void msg_sender(const struct senders_entry* c, const char* a, const char* b);
void error_sender(const struct senders_entry* c, const char* s);
void error_sender3(const struct senders_entry* c, const char* s,
		   uint64 u1, uint64 u2);
void warn_sender(const struct senders_entry* c, const char* s);
void warn_sender3(const struct senders_entry* c, const char* s,
		  uint64 u1, uint64 u2);
void load_senders(int reload);
struct senders_entry* find_sender(const char* sender, const char* service);

/* srlog2d.c */
extern void send_packet(void);
extern void reopen(struct connections_entry* c, const struct timestamp* ts);
extern int tslt(const struct timestamp* a, const struct timestamp* b);
extern void msgpkt2(const char* msg);
extern void msgpkt3(const char* msg);

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
