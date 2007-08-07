#ifndef SRLOG2D__H
#define SRLOG2D__H

#include "srlog2.h"

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

extern int logger;
extern int sock;
extern ipv4addr ip;
extern ipv4port port;

extern str line;
extern str packet;
extern str tmp;

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

struct services_entry;
struct connection_data
{
  AUTH_CTX authenticator;
  DECR_CTX decryptor;
  struct services_entry* service;
};

GHASH_DECL(connections,struct connection_key,struct connection_data);

extern struct ghash connections;
extern const char* format_connection(const struct connections_entry* c);
void error_connection(const struct connections_entry* c, const char* s);
void error_connection3(const struct connections_entry* c, const char* s,
		   uint64 u1, uint64 u2);
void warn_connection(const struct connections_entry* c, const char* s);
void warn_connection3(const struct connections_entry* c, const char* s,
		  uint64 u1, uint64 u2);

/* senders.c */
struct sender_data
{
  struct keylist keys;
};

GHASH_DECL(senders, str, struct sender_data);

extern struct ghash senders;

extern void load_senders(int reload);

/* services.c */
struct service_key
{
  str sender;
  str service;
};

struct service_data
{
  struct keylist keys;
  uint64 next_seq;
  uint64 last_seq;
  unsigned long last_count;
  struct timestamp last_timestamp;
  struct connections_entry* connection;
  struct senders_entry* sender;
};

GHASH_DECL(services,struct service_key,struct service_data);

extern struct ghash services;
extern const char* format_service(const struct services_entry* c);
extern void load_services(int reload);
extern struct services_entry* find_service(const char* sender,
					   const char* service);

/* srlog2d.c */
extern void send_packet(void);
extern int tslt(const struct timestamp* a, const struct timestamp* b);
extern void msgpkt2(const char* msg);
extern void msgpkt3(const char* msg);

/* srlog2d-ini.c */
extern void handle_ini(void);
extern void init_ini(void);

/* srlog2d-msg.c */
extern void handle_msg(void);

/* srlog2d-prf.c */
extern void handle_prq(void);

/* srlog2d-stats.c */
extern void show_stats(void);
extern void handle_srq(void);

#endif
