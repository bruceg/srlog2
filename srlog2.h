#ifndef SRLOG__H__
#define SRLOG__H__

#include <uint32.h>
#include <uint64.h>
#include <adt/ghash.h>
#include <net/ipv4.h>
#include <str/str.h>

#include "key.h"
#include "hash.h"
#include "encr.h"

#define SRL2 0x324c5253UL	/* "SRL2" in LSB format */
#define INI1 0x31494e49UL	/* "INI1" in LSB format */
#define CID1 0x31444943UL
#define MSG1 0x3147534dUL
#define ACK1 0x314b4341UL
#define SRQ1 0x31515253UL
#define SRP1 0x31505253UL
#define PRQ1 0x31515250UL
#define PRF1 0x31465250UL
#define MAX_PACKET 8192

#define DEBUG_STATE 1
#define DEBUG_PACKET 2
#define DEBUG_QUEUE 4
#define DEBUG_BUFFER 8
#define DEBUG_MSG 16

struct timestamp
{
  long sec;
  long nsec;
};

struct line
{
  struct timestamp timestamp;
  uint64 seq;
  str line;
};

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
  HASH_CTX authenticator;
  DECR_CTX decryptor;
  unsigned long last_count;
  str dir;
};

GHASH_DECL(connections,struct connection_key,struct connection_data);

struct sender_key
{
  str sender;
  str service;
};

struct sender_data
{
  int fd;
  HASH_CTX ini_authenticator;
  DECR_CTX decryptor;
  str dir;
  struct connection_key* connection;
};

GHASH_DECL(senders,struct sender_key,struct sender_data);

/* packet.c */
extern void hash_start(HASH_CTX* ctx, const nistp224key key);
extern int pkt_add_u1(str* s, unsigned u);
extern int pkt_add_u2(str* s, unsigned u);
extern int pkt_add_u4(str* s, uint32 u);
extern int pkt_add_u8(str* s, uint64 u);
extern int pkt_add_ts(str* s, const struct timestamp*);
extern int pkt_add_s1(str* s, const str* l);
extern int pkt_add_s1c(str* s, const char* l);
extern int pkt_add_s2(str* s, const str* l);
extern int pkt_add_b(str* s, const char* data, unsigned len);
extern int pkt_add_key(str* s, const nistp224key k);
extern int pkt_add_cc(str* s, const HASH_CTX* ctx);
extern unsigned pkt_get_u1(const str* s, unsigned o, unsigned* u);
extern unsigned pkt_get_u2(const str* s, unsigned o, unsigned* u);
extern unsigned pkt_get_u4(const str* s, unsigned o, uint32* u);
extern unsigned pkt_get_u8(const str* s, unsigned o, uint64* u);
extern unsigned pkt_get_ts(const str* s, unsigned o, struct timestamp*);
extern unsigned pkt_get_b(const str* s, unsigned o, str* l, unsigned len);
extern unsigned pkt_get_s1(const str* s, unsigned o, str* l);
extern unsigned pkt_get_s2(const str* s, unsigned o, str* l);
extern unsigned pkt_get_key(const str* s, unsigned o, nistp224key k);
extern int pkt_validate(str* s, const HASH_CTX* ctx);

/* random.c */
extern void brandom_init(unsigned size, unsigned maxuses);
extern void brandom_fill(char* buf, unsigned len);

/* sequence.c */
extern uint64 seq_next;		/* Next line is assigned this number */
extern uint64 seq_send;		/* Next line to send has this number */

extern void save_seq(void);
extern void open_read_seq(void);

/* buffer.c */
extern int buffer_inuse;
extern void buffer_init(void);
extern const struct line* buffer_peek(void);
extern const struct line* buffer_read(void);
extern void buffer_pop(void);
extern void buffer_push(const struct line*);
extern void buffer_sync(void);
extern void buffer_rewind(void);

/* addrname.c */
GHASH_DECL(addrname,ipv4addr,const char*);
extern struct ghash addrname;

/* senders.c */
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

/* connections.c */
extern struct ghash connections;
void msg_connection(const struct connections_entry* c, const char* a, const char* b);
void error_connection(const struct connections_entry* c, const char* s);
void error_connection3(const struct connections_entry* c, const char* s,
		   uint64 u1, uint64 u2);
void warn_connection(const struct connections_entry* c, const char* s);
void warn_connection3(const struct connections_entry* c, const char* s,
		  uint64 u1, uint64 u2);

#endif
