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

#define INI  0xffffffff00000000ULL
#define CID  0xffffffff00000001ULL
#define SRQ  0xffffffff00000002ULL
#define SRP  0xffffffff00000003ULL
#define MMSG 0xffffffff00000004ULL
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

/* packet.c */
extern void hash_start(HASH_CTX* ctx, const nistp224key key);
extern int pkt_add_u1(str* s, unsigned u);
extern int pkt_add_u2(str* s, unsigned u);
extern int pkt_add_u4(str* s, uint32 u);
extern int pkt_add_u8(str* s, uint64 u);
extern int pkt_add_ts(str* s, const struct timestamp*);
extern int pkt_add_s1(str* s, const str* l);
extern int pkt_add_s2(str* s, const str* l);
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
struct sender_addr
{
  ipv4port port;
  ipv4addr ip;
};

struct sender_data
{
  time_t rotate_at;
  uint64 next_seq;
  struct timestamp last_timestamp;
  int fd;
  HASH_CTX ini_authenticator;
  HASH_CTX authenticator;
  DECR_CTX decryptor;
  str service;
  str dir;
  uint64 last_seq;
  unsigned long last_count;
};

GHASH_DECL(senders,struct sender_addr,struct sender_data);
extern struct ghash senders;
void msg_sender(const struct senders_entry* c, const char* a, const char* b);
void error_sender(const struct senders_entry* c, const char* s);
void error_sender3(const struct senders_entry* c, const char* s,
		   uint64 u1, uint64 u2);
void warn_sender(const struct senders_entry* c, const char* s);
void warn_sender3(const struct senders_entry* c, const char* s,
		  uint64 u1, uint64 u2);
void load_senders(int reload);
struct senders_entry* find_sender(const ipv4addr* addr,	const char* service);

#endif
