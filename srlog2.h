#ifndef SRLOG__H__
#define SRLOG__H__

#include <uint32.h>
#include <uint64.h>
#include <adt/ghash.h>
#include <msg/msg.h>
#include <net/ipv4.h>
#include <str/str.h>

#include "key.h"
#include "keylist.h"
#include "authenticator.h"
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
#define MAX_LINE (MAX_PACKET-4-4-8-1-8-2-ENCR_BLOCK_SIZE-4-AUTH_LENGTH)

#define DEBUG_STATE 1
#define DEBUG_PACKET 2
#define DEBUG_QUEUE 4
#define DEBUG_BUFFER 8
#define DEBUG_MSG 16
#define DEBUG_SEQ 32

#define SET_SEQ(X) do{ \
	debugf(DEBUG_SEQ, "{setting }s{ = }llu", #X, X); \
}while(0)

struct timestamp
{
  unsigned long sec;
  unsigned long nsec;
};

struct line
{
  struct timestamp timestamp;
  uint64 seq;
  str line;
};

/* packet.c */
extern void auth_start(AUTH_CTX* ctx, const struct key* key);
extern int pkt_start(str* s, uint32 type);
extern int pkt_add_u1(str* s, unsigned u);
extern int pkt_add_u2(str* s, unsigned u);
extern int pkt_add_u4(str* s, uint32 u);
extern int pkt_add_u8(str* s, uint64 u);
extern int pkt_add_ts(str* s, const struct timestamp*);
extern int pkt_add_s1(str* s, const str* l);
extern int pkt_add_s1c(str* s, const char* l);
extern int pkt_add_s2(str* s, const str* l);
extern int pkt_add_b(str* s, const unsigned char* data, unsigned len);
extern int pkt_add_key(str* s, const struct key* k);
extern int pkt_add_cc(str* s, const AUTH_CTX* ctx);
extern unsigned pkt_get_u1(const str* s, unsigned o, unsigned* u);
extern unsigned pkt_get_u2(const str* s, unsigned o, unsigned* u);
extern unsigned pkt_get_u4(const str* s, unsigned o, uint32* u);
extern unsigned pkt_get_u8(const str* s, unsigned o, uint64* u);
extern unsigned pkt_get_ts(const str* s, unsigned o, struct timestamp*);
extern unsigned pkt_get_b(const str* s, unsigned o, str* l, unsigned len);
extern unsigned pkt_get_s1(const str* s, unsigned o, str* l);
extern unsigned pkt_get_s2(const str* s, unsigned o, str* l);
extern unsigned pkt_get_key(const str* s, unsigned o, struct key* k,
			    const struct key_cb* cb);
extern int pkt_validate(str* s, const AUTH_CTX* ctx);

/* random.c */
extern void brandom_init(void);
extern void brandom_fill(unsigned char* buf, unsigned len);

/* sequence.c */
extern uint64 seq_next;		/* Next line is assigned this number */
extern uint64 seq_send;		/* Next line to send has this number */

extern void save_seq(void);
extern void open_read_seq(void);

/* writeall.c */
extern void delay(const char* msg);
extern void writeall(int fd, const char* buf, size_t len);

/* buffer-file.c */
extern void buffer_file_init(void);
extern const struct line* buffer_file_peek(void);
extern const struct line* buffer_file_read(void);
extern void buffer_file_pop(void);
extern void buffer_file_push(const struct line*);
extern void buffer_file_rewind(void);

/* buffer-nofile.c */
extern const struct line* buffer_nofile_peek(void);
extern const struct line* buffer_nofile_read(void);
extern void buffer_nofile_pop(void);
extern void buffer_nofile_push(const struct line*);
extern void buffer_nofile_rewind(void);

/* addrname.c */
GHASH_DECL(addrname,ipv4addr,const char*);
extern struct ghash addrname;

#endif
