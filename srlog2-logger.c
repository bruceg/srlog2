/* $Id$ */
#include <string.h>
#include <unistd.h>

#include <systime.h>
#include <adt/ghash.h>
#include <crc/crc32.h>
#include <iobuf/ibuf.h>
#include <msg/msg.h>
#include <msg/wrap.h>
#include <str/str.h>

#include "srlog2.h"
#include "srlog2-logger-cli.h"

/*****************************************************************************/
struct sender_data
{
  time_t rotate_at;
  int fd;
};

static uint32 sender_hash(str const* key)
{
  return crc32_block(key->s, key->len);
}

static int sender_datacopy(struct sender_data* a, struct sender_data const* b)
{
  a->fd = b->fd;
  a->rotate_at = b->rotate_at;
  return 1;
}

GHASH_DECL(senders, str, struct sender_data);
GHASH_DEFN(senders, str, struct sender_data,
	   sender_hash, str_diff,
	   str_copy, sender_datacopy, 0, 0);

static struct ghash senders = {0,0,0,0,0,0,0,0,0,0,0};

/*****************************************************************************/
static const char* parse_part(const char* s, unsigned long* result)
{
  int i;
  unsigned long u = 0;
  for (i = 0; i < 8; ++i, ++s) {
    u *= 16;
    if (*s >= '0' && *s <= '9')
      u += *s - '0';
    else if (*s >= 'a' && *s <= 'f')
      u += *s - 'a' + 10;
    else if (*s >= 'A' && *s <= 'F')
      u += *s - 'A' + 10;
    else
      return 0;
  }
  *result = u;
  return s;
}

static int parse_timestamp(const str* line, struct timestamp* ts)
{
  const char* s;
  if (line->len < 26)
    return 0;
  s = line->s;
  if (memcmp(s, "@40000000", 9) != 0)
    return 0;
  s += 9;
  ts->sec = ts->nsec = 0;
  if ((s = parse_part(s, &ts->sec)) == 0)
    return 0;
  if ((s = parse_part(s, &ts->nsec)) == 0)
    return 0;
  return s - line->s;
}

/*****************************************************************************/
static const char* make_filename(const struct tm* lt)
{
  static char timebuf[100];
  const char* format;

  switch (opt_rotate) {
  case 1: format = "%Y-%m-%d-%H"; break;
  default: format = "%Y-%m-%d"; break;
  }

  timebuf[strftime(timebuf, sizeof timebuf, format, lt)] = 0;
  return timebuf;
}

static time_t next_rotate(struct tm* lt)
{
  switch (opt_rotate) {
  case 1:
    ++lt->tm_hour;
    break;
  default:
    ++lt->tm_mday;
    lt->tm_hour = 0;
  }
  lt->tm_sec = 0;
  lt->tm_min = 0;
  return mktime(lt);
}

static void make_path(str* path,
		      const struct senders_entry* s,
		      const char* suffix)
{
  wrap_str(str_copy(path, &s->key));
  str_subst(path, ' ', '/');
  wrap_str(str_catc(path, '/'));
  wrap_str(str_cats(path, suffix));
}

static void test_reopen(struct senders_entry* s,
			struct timestamp* ts)
{
  static str path;
  const char* filename;
  struct tm* lt;
  time_t sec;

  if (ts->sec >= s->data.rotate_at) {
    if (s->data.fd > 0) {
      fsync(s->data.fd);
      close(s->data.fd);
    }

    sec = ts->sec;
    lt = localtime(&sec);

    filename = make_filename(lt);
    make_path(&path, s, filename);
    
    debug2(1, "Opening ", path.s);
    if ((s->data.fd = open(path.s, O_WRONLY|O_CREAT|O_APPEND, 0644)) == -1)
      warnfsys("{Could not open '}s{'}", path.s);
    else {
      make_path(&path, s, "current");
      unlink(path.s);
      if (symlink(filename, path.s) == -1)
	diefsys(1, "{Could not create symlink '}s{'}", path.s);
    }
    s->data.rotate_at = next_rotate(lt);
  }
}

static struct senders_entry* parse_line(str* line)
{
  static str key;
  int i;
  int j;
  struct timestamp ts;
  struct senders_entry* s;

  s = 0;
  if ((i = parse_timestamp(line, &ts)) > 0
      && line->s[i] == ' '
      && (j = str_findnext(line, ' ', i + 1)) > 0
      && (j = str_findnext(line, ' ', j + 1)) > 0) {
    i++;
    wrap_str(str_copyb(&key, line->s + i, j - i));
    str_spliceb(line, i, j - i + 1, 0, 0);

    if ((s = senders_get(&senders, &key)) == 0) {
      struct sender_data data;
      memset(&data, 0, sizeof data);
      wrap_str(senders_add(&senders, &key, &data));
      s = senders_get(&senders, &key);
    }

    test_reopen(s, &ts);
  }
  return s;
}

int cli_main(int argc, char* argv[])
{
  str line = {0,0,0};
  struct senders_entry* s;
  
  msg_debug_init();
  senders_init(&senders);

  while (ibuf_getstr(&inbuf, &line, LF)) {
    if ((s = parse_line(&line)) != 0)
      write(s->data.fd, line.s, line.len);
  }

  return 0;
  (void)argc;
  (void)argv;
}