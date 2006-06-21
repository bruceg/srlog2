/* $Id$ */
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

#include <iobuf/iobuf.h>
#include <msg/msg.h>
#include <misc/misc.h>
#include <str/str.h>

#include "srlog2.h"

static const char buffer_filename[] = "buffer";

#define ENTER() do{ debug2(DEBUG_BUFFER, "buffer: ENTER ", __FUNCTION__); }while(0)
#define DEBUG1(X) do{ debug2(DEBUG_BUFFER, "buffer: ", X); }while(0)
#define DEBUG2(X,Y) do{ debug3(DEBUG_BUFFER, "buffer: ", X,Y); }while(0)

static unsigned long clean_bytes = 100000;

/* Buffering --------------------------------------------------------------- */
static obuf writebuf;
static ibuf readbuf;

static const struct line* parse_buffered_line(const str* s)
{
  static struct line line;
  char* end;
  line.seq = strtoull(s->s, &end, 10);
  if (*end++ != ' ') die1(1, "Format error in buffer file: bad sequence");
  line.timestamp.sec = strtoul(end, &end, 10);
  if (*end++ != '.') die1(1, "Format error in buffer file: bad timestamp");
  line.timestamp.nsec = strtoul(end, &end, 10);
  if (*end++ != ' ') die1(1, "Format error in buffer file: bad utimestamp");
  if (!str_copyb(&line.line, end, s->len - (end - s->s)))
    die1(1, "Out of memory");
  return &line;
}

static uint64 seq_read;

/** Mark the buffer as empty. */
static void buffer_empty(void)
{
  ENTER();
  if (readbuf.io.offset >= clean_bytes) {
    DEBUG1("Truncating file");
    obuf_flush(&writebuf);
    obuf_rewind(&writebuf);
    ibuf_close(&readbuf);
    readbuf.io.fd = 0;
    if (writebuf.io.fd != 0 &&
	ftruncate(writebuf.io.fd, 0) != 0)
      die1sys(1, "Could not truncate buffer");
  }
  seq_read = seq_next;
}

static const struct line* buffer_next(void)
{
  const struct line* line;
  static str tmpstr;
  ENTER();
  if (readbuf.io.fd == 0) {
    if (!ibuf_open(&readbuf, buffer_filename, 0)) {
      seq_read = seq_send = seq_next;
      DEBUG1("No buffer file");
      return 0;
    }
  }
  while (ibuf_getstr(&readbuf, &tmpstr, LF)) {
    --tmpstr.len;
    line = parse_buffered_line(&tmpstr);
    DEBUG2("Read #", utoa(line->seq));
    if (line->seq < seq_read)
      continue;
    if (line->seq != seq_read)
      seq_read = line->seq;
    ++seq_read;
    return line;
  }
  if (!ibuf_eof(&readbuf))
    die1sys(1, "Could not read next buffered line");
  readbuf.io.flags &= ~IOBUF_EOF;
  DEBUG1("No lines remain in buffer");
  return 0;
}

static const struct line* last_line = 0;

/** Look at the next line in the buffer without advancing. */
const struct line* buffer_file_peek(void)
{
  ENTER();
  if (last_line == 0)
    last_line = buffer_next();
  return last_line;
}

/** Read and advance past the next line in the buffer. */
const struct line* buffer_file_read(void)
{
  const struct line* line;
  ENTER();
  if ((line = last_line) == 0)
    line = buffer_next();
  last_line = 0;
  return line;
}

static void buffer_file_sync(void)
{
  if (writebuf.io.fd != 0)
    fsync(writebuf.io.fd);
}

/** Rewind the buffer to the last mark point. */
void buffer_file_rewind(void)
{
  ENTER();
  if (!ibuf_rewind(&readbuf))
    die1sys(111, "Could not rewind buffer");
  seq_read = seq_send;
  last_line = 0;
  buffer_file_sync();
}

/** "Remove" all read lines from the buffer and advance the mark point. */
void buffer_file_pop(void)
{
  ENTER();
  seq_send = seq_read;
  save_seq();
  if (last_line == 0 && seq_send >= seq_next)
    buffer_empty();
}

/** Add a line to the end of the buffer. */
void buffer_file_push(const struct line* line)
{
  ENTER();
  save_seq();
  if (writebuf.io.fd == 0) {
    DEBUG1("Opening file");
    if (!obuf_open(&writebuf, buffer_filename,
		   OBUF_CREATE/*|OBUF_EXCLUSIVE*/|OBUF_APPEND, 0644, 0))
      die1sys(1, "Could not open buffer file for writing");
  }
  obuf_putull(&writebuf, line->seq);
  obuf_putc(&writebuf, ' ');
  obuf_putull(&writebuf, line->timestamp.sec);
  obuf_putc(&writebuf, '.');
  obuf_putuwll(&writebuf, line->timestamp.nsec, 9, '0');
  obuf_putc(&writebuf, ' ');
  obuf_putstr(&writebuf, &line->line);
  obuf_putc(&writebuf, LF);
  obuf_flush(&writebuf);
}

void buffer_file_init(void)
{
  const char* env;
  if ((env = getenv("CLEAN_BYTES")) != 0)
    clean_bytes = strtoul(env, 0, 10);
  open_read_seq();
  seq_read = seq_send;
  atexit(buffer_file_sync);
}