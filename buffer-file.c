#include <sysdeps.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include <iobuf/ibuf.h>
#include <fmt/misc.h>
#include <fmt/number.h>
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
static int writefd = -1;
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
  while (!str_copyb(&line.line, end, s->len - (end - s->s)))
    delay("allocate memory");
  return &line;
}

static uint64 seq_read;		/* The sequence number to read next */

/** Mark the buffer as empty. */
static void buffer_empty(void)
{
  ENTER();
  if (readbuf.io.offset >= clean_bytes) {
    DEBUG1("Truncating file");
    lseek(writefd, 0, SEEK_SET);
    ibuf_close(&readbuf);
    readbuf.io.fd = 0;
    if (writefd >= 0 &&
	(ftruncate(writefd, 0) != 0 || fsync(writefd) != 0))
      die1sys(1, "Could not truncate buffer"); /* Should be impossible */
  }
  SET_SEQ(seq_read = seq_next);
}

static const struct line* buffer_next(void)
{
  const struct line* line;
  static str tmpstr;
  ENTER();
  if (readbuf.io.fd == 0) {
    if (!ibuf_open(&readbuf, buffer_filename, 0)) {
      SET_SEQ(seq_read = seq_send = seq_next);
      DEBUG1("No buffer file");
      return 0;
    }
  }
  while (ibuf_getstr(&readbuf, &tmpstr, LF)) {
    if (tmpstr.len > 0 && tmpstr.s[tmpstr.len-1] == LF)
      --tmpstr.len;
    if (tmpstr.len == 0)
      continue;			/* Skip blank lines */
    line = parse_buffered_line(&tmpstr);
    DEBUG2("Read #", utoa(line->seq));
    if (line->seq < seq_read)
      continue;
    if (line->seq != seq_read)
      SET_SEQ(seq_read = line->seq);
    return line;
  }
  if (!ibuf_eof(&readbuf))
    die1sys(1, "Could not read next buffered line"); /* Should not happen */
  readbuf.io.flags &= ~IOBUF_EOF;
  DEBUG1("No lines remain in buffer");
  return 0;
}

static const struct line* last_line = 0;

/** Look at the next line in the buffer without advancing. */
static const struct line* buffer_file_peek(void)
{
  ENTER();
  if (last_line == 0)
    last_line = buffer_next();
  return last_line;
}

/** Read and advance past the next line in the buffer. */
static const struct line* buffer_file_read(void)
{
  const struct line* line;
  ENTER();
  if ((line = last_line) == 0)
    line = buffer_next();
  if (line != 0)
    SET_SEQ(seq_read = line->seq + 1);
  last_line = 0;
  return line;
}

static void buffer_file_sync(void)
{
  if (writefd >= 0)
    fsync(writefd);
}

/** Rewind the buffer to the last mark point. */
static void buffer_file_rewind(void)
{
  ENTER();
  if (!ibuf_rewind(&readbuf))
    die1sys(111, "Could not rewind buffer"); /* Should be impossible */
  SET_SEQ(seq_read = seq_send);
  last_line = 0;
  buffer_file_sync();
}

/** "Remove" all read lines from the buffer and advance the mark point. */
static void buffer_file_pop(void)
{
  ENTER();
  SET_SEQ(seq_send = seq_read);
  save_seq();
  if (last_line == 0 && seq_send >= seq_next)
    buffer_empty();
}

/** Add a line to the end of the buffer. */
static void buffer_file_push(const struct line* line)
{
  char buf[FMT_ULONG_LEN*3 + line->line.len + 4];
  unsigned i;

  ENTER();
  save_seq();
  if (writefd < 0) {
    DEBUG1("Opening file");
    writefd = open(buffer_filename, O_WRONLY|O_CREAT|O_APPEND, 0644);
    if (writefd < 0)
      die1sys(1, "Could not open buffer file for writing");
    /* In case the previous run crashed or otherwise ended the file with
     * a truncated line, add a newline to ensure the next line to be
     * written starts at the start of a line. */
    writeall(writefd, "\n", 1);
  }
  i = fmt_ulldec(buf, line->seq);
  buf[i++] = ' ';
  i += fmt_ulldec(buf+i, line->timestamp.sec);
  buf[i++] = '.';
  i += fmt_ulldecw(buf+i, line->timestamp.nsec, 9, '0');
  buf[i++] = ' ';
  i += fmt_str(buf+i, &line->line, 0, 0);
  buf[i++] = LF;
  writeall(writefd, buf, i);
}

static const struct buffer_ops ops = {
  .peek   = buffer_file_peek,
  .read   = buffer_file_read,
  .pop    = buffer_file_pop,
  .push   = buffer_file_push,
  .rewind = buffer_file_rewind,
};

const struct buffer_ops* buffer_file_init(void)
{
  const char* env;
  if ((env = getenv("CLEAN_BYTES")) != 0)
    clean_bytes = strtoul(env, 0, 10);
  open_read_seq();
  SET_SEQ(seq_read = seq_send);
  /* Fix up seq_send in case it didn't match the first readable line in
   * the buffer. */
  if (buffer_file_peek() != 0)
    SET_SEQ(seq_send = last_line->seq);
  atexit(buffer_file_sync);
  return &ops;
}
