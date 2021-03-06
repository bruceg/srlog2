#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <bglibs/iobuf.h>
#include <bglibs/msg.h>
#include <bglibs/str.h>

#include "srlog2.h"

/* Sequence Number Handling ------------------------------------------------ */
uint64 seq_next = 0; /* Next line is assigned this number */
uint64 seq_send = 0; /* Next line to send has this number */
static int seq_fd;

void save_seq(void)
{
  static str seq_line;
  str_truncate(&seq_line, 0);
  str_catull(&seq_line, seq_send);
  str_catc(&seq_line, ':');
  str_catull(&seq_line, seq_next);
  str_catc(&seq_line, LF);
  if (lseek(seq_fd, 0, SEEK_SET) != 0)
    die1sys(1, "Could not seek sequence file"); /* Should be impossible */
  writeall(seq_fd, seq_line.s, seq_line.len);
}

void open_read_seq(void)
{
  char* end;
  char buf[64];
  long rd;
  seq_next = 0;
  if ((seq_fd = open("sequence", O_RDONLY)) != -1) {
    if ((rd = read(seq_fd, buf, sizeof buf)) == -1)
      die1sys(1, "Could not read sequence file");
    /* Don't die on parse errors */
    if (rd > 0) {
      SET_SEQ(seq_send = strtoull(buf, &end, 10));
      if (*end == ':') {
	SET_SEQ(seq_next = strtoull(end+1, &end, 10));
	if (*end != LF)
	  SET_SEQ(seq_next = 0);
      }
    }
    close(seq_fd);
  }
  if (seq_send > seq_next)
    SET_SEQ(seq_next = seq_send);
  if ((seq_fd = open("sequence", O_WRONLY|O_CREAT, 0666)) == -1)
    die1sys(1, "Could not create new sequence file");
  save_seq();
}
