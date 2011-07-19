#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

#include <iobuf/iobuf.h>
#include <msg/wrap.h>
#include <misc/misc.h>
#include <str/str.h>

#include "srlog2.h"

/* Buffering --------------------------------------------------------------- */
struct node
{
  struct line line;
  struct node* next;
};

static struct node* head = 0;
static struct node* curr = 0;
static struct node* tail = 0;
static const struct line* last_line = 0;

/** Look at the next line in the buffer without advancing. */
static const struct line* buffer_nofile_peek(void)
{
  if (last_line == 0 && curr != 0) {
    last_line = &curr->line;
    curr = curr->next;
  }
  return last_line;
}

/** Read and advance past the next line in the buffer. */
static const struct line* buffer_nofile_read(void)
{
  const struct line* line = buffer_nofile_peek();
  last_line = 0;
  return line;
}

/** Rewind the buffer to the last mark point. */
static void buffer_nofile_rewind(void)
{
  curr = head;
}

/** "Remove" all read lines from the buffer and advance the mark point. */
static void buffer_nofile_pop(void)
{
  struct node* next;
  while (head != curr) {
    next = head->next;
    SET_SEQ(seq_send = head->line.seq);
    str_free(&head->line.line);
    free(head);
    head = next;
  }
  if (head == 0)
    curr = 0;
  SET_SEQ(++seq_send);
}

/** Add a line to the end of the buffer. */
static void buffer_nofile_push(const struct line* line)
{
  struct node* node;
  while ((node = malloc(sizeof *node)) == 0)
    delay("allocate memory");
  memset(node, 0, sizeof *node);
  while (!str_copy(&node->line.line, &line->line))
    delay("allocate memory");
  node->line.timestamp = line->timestamp;
  node->line.seq = line->seq;
  node->next = 0;
  if (head == 0)
    head = node;
  else
    tail->next = node;
  tail = node;
  if (curr == 0)
    curr = node;
}

static const struct buffer_ops ops = {
  .peek   = buffer_nofile_peek,
  .read   = buffer_nofile_read,
  .pop    = buffer_nofile_pop,
  .push   = buffer_nofile_push,
  .rewind = buffer_nofile_rewind,
};

const struct buffer_ops* buffer_nofile_init(void)
{
  return &ops;
}
