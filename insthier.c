/* $Id$ */
#include "conf_bin.c"
#include <installer.h>

void insthier(void)
{
  int bin = opendir(conf_bin);

  c(bin, "srlog",              -1, -1, 0711);
  c(bin, "srlog-prep",         -1, -1, 0711);
  c(bin, "srlogd",             -1, -1, 0711);
  c(bin, "srlogq",             -1, -1, 0711);
}
