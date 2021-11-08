/* For malloc() */
#include <stdlib.h>
/* For puts()/printf() */
#include <stdio.h>

int main(void) {
  const char* smtpmailfrom = getenv("SMTPMAILFROM");

  if (smtpmailfrom == NULL) {
    smtpmailfrom = "";
  }
   printf("HReturn-Path: <%s>\n", smtpmailfrom);
   exit(0);
}
