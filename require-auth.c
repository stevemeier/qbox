/* For malloc() */
#include <stdlib.h>
/* For puts()/printf() */
#include <stdio.h>

int main(void) {
  const char* smtpauthuser = getenv("SMTPAUTHUSER");

  if (smtpauthuser == NULL) {
    printf("E550 Authentication required\n");
  }

  exit(0);
}
