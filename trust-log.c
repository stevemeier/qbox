#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main() {
  if ( (getenv("RELAYCLIENT")) ||
       (getenv("TRUSTCLIENT")) ) {
    fprintf(stderr, "%d mail from: %s\n", getpid(), getenv("SMTPMAILFROM"));
    fprintf(stderr, "%d rcpt to: %s\n", getpid(), getenv("SMTPRCPTTO"));
  }

  printf("\n");
  exit(0);
}
