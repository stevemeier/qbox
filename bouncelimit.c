#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main() {
  // read SMTPMAILFROM and SMTPRCPTCOUNT from environment
  const char* smtpmailfrom = getenv("SMTPMAILFROM");
  const char* smtprcptcount = getenv("SMTPRCPTCOUNT");

  if (smtpmailfrom == NULL) {
    printf("\n");
    exit(0);
  }

  if (smtprcptcount == NULL) {
    printf("\n");
    exit(0);
  }

  int rcptcount = toString(smtprcptcount);

  if ( (strcmp(smtpmailfrom, "") == 0) &&
       (rcptcount >= 1) ) {
    fprintf(stderr, "%d Empty envelope sender with multiple recipients from %s\n", getpid(), getenv("TCPREMOTEIP"));
    printf("E550 Bounces should only have one recipient\n");
  } else {
    printf("\n");
  }

  exit(0);
}

int toString(char a[]) {
  int c, sign, offset, n;
 
  if (a[0] == '-') {  // Handle negative integers
    sign = -1;
  }
 
  if (sign == -1) {  // Set starting position to convert
    offset = 1;
  }
  else {
    offset = 0;
  }
 
  n = 0;
 
  for (c = offset; a[c] != '\0'; c++) {
    n = n * 10 + a[c] - '0';
  }
 
  if (sign == -1) {
    n = -n;
  }
 
  return n;
}
