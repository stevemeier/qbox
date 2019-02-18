#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main() {
  // read SMTPHELOHOST from environment
  const char* hostname = getenv("SMTPHELOHOST");

  // skip this test for RELAYCLIENT
  // skip this test for TRUSTCLIENT
  // skip this test if there is no badhelo file
  if ( (getenv("RELAYCLIENT")) || (getenv("TRUSTCLIENT")) || (access("/var/qmail/control/badhelo", R_OK) == -1 ) ) {
    printf("\n");
    exit(0);
  }

  // check for empty hostname
  if (hostname == NULL) {
    printf("E550 No hostname provided in HELO/EHLO\n");
    exit(0);
  }

  // search through badhelo file
  if (search_in_file("/var/qmail/control/badhelo",hostname)) {
    fprintf(stderr, "%d Found %s in badhelo list !\n", getpid(), hostname);
    sleep(5);
    printf("E550 Bad hostname [%s]\n", hostname);
    exit(0);
  }

  // default last action
  printf("\n");
  exit(0);
}

int search_in_file(char *fname, char *str) {
  FILE *fp;
  int found = 0;
  char temp[512];

  // check if file is readbale
  if ((fp = fopen(fname, "r")) == NULL) {
    return(-1);
  }

  while (fgets(temp, 512, fp) != NULL) {
    if ((strstr(temp, str)) != NULL) {
      found++;
    }
  }

  // close file if still open
  if (fp) { fclose(fp); }

  return(found);
}
