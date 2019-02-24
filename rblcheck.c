#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <arpa/inet.h>
#include <netdb.h>

int main(void) {
  int listed = 0;
  int maxscore = 2;
  int rblscore = 0;
  int hostscore = 0;

  // skip this test for RELAYCLIENT
  // skip this test for TRUSTCLIENT
  if ( (getenv("RELAYCLIENT")) || 
       (getenv("TRUSTCLIENT")) ) {
    printf("\n");
    exit(0);
  }

  // search through badhelo file
  DIR *dir;
  struct dirent *ent;
  if ((dir = opendir("/var/qmail/control/rbldomains")) != NULL) {
    while ((ent = readdir(dir)) != NULL) {
      if ( (strcmp(ent->d_name, ".") != 0) && 
           (strcmp(ent->d_name, "..") != 0) ) {

        if (getenv("TCPREMOTEIP")) {
          // check if IP is listed (IPv6 would be in TCP6REMOTEIP)
          listed = check_whitelist_ip(getenv("TCPREMOTEIP"), ent->d_name);
          if (listed > 0) {
//          printf("IP %s is listed in %s\n", getenv("TCPREMOTEIP"), ent->d_name);
            rblscore = get_rbl_score(ent->d_name);
            fprintf(stderr, "%d IP %s is listed in %s (score: %d)\n", getppid(), getenv("TCPREMOTEIP"), ent->d_name, rblscore);
            hostscore = hostscore + rblscore;
//          fprintf(stderr, "%d Score for %s is %d\n", getpid(), ent->d_name, rblscore);
//          fprintf(stderr, "Host score is now %d\n", hostscore);
            if (hostscore >= maxscore) {
              fprintf(stderr, "%d Rejecting %s with score of %d (limit %d)\n", getppid(), getenv("TCPREMOTEIP"), hostscore, maxscore);
              sleep(5);
              printf("E451 Sorry, your IP address is blacklisted\n");
              exit(0);
            }
          }
        }
      }
    }
  }
  closedir(dir);

  // default last action
  printf("\n");
  exit(0);
}

int check_whitelist_ip (char *ip, char *rbl) {
  struct addrinfo hints;
  struct hostent *rv;

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC; // use AF_INET6 to force IPv6
  hints.ai_socktype = SOCK_DGRAM;

  static char reversed_ip[INET_ADDRSTRLEN];
  in_addr_t addr;

  // Turn text into binary representation
  inet_pton(AF_INET, ip, &addr);

  // Flip the bits around (MAGIC!)
  addr =
    ((addr & 0xff000000) >> 24) |
    ((addr & 0x00ff0000) >>  8) |
    ((addr & 0x0000ff00) <<  8) |
    ((addr & 0x000000ff) << 24);

  inet_ntop(AF_INET, &addr, reversed_ip, sizeof(reversed_ip));

  char dnsname[256] = "";
  strcat(dnsname, reversed_ip);
  strcat(dnsname, ".");
  strcat(dnsname, rbl);

  if ( (rv = gethostbyname(dnsname)) == NULL) {
    return 0; 
  } else {
    return 1;
  }
}

int get_rbl_score (const char* rblname) {
  if (chdir("/var/qmail/control/rbldomains")) {
    FILE* file = fopen(rblname, "r");
    int i = 0;
    int count = 0;

    count = fscanf(file, "%d", &i);
    fclose(file);
    if (count == 1) {
      return i;
    }
  } 
  
  return 0;
}
