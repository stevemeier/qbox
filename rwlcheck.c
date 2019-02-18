#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <arpa/inet.h>
#include <netdb.h>

int main(void) {
  // read TCPREMOTEHOST from environment
  const char* hostname = getenv("TCPREMOTEHOST");

  // skip this test for RELAYCLIENT
  // skip this test for TRUSTCLIENT
  if ( (getenv("RELAYCLIENT")) || 
       (getenv("TRUSTCLIENT")) ) {
    printf("\n");
    exit(0);
  }

  // check for empty hostname
  if (hostname == NULL) {
    printf("\n");
    exit(0);
  }

  // search through badhelo file
  DIR *dir;
  struct dirent *ent;
  if ((dir = opendir("/var/qmail/control/rwldomains")) != NULL) {
    while ((ent = readdir(dir)) != NULL) {
      if ( (strcmp(ent->d_name, ".") != 0) && 
           (strcmp(ent->d_name, "..") != 0) ) {

        if (check_whitelist_name(hostname, ent->d_name) > 0) {
//        printf("Name %s is listed in %s\n", hostname, ent->d_name);
          fprintf(stderr, "%d Name %s is listed in %s\n", getppid(), hostname, ent->d_name);
          printf("STRUSTCLIENT=1\n\n");
          exit(0);
        }

        if (getenv("TCPREMOTEIP")) {
          // check if IP is listed (IPv6 would be in TCP6REMOTEIP)
          if (check_whitelist_ip(getenv("TCPREMOTEIP"), ent->d_name) > 0) {
//          printf("IP %s is listed in %s\n", getenv("TCPREMOTEIP"), ent->d_name);
            fprintf(stderr, "%d IP %s is listed in %s\n", getppid(), getenv("TCPREMOTEIP"), ent->d_name);
            printf("STRUSTCLIENT=1\n\n");
            exit(0);
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

int check_whitelist_name (char *hostname, char *rbl) {
  struct addrinfo hints;
  struct hostent *rv;

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC; // use AF_INET6 to force IPv6
  hints.ai_socktype = SOCK_DGRAM;

  char dnsname[256] = "";
  strcat(dnsname, hostname);
  strcat(dnsname, ".");
  strcat(dnsname, rbl);

  if ( (rv = gethostbyname(dnsname)) == NULL) {
    return 0; 
  } else {
    return 1;
  }
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

