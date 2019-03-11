package main

import "fmt"
import "net"
import "os"
import "regexp"
import "strings"

func main() {

  var smtprcptto string = os.Getenv("SMTPRCPTTO")
  addrparts := strings.Split(smtprcptto, "@")

  if len(addrparts) < 2 ||
     env_defined("RELAYCLIENT") ||
     env_defined("TRUSTCLIENT") {
       fmt.Println()
       os.Exit(0)
  }

  user, domain := addrparts[0], addrparts[1]
  _ = user

  if heluna_active(domain) {
    fmt.Fprintf(os.Stderr, "%d Direct delivery for %s attempted (should come via Heluna)\n", os.Getppid(), os.Getenv("SMTPRCPTTO"))
    fmt.Println("E451 Please obey MX configuration")
  }

  // Happy End
  fmt.Println()
  os.Exit(0)
}

func heluna_active (domain string) bool {
  mx, error := net.LookupMX(domain)
  _ = mx

  // catch lookup errors
  if error != nil {
    return false
  }

  // look at MX set to see if it points to heluna.com
  for i := 0; i < len(mx); i++ {
    match, _ := regexp.MatchString("\\.in\\.heluna\\.com\\.$", mx[i].Host)
    if match {
      return true
    }
  } 

  // by default, return false
  return false
}

func env_defined (key string) bool {
  value, exists := os.LookupEnv(key)
  _ = value

  return exists
}
