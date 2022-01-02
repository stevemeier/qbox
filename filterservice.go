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

	if mx_match_regexp(domain, `\.in\.heluna\.com\.$`) {
		fmt.Fprintf(os.Stderr, "%d Direct delivery for %s attempted (should come via Heluna)\n", os.Getppid(), os.Getenv("SMTPRCPTTO"))
		fmt.Println("E451 Please obey MX configuration")
		os.Exit(0)
	}
	if mx_match_regexp(domain, `\.spambarrier\.de\.$`) {
		fmt.Fprintf(os.Stderr, "%d Direct delivery for %s attempted (should come via SpamBarrier)\n", os.Getppid(), os.Getenv("SMTPRCPTTO"))
		fmt.Println("E451 Please obey MX configuration")
		os.Exit(0)
	}

	// Happy End
	fmt.Println()
	os.Exit(0)
}

func mx_match_regexp (domain string, mxfilter string) bool {
	mx, error := net.LookupMX(domain)
	_ = mx

	// catch lookup errors
	if error != nil {
		return false
	}

	// look at MX set to see if it points to heluna.com
//	re := regexp.MustCompile(`\.in\.heluna\.com\.$`)
	re := regexp.MustCompile(mxfilter)
	for i := 0; i < len(mx); i++ {
		if re.MatchString(strings.ToLower(mx[i].Host)) {
			return true
		}
	}

	// by default, return false
	return false
}

func env_defined(key string) bool {
	value, exists := os.LookupEnv(key)
	_ = value

	return exists
}
