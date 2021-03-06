package main

import "fmt"
import "net"
import "os"
import "regexp"
import "strings"
import "time"

func main() {

	var smtpmailfrom string = os.Getenv("SMTPMAILFROM")
	addrparts := strings.Split(smtpmailfrom, "@")

	// Allow relay clients, trusted clients and bounces (empty envelope sender)
	if env_defined("RELAYCLIENT") ||
		env_defined("TRUSTCLIENT") ||
		len(smtpmailfrom) == 0 {
		fmt.Println()
		os.Exit(0)
	}

	// No @ in envelope sender
	if len(addrparts) < 2 {
		fmt.Fprintf(os.Stderr, "%d Sender %s has no domain part\n", os.Getppid(), smtpmailfrom)
		fmt.Println("E501 Sender address is invalid")
		os.Exit(0)
	}

	user, domain := addrparts[0], addrparts[1]
	_ = user

	// Check for . in domain, TLDs don't send mail
	match, _ := regexp.MatchString("\\.", domain)
	if !match {
		fmt.Fprintf(os.Stderr, "%d Sender %s claims to be at TLD\n", os.Getppid(), smtpmailfrom)
		fmt.Println("E501 Sender address is invalid")
		os.Exit(0)
	}

	if mx_or_a(domain) {
		fmt.Fprintf(os.Stderr, "%d Sender %s passed domain check\n", os.Getppid(), smtpmailfrom)
		fmt.Println()
	} else {
		fmt.Fprintf(os.Stderr, "%d No MX/A record for %s (claimed sender: %s)\n", os.Getppid(), domain, smtpmailfrom)
		fmt.Fprintf(os.Stderr, "%d Mail recipient would have been %s\n", os.Getppid(), os.Getenv("SMTPRCPTTO"))
		time.Sleep(5 * time.Second)
		fmt.Println("E451 Sender domain does not exist")
	}

	os.Exit(0)
}

func env_defined(key string) bool {
	value, exists := os.LookupEnv(key)
	_ = value

	return exists
}

func mx_or_a(domain string) bool {
	mx, error := net.LookupMX(domain)
	_ = mx
	if error == nil {
		return true
	}

	addrs, error := net.LookupHost(domain)
	_ = addrs
	return error == nil
}
