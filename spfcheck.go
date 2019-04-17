package main

import "fmt"
import "net"
import "blitiri.com.ar/go/spf"
import "os"
import "strings"
import "time"

func main() {
	if env_defined("RELAYCLIENT") ||
		env_defined("TRUSTCLIENT") {
		fmt.Println()
		os.Exit(0)
	}

	if !env_defined("TCPREMOTEIP") {
		fmt.Println()
		os.Exit(0)
	}

	var smtpmailfrom string = os.Getenv("SMTPMAILFROM")
	var addrparts []string = strings.Split(smtpmailfrom, "@")

	ip := net.ParseIP(os.Getenv("TCPREMOTEIP"))
	r, _ := spf.CheckHost(ip, addrparts[1])

	if (r == "fail") {
		fmt.Fprintf(os.Stderr, "%d SPF check failed for %s!\n", os.Getppid(), smtpmailfrom)
		fmt.Fprintf(os.Stderr, "%d Mail recipient would have been %s\n", os.Getppid(), os.Getenv("SMTPRCPTTO"))
		time.Sleep(5)
		fmt.Println("E451 SPF check failed")
	} else {
		fmt.Println()
	}

	os.Exit(0)
}

func env_defined(key string) bool {
	value, exists := os.LookupEnv(key)
	_ = value

	return exists
}
