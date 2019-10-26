package main

import "bufio"
import "fmt"
import "os"
import "regexp"
import "strings"

func main() {

	if env_defined("RELAYCLIENT") ||
	   env_defined("TRUSTCLIENT") {
		fmt.Println()
		os.Exit(0)
	}

	file, err := os.Open("/var/qmail/control/badrcptto")
	if err != nil {
		fmt.Println()
		os.Exit(0)
	}
	defer file.Close()

	var recipient string = strings.ToLower(os.Getenv("SMTPRCPTTO"))

	if len(recipient) == 0 {
		fmt.Println()
		os.Exit(0)
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		match, _ := regexp.MatchString(recipient, scanner.Text())
		if match {
			fmt.Fprintf(os.Stderr, "%d Found %s in badrcptto list\n", os.Getppid(), recipient)
			fmt.Fprintf(os.Stdout, "E550 This address no longer accepts mail [%s]\n", recipient)
			os.Exit(0)
		}
	}

	fmt.Println()
	os.Exit(0)
}

func env_defined(key string) bool {
	value, exists := os.LookupEnv(key)
	_ = value

	return exists
}
