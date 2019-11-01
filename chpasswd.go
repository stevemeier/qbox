package main

import "bufio"
import "database/sql"
import _ "github.com/go-sql-driver/mysql"
import "fmt"
import "io/ioutil"
import "log"
import "os"
import "strings"

const configdir = "/etc/qbox"

// Implements `chpasswd` functionality to be used by
// Roundcube's password plugin

func main() {
	// Read config files
	var dbserver string = "127.0.0.1"
	if fileExists(configdir + "/dbserver") {
		buf, err := ioutil.ReadFile(configdir + "/dbserver")
		if err == nil {
			dbserver = string(buf)
		}
	}

	var dbuser string = "qbox"
	if fileExists(configdir + "/dbuser") {
		buf, err := ioutil.ReadFile(configdir + "/dbuser")
		if err == nil {
			dbuser = string(buf)
		}
	}

	var dbpass string
	if fileExists(configdir + "/dbpass") {
		buf, err := ioutil.ReadFile(configdir + "/dbpass")
		if err == nil {
			dbpass = string(buf)
		}
	}

	// Initialize DB
	db, err := sql.Open("mysql", dbuser+":"+dbpass+"@tcp("+dbserver+")/qbox")
	if err == nil {
		err = db.Ping()
		if err != nil {
			internal_error()
			log.Fatal(err)
		}
	} else {
		internal_error()
		log.Fatal(err)
	}
	defer db.Close()

	// Read username:password sets from stdin
	var changes map[string]string
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Err() != nil {
		fmt.Println("Could not read STDIN: "+err.Error())
		os.Exit(1)
	}
	for scanner.Scan() {
	    split := strings.SplitN(scanner.Text(), ":", 2)
	    if len(split) == 2 {
		    changes[split[0]] = split[1]
	    }
	}

	// Execute SQL updates
	for username, password := range changes {
		fmt.Println("Updating "+username+" with password "+password)
	}

	// Exit
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}

	return !info.IsDir()
}

func env_defined(key string) bool {
	value, exists := os.LookupEnv(key)
	_ = value

	return exists
}

func internal_error() {
	fmt.Println("E451 Recipient verification falied")
}
