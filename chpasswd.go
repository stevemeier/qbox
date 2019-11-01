package main

import "bufio"
import "database/sql"
import _ "github.com/go-sql-driver/mysql"
import "fmt"
import "io/ioutil"
import "os"
import "strings"

const configdir = "/etc/qbox"

// Implements `chpasswd` functionality to be used by
// Roundcube's password plugin

// Exit codes
// 0 = success
// 1 = Problem reading from STDIN
// 2 = Database problem

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
			fmt.Println(err)
			os.Exit(2)
		}
	} else {
		fmt.Println(err)
		os.Exit(2)
	}
	defer db.Close()

	// Read username:password sets from stdin
	var changes = make(map[string]string)
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Err() != nil {
		fmt.Println("Could not read STDIN: "+err.Error())
		os.Exit(1)
	}
	for scanner.Scan() {
	    split := strings.SplitN(scanner.Text(), ":", 2)
	    if len(split) == 2 {
		    changes[split[0]] = split[1]
	    } else {
		    fmt.Println("Failed to parse: "+scanner.Text())
		    os.Exit(1)
	    }
	}

	// Execute SQL updates
	for username, password := range changes {
	        stmt, err := db.Prepare("UPDATE passwd SET password = ? WHERE username = ? LIMIT 1")
		if err != nil {
			fmt.Println(err)
			os.Exit(2)
		}
		defer stmt.Close()

	        _, err = stmt.Exec(password, username)
		if err != nil {
			fmt.Println(err)
			os.Exit(2)
		}
	}

	// END
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}

	return !info.IsDir()
}
