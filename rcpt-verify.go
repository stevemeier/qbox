package main

import "database/sql"
import _ "github.com/go-sql-driver/mysql"
import "fmt"
import "io/ioutil"
import "log"
import "os"
import "strings"

//import "github.com/davecgh/go-spew/spew"

const configdir = "/etc/qbox"

func main() {
	// No SMTPRCPTTO, we can't do anything
	if !env_defined("SMTPRCPTTO") {
		fmt.Println()
		os.Exit(0)
	}

	// Split recipient in user and domain part
	var smtprcptto string = os.Getenv("SMTPRCPTTO")
	addrparts := strings.Split(smtprcptto, "@")
	if len(addrparts) < 2 {
		fmt.Println("E451 Invalid address")
		os.Exit(0)
	}
	user, domain := addrparts[0], addrparts[1]

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

	// Query DB for domain rewrite
	var rewrite string
	stmt1, err := db.Prepare("SELECT rewrite FROM domains WHERE domain = ? AND rewrite != ''")
	rows1, err := stmt1.Query(domain)
	if err != nil {
		internal_error()
		log.Fatal(err)
	}
	defer stmt1.Close()

	for rows1.Next() {
		err := rows1.Scan(&rewrite)
		if err != nil {
			internal_error()
			log.Fatal(err)
		}
	}

	if len(rewrite) > 0 {
		fmt.Fprintf(os.Stderr, "%d Domain %s is rewritten to %s for %s\n", os.Getppid(), domain, rewrite, smtprcptto)
		domain = rewrite
	}

	// Query DB for user
	stmt2, err := db.Prepare("SELECT DISTINCT COUNT(passwd.homedir) FROM passwd INNER JOIN mapping ON passwd.uid = mapping.uid WHERE domain = ? AND (user = ? OR user = '*')")
	if err != nil {
		internal_error()
		log.Fatal(err)
	}
	defer stmt2.Close()

	var ucount int
	rows2, err := stmt2.Query(domain, user)
	if err != nil {
		internal_error()
		log.Fatal(err)
	}
	for rows2.Next() {
		err := rows2.Scan(&ucount)
		if err != nil {
			internal_error()
			log.Fatal(err)
		}
	}

	if ucount > 0 {
		// Recipient found
		fmt.Fprintf(os.Stderr, "%d Found mapping for %s\n", os.Getppid(), smtprcptto)
		fmt.Println()
		os.Exit(0)
	}

	// The user was not found, check if the domain is even in the system
	stmt3, err := db.Prepare("SELECT COUNT(domain) FROM domains WHERE domain = ?")
	if err != nil {
		internal_error()
		log.Fatal(err)
	}

	var dcount int
	err = stmt3.QueryRow(domain).Scan(&dcount)
	if dcount > 0 {
		fmt.Fprintf(os.Stderr, "%d User %s not found in database\n", os.Getppid(), smtprcptto)
		fmt.Fprintf(os.Stdout, "E550 User unknown [%s]\n", smtprcptto)
	} else {
		fmt.Fprintf(os.Stderr, "%d Domain %s not found in table DOMAINS\n", os.Getppid(), domain)
		fmt.Fprintf(os.Stdout, "E521 Domain unknown [%s]\n", domain)
	}
	os.Exit(0)
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
	return
}
