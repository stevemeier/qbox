package main

import "database/sql"
import "fmt"
import _ "github.com/mattn/go-sqlite3"
import "github.com/c-robinson/iplib"
import "golang.org/x/net/publicsuffix"
import "golang.org/x/sys/unix"
import "log"
import "net"
import "os"
import "strings"
import "strconv"
import "time"

const configdir = "/var/qmail/control/greylist"
const message = "E451 Greylisting active. Your mail will be accepted on the next attempt."

// int64 because epoch is also int64
const mindelay int64 = 170
const maxvalid int64 = 604800

func main() {
	if env_defined("RELAYCLIENT") ||
		env_defined("TRUSTCLIENT") ||
		file_exists(configdir+"/disable") ||
		!file_exists(configdir+"/sqlite.db") ||
		(unix.Access(configdir, unix.W_OK) != nil) {
		fmt.Println()
		os.Exit(0)
	}

	var remoteip string
	var remotenet string
	var remotehost string
	var remotedomain string

	// Put client IP into `remoteip`
	// Depending on IPv4/IPv6/TLS, it can be in different places
	if env_defined("TCPREMOTEIP") {
		remoteip = os.Getenv("TCPREMOTEIP")
	}
	if env_defined("TCP6REMOTEIP") {
		remoteip = os.Getenv("TCP6REMOTEIP")
	}
	if env_defined("SSLREMOTEIP") {
		remoteip = os.Getenv("SSLREMOTEIP")
	}

	// Extract the subnet from `remoteip` and put it into `remotenet`
	ipobj := net.ParseIP(remoteip)
	if ipobj.To4() != nil {
		// remoteip is IPv4
		remotenet = fmt.Sprint(iplib.NewNet(ipobj, 24).NetworkAddress()) + "/24"
	} else {
		// remoteip is IPv6
		remotenet = fmt.Sprint(iplib.NewNet(ipobj, 56).NetworkAddress()) + "/56"
	}

	// Same for `remotehost`
	if env_defined("TCPREMOTEHOST") {
		remotehost = os.Getenv("TCPREMOTEHOST")
	}
	if env_defined("TCP6REMOTEHOST") {
		remotehost = os.Getenv("TCP6REMOTEHOST")
	}
	if env_defined("SSLREMOTEHOST") {
		remotehost = os.Getenv("SSLREMOTEHOST")
	}

	// If `remotehost` is populated, find the ETLD+1
	if len(remotehost) > 0 {
		remotedomain, _ = publicsuffix.EffectiveTLDPlusOne(remotehost)
	}

	// Extract the sender domain
	var senderdomain string
	if env_defined("SMTPMAILFROM") {
		addrparts := strings.Split(os.Getenv("SMTPMAILFROM"), "@")
		if len(addrparts) == 2 {
			senderdomain = addrparts[1]
		}
	}

	// Read the recipient
	var recipient string
	if env_defined("SMTPRCPTTO") {
		recipient = os.Getenv("SMTPRCPTTO")
	}

	// Check the current time
	var epoch = (time.Now()).Unix()

	// Open database
	db, err := sql.Open("sqlite3", configdir+"/sqlite.db")
	if err != nil {
		fmt.Println(message)
		log.Fatal(err)
		err = db.Ping()
		if err != nil {
			fmt.Println(message)
			log.Fatal(err)
		}
	}
	defer db.Close()

	// Clean up cruft
	if (epoch % 60) == 0 {
		fmt.Fprintf(os.Stderr, "%d Vacuuming greylist database\n", os.Getppid())
		_, err = db.Exec(`DELETE FROM main WHERE timestamp < ` + strconv.FormatInt((epoch-maxvalid), 10) + `; VACUUM`)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%d Failed to vacuum database: %s\n", os.Getppid(), err)
		}
	}

	stmt, err := db.Prepare("SELECT COUNT(*) FROM main WHERE" +
		"(timestamp >= ? AND timestamp <= ?)" +
		"AND mail = ? AND rcpt = ? AND" +
		"(ipaddr = ? OR rdns = ?)")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%d Failed to prepare query: %s\n", os.Getppid(), err)
	}
	var count int
	//	fmt.Printf("SELECT COUNT(*) FROM main WHERE (timestamp >= %d AND timestamp <= %d) AND mail = \"%s\" AND rcpt = \"%s\" AND (ipaddr = \"%s\" OR rdns = \"%s\");\n", epoch - maxvalid, epoch + mindelay, senderdomain, recipient, remotenet, remotedomain)
	err = stmt.QueryRow(epoch-maxvalid, epoch-mindelay, senderdomain, recipient, remotenet, remotedomain).Scan(&count)
	if err != nil {
		fmt.Println(message)
		log.Fatal(err)
	}

	// Found an entry in the greylist DB
	if count > 0 {
		fmt.Fprintf(os.Stderr, "%d IP %s passed greylist test\n", os.Getppid(), remoteip)
		fmt.Println()
		os.Exit(0)
	}

	// Add client to the database
	_, err = db.Exec(`INSERT INTO main VALUES ("` + remotenet + `","` + senderdomain + `","` + recipient + `","` + strconv.FormatInt(epoch, 10) + `","` + remotedomain + `")`)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%d Failed to insert into greylist DB: %s\n", os.Getppid(), err)
	} else {
		fmt.Fprintf(os.Stderr, "%d IP %s added to greylist (%s -> %s)\n", os.Getppid(), remoteip, senderdomain, recipient)
	}
	fmt.Println(message)

	os.Exit(0)
}

func env_defined(key string) bool {
	value, exists := os.LookupEnv(key)
	_ = value

	return exists
}

func file_exists(filename string) bool {
	_, err := os.Stat(filename)
	return !os.IsNotExist(err)
}
