package main

import "database/sql"
import _ "github.com/go-sql-driver/mysql"
import "bufio"
import "bytes"
import "io"
import "io/ioutil"
import "fmt"
import "os"
import "os/exec"
import "regexp"
import "strconv"
import "strings"
import "time"
import "crypto/sha1"

import "github.com/davecgh/go-spew/spew"
import "golang.org/x/sys/unix"

const configdir = "/etc/qbox"

// Make DB available globally, not just in main
var db *sql.DB

type email struct {
	Length		int
	Recipient	string
	Sha1		string
	Text		string
}

func main() {
	// Default exit code is 111
	var exitcode int = 111

	// Set up a function to catch panic and exit with default code
	defer func() {
		if err := recover(); err != nil {
			os.Exit(exitcode)
		}
	}()

	// Destinations is an array where email should go
	var destinations []string

	var message email
	var err error
	message.Text, err = read_from_stdin()
	if err != nil {
		os.Exit(1)
	}

	message.Length = len(message.Text)
	message.Recipient = strings.TrimPrefix(os.Getenv("RECIPIENT"), "qbox-")
	message.Sha1 = sha1sum(message.Text)

	if (len(message.Recipient) == 0) {
		fmt.Println("RECIPIENT not set!")
		os.Exit(1)
	}

	addrparts := strings.Split(message.Recipient, "@")
        if len(addrparts) < 2 {
                os.Exit(111)
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
                        os.Exit(exitcode)
                }
        } else {
                os.Exit(exitcode)
        }
        defer db.Close()

	// Check for domain rewrite
	domain = rewrite_domain(domain)

	// Get destinations
	destinations = get_destinations(user, domain)

	// Check wildcard
	if len(destinations) == 0 {
		user = `*`
		destinations = get_destinations(user, domain)
	}

	// Check if we have at least one destination
	if len(destinations) == 0 {
		fmt.Println("Could not find mapping for "+message.Recipient)
		os.Exit(100)
	}

	spew.Dump(message)
	hostname, _ := os.Hostname()
	writesuccess := write_to_file(message, `/tmp/`+epoch()+`.`+strconv.Itoa(os.Getpid())+`.`+hostname+`.`+message.Sha1)
	if (writesuccess) {
		exitcode = 0
	}
	spew.Dump(writesuccess)
	os.Exit(exitcode)
}

func read_from_stdin () (string, error) {
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Err() != nil {
		return "", scanner.Err()
	}

	var message string
	for scanner.Scan() {
		message = message + scanner.Text() + "\n"
	}

	return message, nil
}

func sha1sum (message string) (string) {
	hash := sha1.New()
	io.WriteString(hash, message)
	return fmt.Sprintf("%x", hash.Sum(nil))
}

func epoch () (string) {
	now := time.Now()
	// Using UnixNano instead of just Unix gives us greater entropy in the filename
	return strconv.FormatInt(now.UnixNano(), 10)
}

func write_to_file (message email, filename string) (bool) {
	unix.Umask(077)

	// Never overwrite existing files
	if fileExists(filename) {
		return false
	}

	// Only accept absolute paths (starting with slash)
	re := regexp.MustCompile(`^/`)
	if !re.MatchString(filename) {
		return false
	}

	err := ioutil.WriteFile(filename, []byte(message.Text), 0600)
	return err == nil
}

func write_to_tempfile (message email) (string) {
	tmpfile, err := ioutil.TempFile("", "qbox")
	if err != nil {
		return ""
	}

	_, err = tmpfile.Write([]byte(message.Text))
	if err != nil {
		return ""
	}

	return tmpfile.Name()
}

func fileExists(filename string) bool {
        info, err := os.Stat(filename)
        if os.IsNotExist(err) {
                return false
        }

        return !info.IsDir()
}

func rewrite_domain (domain string) string {
        // Query DB for domain rewrite
        var rewrite string
        stmt1, err := db.Prepare("SELECT rewrite FROM domains WHERE domain = ? AND rewrite != ''")
        if err != nil {
		os.Exit(111)
        }
        rows1, err := stmt1.Query(domain)
        if err != nil {
                os.Exit(111)
        }
        defer stmt1.Close()

        for rows1.Next() {
                err := rows1.Scan(&rewrite)
                if err != nil {
                        os.Exit(111)
                }
        }

        if len(rewrite) > 0 {
                return rewrite
        }
	return domain
}

func get_destinations (user string, domain string) ([]string) {
	var destinations []string
	var homedir string

        stmt1, err := db.Prepare("SELECT DISTINCT passwd.homedir FROM passwd INNER JOIN mapping ON passwd.uid = mapping.uid WHERE user = ? AND domain = ?")
        if err != nil {
		os.Exit(111)
        }
        rows1, err := stmt1.Query(user, domain)
        if err != nil {
                os.Exit(111)
        }
        defer stmt1.Close()

        for rows1.Next() {
                err := rows1.Scan(&homedir)
                if err != nil {
                        os.Exit(111)
                }
		destinations = append(destinations, homedir)
        }

	return destinations
}

func antispam_enabled (user string, domain string) (bool) {
	var count int
	stmt1, err := db.Prepare("SELECT DISTINCT passwd.antispam FROM passwd INNER JOIN mapping ON passwd.uid = mapping.uid WHERE user = ? AND domain = ? AND antispam > 0")
        if err != nil {
		os.Exit(111)
        }
	err = stmt1.QueryRow(user, domain).Scan(&count)
        if err != nil {
                os.Exit(111)
        }

	return count > 0
}

func antivir_enabled (user string, domain string) (bool) {
	var count int
	stmt1, err := db.Prepare("SELECT DISTINCT passwd.antispam FROM passwd INNER JOIN mapping ON passwd.uid = mapping.uid WHERE user = ? AND domain = ? AND antivir > 0")
        if err != nil {
		os.Exit(111)
        }
	err = stmt1.QueryRow(user, domain).Scan(&count)
        if err != nil {
                os.Exit(111)
        }

	return count > 0
}

func sysexec (command string, args []string, input []byte) ([]byte, int, error) {
	var output bytes.Buffer

	cmd := exec.Command(command, args...)
	cmd.Stdin = bytes.NewBuffer(input)
	cmd.Stdout = &output
	err := cmd.Run()

	exitcode := 0
	if exitError, ok := err.(*exec.ExitError); ok {
		exitcode = exitError.ExitCode()
	}

	return output.Bytes(), exitcode, err
}

func rfc2822_date () (string) {
	layout := "Mon, 02 Jan 2006 15:04:05 UTC"
	time := time.Now().UTC()
	return time.Format(layout)
}
