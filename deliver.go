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
const quarantine = "/var/qmail/quarantine"
const debug_enabled = false

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
			fmt.Println(err)
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
		fmt.Println("ERROR: Could not split recipient address")
                os.Exit(111)
        }
        user, domain := addrparts[0], addrparts[1]

        // Read config files
        var dbserver string = "127.0.0.1"
        if file_exists(configdir + "/dbserver") {
                buf, err := ioutil.ReadFile(configdir + "/dbserver")
                if err == nil {
                        dbserver = string(buf)
                }
        }

        var dbuser string = "qbox"
        if file_exists(configdir + "/dbuser") {
                buf, err := ioutil.ReadFile(configdir + "/dbuser")
                if err == nil {
                        dbuser = string(buf)
                }
        }

        var dbpass string
        if file_exists(configdir + "/dbpass") {
                buf, err := ioutil.ReadFile(configdir + "/dbpass")
                if err == nil {
                        dbpass = string(buf)
                }
        }

        // Initialize DB
        db, err = sql.Open("mysql", dbuser+":"+dbpass+"@tcp("+dbserver+")/qbox")
        if err == nil {
                err = db.Ping()
                if err != nil {
			fmt.Println("ERROR: db.Ping failed!")
                        os.Exit(exitcode)
                }
        } else {
		fmt.Println("ERROR: Could not connect to MySQL "+err.Error())
                os.Exit(exitcode)
        }
        defer db.Close()

	// Check for domain rewrite
	debug("Calling rewrite_domain with parameter: "+domain+"\n")
	domain = rewrite_domain(domain)

	// Get destinations
	debug("Calling get_destinations with parameters: "+user+", "+domain+"\n")
	destinations = get_destinations(user, domain)
	if debug_enabled {
		spew.Dump(destinations)
	}

	// Check wildcard
	if len(destinations) == 0 {
		debug("Checking for wildcards\n")
		user = `*`
		destinations = get_destinations(user, domain)
	}

	// Check if we have at least one destination
	if len(destinations) == 0 {
		fmt.Println("Could not find mapping for "+message.Recipient)
		os.Exit(100)
	}

	if antispam_enabled(user, domain) {
		tempfile := write_to_tempfile(message)
		defer os.Remove(tempfile)
		debug("Starting spamc\n")
		antispamresult, antispamsuccess, _ := sysexec("/usr/bin/spamc", nil, []byte(message.Text))
		if antispamsuccess == 0 {
			message.Text = string(antispamresult)
		}
	}

	if antivir_enabled(user, domain) {
		tempfile := write_to_tempfile(message)
		defer os.Remove(tempfile)
		debug("Starting clamscan\n")
		_, antivirsuccess, _ := sysexec("/usr/bin/clamscan", []string{tempfile}, nil)
		if antivirsuccess == 1 {
			// Infected mails go to the quarantine
			destinations = []string{quarantine}
		}
	}

	for _, destination := range destinations {
		debug("Starting delivery to "+destination+"\n")
		switch destination_type(destination) {
		case "maildir":
			writesuccess := write_to_maildir(message, destination+"/INBOX")
			if writesuccess {
				fmt.Println("Message delivered to "+destination+" for "+message.Recipient)
			} else {
				fmt.Println("ERROR: Could not delivered to "+destination+" for "+message.Recipient)
				exitcode = 1
			}

		case "forward":
			_, fwdsuccess, _ := sysexec("/var/qmail/bin/qmail-inject", []string{"-fpostmaster@mail.lordy.de", destination}, []byte(message.Text))
			if fwdsuccess == 0 {
				fmt.Println("Message forwarded to "+destination+" for "+message.Recipient)
			} else {
				fmt.Println("ERROR: Could not forward to "+destination+" for "+message.Recipient)
				exitcode = fwdsuccess
			}

		case "pipe":
			_, execsuccess, _ := sysexec(destination, nil, []byte(message.Text))
			if execsuccess == 0 {
				fmt.Println("Message piped to "+destination+" for "+message.Recipient)
			} else {
				fmt.Println("ERROR: Could not pipe to "+destination+" for "+message.Recipient)
				exitcode = execsuccess
			}
		}
	}

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

func sha1sum_body (message string) (string) {
	// Ignore Headers so that duplicate detection can actually work
        re, _ := regexp.Compile(`\n\n`)
        fsi := re.FindStringIndex(message)
        body := message[fsi[1]:]

        hash := sha1.New()
        io.WriteString(hash, body)
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
	if file_exists(filename) {
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

func file_exists(filename string) bool {
        info, err := os.Stat(filename)
        if os.IsNotExist(err) {
                return false
        }

        return !info.IsDir()
}

func rewrite_domain (domain string) string {
        // Query DB for domain rewrite
        var rewrite sql.NullString
        stmt1, err := db.Prepare("SELECT rewrite FROM domains WHERE domain = ? AND rewrite != ''")
        if err != nil {
		fmt.Println("DEBUG: Failed to prepare statement in rewrite_domain")
		os.Exit(111)
        }

        rows1, err := stmt1.Query(domain)
        if err != nil {
		fmt.Println("DEBUG: Failed to execute query in rewrite_domain")
                os.Exit(111)
        }
        defer stmt1.Close()

        for rows1.Next() {
                err := rows1.Scan(&rewrite)
                if err != nil {
			fmt.Println("DEBUG: Failed to scan row in rewrite_domain "+err.Error())
                        os.Exit(111)
                }
        }

	// See https://stackoverflow.com/questions/40092155/difference-between-string-and-sql-nullstring
	if rewrite.Valid {
		return rewrite.String
	}
	return domain
}

func get_destinations (user string, domain string) ([]string) {
	var destinations []string
	var homedir string

	debug("Preparing statement in get_destinations\n")
        stmt1, err := db.Prepare("SELECT DISTINCT passwd.homedir FROM passwd INNER JOIN mapping ON passwd.uid = mapping.uid WHERE user = ? AND domain = ?")
        if err != nil {
		os.Exit(111)
        }
	debug("Running query in get_destinations\n")
        rows1, err := stmt1.Query(user, domain)
        if err != nil {
                os.Exit(111)
        }
        defer stmt1.Close()

        for rows1.Next() {
		debug("Scanning row in get_destinations\n")
                err := rows1.Scan(&homedir)
                if err != nil {
                        os.Exit(111)
                }
		destinations = append(destinations, homedir)
        }

	debug("Reached end of get_destinations\n")
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

func directory_filelist (directory string) ([]string, error) {
        var result []string

        files, err := ioutil.ReadDir(directory)
        if err != nil {
                return result, err
        }

        for _, file := range files {
                filestat, err := os.Stat(file.Name())
                if err == nil {
                        if filestat.Mode().IsRegular() {
                                result = append(result, file.Name())
                        }
                }
        }

        return result, nil
}

func is_duplicate (directory string, hash string) (bool) {
	filelist, err := directory_filelist(directory)
	if err != nil {
		return false
	}

	re, _ := regexp.Compile(`.`+hash)

	for _, file := range filelist {
		if re.MatchString(file) {
			return true
		}
	}

	return false
}

func destination_type (destination string) (string) {
	var matched bool

	matched, _ = regexp.MatchString(`^/`, destination)
	if matched {
		return "maildir"
	}

	matched, _ = regexp.MatchString(`@`, destination)
	if matched {
		return "forward"
	}

	matched, _ = regexp.MatchString(`^|`, destination)
	if matched {
		return "pipe"
	}

	return ""
}

func write_to_maildir (message email, directory string) (bool) {
	// Example filename:
	// 1576429450084839306.27056.bart.lordy.de.7a3e892ba01ce9899d101745da2757a81ac55779
	filename := epoch()+`.`+strconv.Itoa(os.Getpid())+`.`+sys_hostname()+`.`+message.Sha1
	writesuccess := write_to_file(message, directory+"/tmp/"+filename)

	if writesuccess {
		linkerr := os.Link(directory+"/tmp/"+filename, directory+"/new/"+filename)
		if linkerr == nil {
			rmerr := os.Remove(directory+"/tmp/"+filename)
			if rmerr == nil {
				return true
			}
		}
	}

	return false
}

func sys_hostname () (string) {
	hostname, _ := os.Hostname()

	if len(hostname) > 0 {
		return hostname
	}

	return "localhost"
}

func debug (message string) (bool) {
	if debug_enabled {
		fmt.Fprintf(os.Stderr, "DEBUG: "+message)
		return true
	}
	return false
}
