package main

import "database/sql"
import _ "github.com/go-sql-driver/mysql"
import "bufio"
import "bytes"
import "fmt"
import "io"
import "io/ioutil"
import "net/mail"
import "os"
import "os/exec"
import "path/filepath"
import "regexp"
import "strconv"
import "strings"
import "time"
import "crypto/sha1"

import "github.com/davecgh/go-spew/spew"
import "golang.org/x/sys/unix"

const configdir = "/etc/qbox"
const quarantine = "/var/qmail/quarantine"
var debug_enabled bool = false

// Make DB available globally, not just in main
var db *sql.DB

type email struct {
	Length		int
	Recipient	string
	Sha1		string
	Text		string
	Object		*mail.Message
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

	if env_defined("QBOX_DEBUG") {
		debug_enabled = true
	}

	// Destinations is an array where email should go
	var destinations []string

	// Record the delivery results
	var deliveryresults []int

	var message email
	var err error
	message.Text, err = read_from_stdin()
	if err != nil {
		os.Exit(1)
	}

	message.Length = len(message.Text)
	message.Recipient = strings.TrimPrefix(os.Getenv("RECIPIENT"), "qbox-")
	message.Sha1 = sha1sum(message.Text)
	message.Object, _ = mail.ReadMessage(strings.NewReader(message.Text))

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

	var sender string
	if env_defined("SENDER") {
		sender = os.Getenv("SENDER")
	}

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

	if antispam_enabled(user, domain) && spamd_available() {
		tempfile := write_to_tempfile(message)
		defer os.Remove(tempfile)
		debug("Starting spamc\n")
//		antispamresult, antispamsuccess, _ := sysexec("/usr/bin/spamc", nil, []byte(message.Text))
		antispamresult, antispamsuccess, _ := sysexec("/usr/bin/spamc", []string{"-E"}, []byte(message.Text))
		// Spamc will exit 0 on ham, 1 on spam
		if antispamsuccess < 2 {
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
//			duplicate := is_duplicate(destination+"/INBOX", message.Sha1)
//			if duplicate {
			if dupfilter_enabled(user, domain) && is_duplicate(destination+"/INBOX", message.Sha1) {
				fmt.Println("Message to "+destination+" for "+message.Recipient+" was a duplicate ("+message.Sha1+")")
				deliveryresults = append(deliveryresults, 0)
			} else {
				writesuccess := write_to_maildir(message, destination+"/INBOX")
				if writesuccess  {
					fmt.Println("Message delivered to "+destination+" for "+message.Recipient)
					deliveryresults = append(deliveryresults, 0)
				} else {
					fmt.Println("ERROR: Could not deliver to "+destination+" for "+message.Recipient)
					deliveryresults = append(deliveryresults, 1)
				}
			}

		case "forward":
			_, fwdsuccess, _ := sysexec("/var/qmail/bin/qmail-inject", []string{"-fpostmaster@mail.lordy.de", destination}, []byte(message.Text))
			if fwdsuccess == 0 {
				fmt.Println("Message forwarded to "+destination+" for "+message.Recipient)
			} else {
				fmt.Println("ERROR: Could not forward to "+destination+" for "+message.Recipient)
			}
			deliveryresults = append(deliveryresults, fwdsuccess)

		case "pipe":
			destination = strings.TrimPrefix(destination,`|`)
			_, execsuccess, _ := sysexec(destination, nil, []byte(message.Text))
			if execsuccess == 0 {
				fmt.Println("Message piped to "+destination+" for "+message.Recipient)
			} else {
				fmt.Println("ERROR: Could not pipe to "+destination+" for "+message.Recipient)
			}
			deliveryresults = append(deliveryresults, execsuccess)

		default:
			fmt.Println("Can not handle "+destination+" for "+message.Recipient)
			deliveryresults = append(deliveryresults, 111)
//			exitcode = 111
		}
	}

	// Autoresponder code goes here
	// Mailing lists are ignored (if List-ID header is present)
	// If there is no X-Mailer Header, it's likely automated, so no response either
	noreply := regexp.MustCompile(`^noreply`)
	if autoresponder_enabled(user, domain) &&
	   !noreply.MatchString(sender) &&
	   sender != "" &&
	   message.Object.Header.Get("List-ID") == "" &&
	   message.Object.Header.Get("X-Mailer") != "" {
		if autoresponder_history(user, domain, sender, 604800) {
			ar := "From: <"+message.Recipient+">\n"
			ar += "To: <"+sender+">\n"
			ar += "Message-ID: <"+epoch()+strconv.Itoa(os.Getpid())+"@"+sys_hostname()+">\n"
			ar += "Date: "+rfc2822_date()+"\n"
			if message.Object.Header.Get("Subject") == "" {
				ar += "Subject: Autoresponder reply\n"
			} else {
				ar += "Subject: Auto: "+message.Object.Header.Get("Subject")
			}
			ar += "\n\n"
			ar += autoresponder_text(user, domain)

			_, arsuccess, _ := sysexec("/var/qmail/bin/qmail-inject", []string{"-f"+message.Recipient, sender}, []byte(ar))
			if arsuccess == 0 {
				record_autoresponse(email_to_uid(user,domain), sender)
			}
		}
	}

	if len(deliveryresults) == 1 {
		// For a single delivery, we pass through the exit code
		exitcode = deliveryresults[0]
	} else {
		// For multiple deliveries, if one fails, we exit 111 to get another chance
		// Yes, that may cause duplicates, but that's better than losing mail
		if array_sum(deliveryresults) > 0 {
			exitcode = 111
		} else {
			exitcode = 0
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
	_, _ = io.WriteString(hash, message)
	return fmt.Sprintf("%x", hash.Sum(nil))
}

func sha1sum_body (message string) (string) {
	// Ignore Headers so that duplicate detection can actually work
        re, _ := regexp.Compile(`\n\n`)
        fsi := re.FindStringIndex(message)
        body := message[fsi[1]:]

        hash := sha1.New()
        _, _ = io.WriteString(hash, body)
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
	debug("Preparing statement in antispam_enabled\n")
//	stmt1, err := db.Prepare("SELECT DISTINCT passwd.antispam FROM passwd INNER JOIN mapping ON passwd.uid = mapping.uid WHERE user = ? AND domain = ? AND antispam > 0")
	stmt1, err := db.Prepare("SELECT COUNT(passwd.antispam) FROM passwd INNER JOIN mapping ON passwd.uid = mapping.uid WHERE user = ? AND domain = ? AND antispam > 0")
        if err != nil {
		fmt.Println(err)
		os.Exit(111)
        }
	debug("Running query in antispam_enabled\n")
	err = stmt1.QueryRow(user, domain).Scan(&count)
        if err != nil {
		fmt.Println(err)
                os.Exit(111)
        }

	return count > 0
}

func antivir_enabled (user string, domain string) (bool) {
	var count int
	debug("Preparing statement in antivir_enabled\n")
//	stmt1, err := db.Prepare("SELECT DISTINCT passwd.antivir FROM passwd INNER JOIN mapping ON passwd.uid = mapping.uid WHERE user = ? AND domain = ? AND antivir > 0")
	stmt1, err := db.Prepare("SELECT COUNT(passwd.antivir) FROM passwd INNER JOIN mapping ON passwd.uid = mapping.uid WHERE user = ? AND domain = ? AND antivir > 0")
        if err != nil {
		fmt.Println(err)
		os.Exit(111)
        }
	debug("Running query in antivir_enabled\n")
	err = stmt1.QueryRow(user, domain).Scan(&count)
        if err != nil {
		fmt.Println(err)
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

func directory_filelist_recursive (directory string) ([]string, error) {
	re := regexp.MustCompile("permission denied")
	var filelist []string

	debug("Indexing "+directory+" in directory_filelist_recursive\n")
	err := filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		// We ignore "permission denied" errors"
		if err != nil && !re.MatchString(err.Error()) {
			return err
		}

		if !info.IsDir() {
			// If it's not a directory, stick it into filelist
			filelist = append(filelist, path)
		}
		return nil
	})

	// if Walk ran into an error we return an empty list and pass the error up
	if err != nil {
		return nil, err
	}

	// On success we return a filelist and a nil error
	return filelist, nil
}

func is_duplicate (directory string, hash string) (bool) {
//	filelist, err := directory_filelist(directory)
	debug("Getting file list for "+directory+" in is_duplicate\n")
	filelist, err := directory_filelist_recursive(directory)
	if err != nil {
		return false
	}
	// filelist can be empty, handle this
	if filelist == nil {
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
	// Make sure that destination actually is a directory
	if !is_directory(directory) {
		return false
	}
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

func spamd_available () (bool) {
	_, spamdstatus, _ := sysexec("/usr/bin/spamc", []string{"-K"}, nil)
	return spamdstatus == 0
}

func dupfilter_enabled (user string, domain string) (bool) {
	var count int
	debug("Preparing statement in dupfilter_enabled\n")
	stmt1, err := db.Prepare("SELECT COUNT(passwd.dupfilter) FROM passwd INNER JOIN mapping ON passwd.uid = mapping.uid WHERE user = ? AND domain = ? AND dupfilter > 0")
        if err != nil {
		fmt.Println(err)
		os.Exit(111)
        }
	debug("Running query in dupfilter_enabled\n")
	err = stmt1.QueryRow(user, domain).Scan(&count)
        if err != nil {
		fmt.Println(err)
                os.Exit(111)
        }

	return count > 0
}

func env_defined (key string) bool {
  value, exists := os.LookupEnv(key)
  _ = value

  return exists
}

func autoresponder_enabled (user string, domain string) (bool) {
	var count int
	debug("Preparing statement in autoresponder_enabled\n")
//	stmt1, err := db.Prepare("SELECT CHAR_LENGTH(passwd.artext) FROM passwd INNER JOIN mapping ON passwd.uid = mapping.uid WHERE user = ? AND domain = ? AND arstart > 0 AND arend >= UNIX_TIMESTAMP()")
	stmt1, err := db.Prepare("SELECT COUNT(*) FROM passwd INNER JOIN mapping ON passwd.uid = mapping.uid WHERE user = ? AND domain = ? AND arstart > 0 AND arend >= UNIX_TIMESTAMP()")
        if err != nil {
		fmt.Println(err)
		os.Exit(111)
        }
	debug("Running query in autoresponder_enabled\n")
	err = stmt1.QueryRow(user, domain).Scan(&count)
        if err != nil {
		fmt.Println(err)
                os.Exit(111)
        }

	return count > 0
}

func autoresponder_history (user string, domain string, sender string, duration int) bool {
	var count int
	debug("Preparing statement in autoresponder_history\n")
	stmt1, err := db.Prepare("SELECT COUNT(*) FROM responses WHERE uid = "+string(email_to_uid(user,domain))+" AND rcpt = ? AND time > (UNIX_TIMESTAMP() - "+string(duration) )
        if err != nil {
		fmt.Println(err)
		os.Exit(111)
        }
	debug("Running query in autoresponder_history\n")
	err = stmt1.QueryRow(user, domain).Scan(&count)
        if err != nil {
		fmt.Println(err)
                os.Exit(111)
        }

	return count > 0
}

func email_to_uid (user string, domain string) (int) {
	var uid int
	debug("Preparing statement in email_to_uid\n")
	stmt1, err := db.Prepare("SELECT uid FROM passwd INNER JOIN mapping ON passwd.uid = mapping.uid WHERE user = ? AND domain = ?")
        if err != nil {
		fmt.Println(err)
		os.Exit(111)
        }
	debug("Running query in email_to_uid\n")
	err = stmt1.QueryRow(user, domain).Scan(&uid)
        if err != nil {
		fmt.Println(err)
                os.Exit(111)
        }

	return uid
}

func autoresponder_text (user string, domain string) (string) {
	var artext string
	debug("Preparing statement in autresponder_text\n")
	stmt1, err := db.Prepare("SELECT artext FROM passwd INNER JOIN mapping ON passwd.uid = mapping.uid WHERE user = ? AND domain = ?")
        if err != nil {
		fmt.Println(err)
		os.Exit(111)
        }
	debug("Running query in autresponder_text\n")
	err = stmt1.QueryRow(user, domain).Scan(&artext)
        if err != nil {
		fmt.Println(err)
                os.Exit(111)
        }

	return artext
}

func record_autoresponse (from int, to string) bool {
	debug("Preparing statement in record_autoresponse\n")
	stmt1, err := db.Prepare("INSERT INTO responses VALUES ('', ?, ?, UNIX_TIMESTAMP() )")
        if err != nil {
		fmt.Println(err)
		os.Exit(111)
        }
	debug("Running query in record_autoresponse\n")
	_, err = stmt1.Exec(from, to)
//        if err != nil {
//		fmt.Println(err)
//               os.Exit(111)
//      }

	return err == nil
}

func array_sum (input []int) int {
        var sum int
        for _, i := range input {
                sum += i
        }

        return sum
}

func is_directory (path string) bool {
    fileInfo, err := os.Stat(path)
    if err != nil{
      return false
    }
    return fileInfo.IsDir()
}
