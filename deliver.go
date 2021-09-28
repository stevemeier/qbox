package main

import "database/sql"
import _ "github.com/go-sql-driver/mysql"
import "bytes"
import "encoding/json"
import "errors"
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
import "syscall"
import "time"
import "crypto/sha1"

import "github.com/davecgh/go-spew/spew"
import "golang.org/x/sys/unix"
import jwemail "github.com/jordan-wright/email"

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
	Object		*mail.Message	// currently only used for Autoresponder
}

type report struct {
	Sender		string
	Recipient	string
	Destinations	[]string
	Results		[]int
	Exitcode	int
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

	var dreport report
	var message email
	var err error

	// Read email message from STDIN
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

	// Read the `sender` from the environment
	var sender string
	if env_defined("SENDER") {
		sender = os.Getenv("SENDER")
	}

        // Read config files
        var dbserver string = "127.0.0.1"
        if file_exists(configdir + "/dbserver") {
		dbserver = file_content(configdir + "/dbserver")
        }

        var dbuser string = "qbox"
        if file_exists(configdir + "/dbuser") {
		dbuser = file_content(configdir + "/dbuser")
        }

        var dbpass string
        if file_exists(configdir + "/dbpass") {
		dbpass = file_content(configdir + "/dbpass")
        }

        // Initialize DB
        db, err = sql.Open("mysql", dbuser+":"+dbpass+"@tcp("+dbserver+")/qbox")
        if err == nil {
                err = db.Ping()
                if err != nil {
			fmt.Println("ERROR: MySQL db.Ping failed! ["+err.Error()+"]")
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

	if feature_enabled(user, domain, "antispam") && spamd_available() {
		tempfile := write_to_tempfile(message)
		defer os.Remove(tempfile)
		debug("Starting spamc\n")
		antispamresult, antispamsuccess, _ := sysexec("/usr/bin/spamc", []string{"-E"}, []byte(message.Text))
		// Spamc will exit 0 on ham, 1 on spam
		if antispamsuccess < 2 {
			message.Text = string(antispamresult)
		}
	}

	if feature_enabled(user, domain, "antivir") {
		tempfile := write_to_tempfile(message)
		defer os.Remove(tempfile)
		debug("Starting clamdscan\n")
		_, antivirsuccess, _ := sysexec("/usr/bin/clamdscan", []string{tempfile}, nil)
		if antivirsuccess == 1 {
			// Infected mails go to the quarantine
			destinations = []string{quarantine}
		}
	}

	for _, destination := range destinations {
		debug("Starting delivery to "+destination+"\n")
		switch destination_type(destination) {
		case "maildir":
			if feature_enabled(user, domain, "dupfilter") && is_duplicate(destination+"/INBOX", message.Sha1) {
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
			_, fwdsuccess, err := sysexec("/var/qmail/bin/qmail-inject", []string{"-fpostmaster@mail.lordy.de", destination}, []byte(message.Text))
			if fwdsuccess == 0 {
				fmt.Println("Message forwarded to "+destination+" for "+message.Recipient)
			} else {
				fmt.Println("ERROR: Could not forward to "+destination+" for "+message.Recipient+" ["+err.Error()+"]")
			}
			deliveryresults = append(deliveryresults, fwdsuccess)

		case "pipe":
			destination = strings.TrimPrefix(destination,`|`)
			_, execsuccess, err := sysexec(destination, nil, []byte(message.Text))
			if execsuccess == 0 {
				fmt.Println("Message piped to "+destination+" for "+message.Recipient)
			} else {
				fmt.Println("ERROR: Pipe failed to "+destination+" for "+message.Recipient+" ["+err.Error()+"]")
			}
			deliveryresults = append(deliveryresults, execsuccess)

		default:
			fmt.Println("Can not handle "+destination+" for "+message.Recipient)
			deliveryresults = append(deliveryresults, 111)
		}
	}

	// Autoresponder code goes here
	// Mailing lists are ignored (if List-ID header is present)
	// If there is no X-Mailer Header, it's likely automated, so no response either
	noreply := regexp.MustCompile(`^noreply`)
	if feature_enabled(user, domain, "autoresponder") &&
	   !noreply.MatchString(sender) &&
	   sender != "" &&
	   message.Object.Header.Get("List-ID") == "" &&
	   message.Object.Header.Get("X-Mailer") != "" {
		if autoresponder_history(user, domain, sender, 604800) {
			ar := jwemail.NewEmail()
			ar.From = "<"+message.Recipient+">"
			ar.To[0] = "<"+sender+">"
			if message.Object.Header.Get("Subject") == "" {
				ar.Subject = "Autoresponder reply\n"
			} else {
				ar.Subject = "Auto: "+message.Object.Header.Get("Subject")
			}
			ar.Text = []byte(autoresponder_text(user, domain))

			arbytes, _ := ar.Bytes()
			_, arsuccess, _ := sysexec("/var/qmail/bin/qmail-inject", []string{"-f"+message.Recipient, sender}, arbytes)
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

	// Delivery Report
	dreport.Sender = os.Getenv("SENDER")
	dreport.Recipient = message.Recipient
	dreport.Destinations = destinations
	dreport.Results = deliveryresults
	dreport.Exitcode = exitcode
	if debug_enabled {
		json, _ := json.Marshal(dreport)
		fmt.Fprintf(os.Stderr, "%s", string(json))
	}

	os.Exit(exitcode)
}

func read_from_stdin () (string, error) {
        var message []byte
	message, err := ioutil.ReadAll(os.Stdin)
	return string(message), err
}

func sha1sum (message string) (string) {
	hash := sha1.New()
	_, _ = io.WriteString(hash, message)
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
        stmt1, err := db.Prepare("SELECT DISTINCT passwd.homedir FROM passwd "+
	                         "INNER JOIN mapping ON passwd.uid = mapping.uid "+
				 "WHERE user = ? AND domain = ?")
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

func feature_enabled (user string, domain string, feature string) (bool) {
	// Currently supported:
	// `antispam`
	// `antivir`
	// `autoresponder`
	// `dupfilter`
	var count int
	debug("Preparing statement in feature_enabled ["+feature+"]\n")
	stmt1, err := db.Prepare("SELECT COUNT(passwd."+feature+") FROM passwd "+
	                         "INNER JOIN mapping ON passwd.uid = mapping.uid "+
				 "WHERE user = ? AND domain = ? AND "+feature+" > 0")
        if err != nil {
		fmt.Println(err)
		os.Exit(111)
        }
	debug("Running query in feature_enabled ["+feature+"]\n")
	err = stmt1.QueryRow(user, domain).Scan(&count)
        if err != nil {
		fmt.Println(err)
                os.Exit(111)
        }

	return count > 0
}

func sysexec (command string, args []string, input []byte) ([]byte, int, error) {
	var output bytes.Buffer

	if !file_exists(command) {
		return nil, 111, errors.New("command not found")
	}

	if !is_executable(command) {
		return nil, 111, errors.New("command not executable")
	}

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

//func rfc2822_date () (string) {
//	layout := "Mon, 02 Jan 2006 15:04:05 UTC"
//	time := time.Now().UTC()
//	return time.Format(layout)
//}

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
	debug("Getting file list for "+directory+" in is_duplicate\n")
	filelist, err := directory_filelist_recursive(directory)
	if err != nil {
		return false
	}
	// filelist can be empty, handle this
	if filelist == nil {
		return false
	}

//	re, _ := regexp.Compile(`.`+hash)

	for _, file := range filelist {
//		if re.MatchString(file) {
		if strings.HasSuffix(file, hash) {
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
	// If homedir is set to /dev/null, silently discard the message
	if strings.HasPrefix(directory, "/dev/null") {
		return true
	}
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

func env_defined (key string) bool {
	_, exists := os.LookupEnv(key)
	return exists
}

func autoresponder_history (user string, domain string, sender string, duration int) bool {
	var count int
	debug("Preparing statement in autoresponder_history\n")
	stmt1, err := db.Prepare("SELECT COUNT(*) FROM responses WHERE uid = "+strconv.Itoa(email_to_uid(user,domain))+" AND rcpt = ? AND time > (UNIX_TIMESTAMP() - "+strconv.Itoa(duration)+")")
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
	if err != nil { return false }
	return fileInfo.IsDir()
}

func is_executable (file string) bool {
        stat, err := os.Stat(file)
        if err != nil {
                return false
        }

        // These calls return uint32 by default while
        // os.Get?id returns int. So we have to change one
        fileuid := int(stat.Sys().(*syscall.Stat_t).Uid)
        filegid := int(stat.Sys().(*syscall.Stat_t).Gid)

        if (os.Getuid() == fileuid) { return stat.Mode()&0100 != 0 }
        if (os.Getgid() == filegid) { return stat.Mode()&0010 != 0 }
        return stat.Mode()&0001 != 0
}

func bool_yesno (input bool) (string) {
	if input { return "Yes" }
	return "No"
}

func file_content (filename string) (string) {
	buf, err := ioutil.ReadFile(filename)
	if err == nil { return string(buf) }
	return ""
}
