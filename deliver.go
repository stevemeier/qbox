package main

import "database/sql"
import _ "github.com/go-sql-driver/mysql"
import "context"
import "bytes"
import "encoding/json"
import "errors"
import "fmt"
import "io"
import "io/ioutil"
import "log/syslog"
import "net"
import "os"
import "os/exec"
import "path"
import "path/filepath"
import "regexp"
import "strconv"
import "strings"
import "syscall"
import "time"
import "crypto/sha1"

import "github.com/google/uuid"
import "golang.org/x/sys/unix"
import jwemail "github.com/jordan-wright/email"
import "github.com/baruwa-enterprise/clamd"
import "github.com/teamwork/spamc"

var Version string
const configdir = "/etc/qbox"
var debug_enabled bool = false

// Make DB available globally, not just in main
var db *sql.DB

type email struct {
	Length		int
	Recipient	string
	Sha1		string
	Raw		string		// Message as read from STDIN (unaltered)
	Object		*jwemail.Email	// currently only used for Autoresponder
	ObjectOK	bool		// Indicates if mail was parsed successfully by jwemail
	UseObject	bool		// Use object instead of `Raw`, if true
	IsSpam		bool
}

type report struct {
	Sender		string
	Recipient	string
	Size		int
	ProcessingTime	float64
	Destinations	[]destination
	Results		[]int
	Features	[]string
	Exitcode	int
	ObjectOK	bool
	UseObject	bool
	IsSpam		bool
	OnDisk		int64
}

type destination struct {
	Default		string
	Spam		string
}

func main() {
	// Start a timer
	start := time.Now()

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

	// Generate a session ID to make log grep-ing easier
	session := uuid.NewString()
	syslog_write(fmt.Sprintf("%s / Starting session [version %s]", session, Version))

	// Destinations is an array where email should go
	// contains to strings: Default and Spam
	var destinations []destination

	// Record the delivery results
	var deliveryresults []int

	var dreport report
	dreport.Destinations = []destination{}
	dreport.Features = []string{}
	dreport.Results = []int{}
	var message email
	var err error

	// Read email message from STDIN
	message.Raw, err = read_from_stdin()
	if err != nil {
		os.Exit(1)
	}

	syslog_write(fmt.Sprintf("%s / Read %d bytes from STDIN", session, len(message.Raw)))

	message.Length = len(message.Raw)
	message.Recipient = strings.TrimPrefix(os.Getenv("RECIPIENT"), chomp(file_content(configdir + "/prefix")))
	message.Sha1 = sha1sum(message.Raw)

	// NewEmailFromReader can fail (e.g. escaping issues)
	// If it does, we can't use the object
	// Conveniently, ObjectOK is `false` by default, so we set it to true if the parser does not complain
	var newmailerr error
	message.Object, newmailerr = jwemail.NewEmailFromReader(strings.NewReader(message.Raw))
	if newmailerr == nil { message.ObjectOK = true }

	if (len(message.Recipient) == 0) {
		fmt.Println("RECIPIENT not set!")
		os.Exit(1)
	}

	syslog_write(fmt.Sprintf("%s / Recipient is <%s>", session, message.Recipient))

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

	syslog_write(fmt.Sprintf("%s / Sender is <%s>", session, sender))

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
		fmt.Println("ERROR: Could not connect to MySQL ["+err.Error()+"]")
                os.Exit(exitcode)
        }
        defer db.Close()

	// Check for domain rewrite
	debug("Calling rewrite_domain with parameter: "+domain+"\n")
	domain = rewrite_domain(domain)

	// Remove extension
	debug("Removing extension: "+user+" -> "+remove_extension(user)+"\n")
	user = remove_extension(user)

	// Get destinations
	debug("Calling get_destinations with parameters: "+user+", "+domain+"\n")
	destinations = get_destinations(user, domain)
	if debug_enabled {
		debug("Destinations: "+list_destinations(destinations)+"\n")
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

	// At this point we have at least one destination for the message
	syslog_write(fmt.Sprintf("%s / Destinations: %s", session, list_destinations(destinations)))

	// Check if spam filter is active for this user
	if feature_enabled(user, domain, "antispam") {
		dreport.Features = append(dreport.Features, "antispam")
		debug("Running SPAM scan\n")
		spamresult, spamerr := spamd_scan(&message.Raw)
		if spamerr == nil {
			message.Object.Headers.Set("X-Spam-Flag", bool_yesno(spamresult.IsSpam))
			message.Object.Headers.Set("X-Spam-Level", strings.Repeat(`*`, not_negative(int(spamresult.Score))))
			message.UseObject = true
			if spamresult.Score >= user_spamlimit(user, domain) {
				debug(fmt.Sprintf("Spamlimit %f is reached or exceeded by %f\n", user_spamlimit(user, domain), spamresult.Score))
				message.IsSpam = true
			}
		}
	}

	// Check for existing Spam markers
	subjectline := message.Object.Subject
	// This is used by SpamBarrier
	spamre1 := regexp.MustCompile(`\*\*\*\*\*SPAM\*\*\*\*\*`)
	spamre2 := regexp.MustCompile(`\[SPAM\]`)
	if spamre1.MatchString(subjectline) || spamre2.MatchString(subjectline) {
		syslog_write(fmt.Sprintf("%s / Message already marked as spam (subject line)", session))
		message.IsSpam = true
	}

	// Check if virus filter is active for this user
	if feature_enabled(user, domain, "antivir") {
		dreport.Features = append(dreport.Features, "antivir")
		debug("Running AV scan\n")
		avresult, averr := clamd_scan(&message.Raw)
		if averr == nil {
			debug("AV result: "+ avresult.Status +"\n")
			message.Object.Headers.Set("X-Virus-Scanned", "ClamAV")
			message.UseObject = true
			if avresult.Status != "OK" {
				// Virus was found, strip attachments
				message.Object.Attachments = nil
				// Add a security note instead
				message.Object.Attach(strings.NewReader("Attachments have been removed by virus scanner"), "security_notice.txt", "text/plain")
			}
		}
	}

	for _, dst := range destinations {
		var destination string
		destination = dst.Default
		if message.IsSpam { destination = dst.Spam }

		debug("Starting delivery to "+destination+"\n")
		syslog_write(fmt.Sprintf("%s / Delivering to %s", session, destination))
		switch destination_type(destination) {
		case "maildir":
			if !is_valid_maildir(destination) {
				fmt.Printf("ERROR: %s is not a valid maildir\n", destination)
				deliveryresults = append(deliveryresults, 1)
				break
			}

			dupfilter := feature_enabled(user, domain, "dupfilter")
			if dupfilter { dreport.Features = append(dreport.Features, "dupfilter") }
			if dupfilter && is_duplicate(destination, message.Sha1) {
				fmt.Println("Message to "+destination+" for "+message.Recipient+" was a duplicate ("+message.Sha1+")")
				deliveryresults = append(deliveryresults, 0)
			} else {
				writesuccess, err, ondisk := write_to_maildir(message, destination)
				dreport.OnDisk = ondisk
				if writesuccess  {
					fmt.Println("Message delivered to "+destination+" for "+message.Recipient)
					deliveryresults = append(deliveryresults, 0)
				} else {
					fmt.Println("ERROR: Could not deliver to "+destination+" for "+message.Recipient+" ["+err.Error()+"]")
					deliveryresults = append(deliveryresults, 1)
				}
			}

		case "forward":
			_, fwdsuccess, err := sysexec("/var/qmail/bin/qmail-inject", []string{"-f"+forward_sender(), destination}, []byte(message.Raw))
			if fwdsuccess == 0 {
				fmt.Println("Message forwarded to "+destination+" for "+message.Recipient)
			} else {
				fmt.Println("ERROR: Could not forward to "+destination+" for "+message.Recipient+" ["+err.Error()+"]")
			}
			deliveryresults = append(deliveryresults, fwdsuccess)

		case "pipe":
			destination = strings.TrimPrefix(destination,`|`)
			_, execsuccess, err := sysexec(destination, nil, []byte(message.Raw))
			if execsuccess == 0 {
				fmt.Println("Message piped to "+destination+" for "+message.Recipient)
			} else {
				fmt.Println("ERROR: Pipe failed to "+destination+" for "+message.Recipient+" ["+err.Error()+"]")
			}
			deliveryresults = append(deliveryresults, execsuccess)

		case "":
			fmt.Println("Homedir is not defined for "+message.Recipient)
                        deliveryresults = append(deliveryresults, 111)

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
	   message.Object.Headers.Get("List-ID") == "" &&
	   message.Object.Headers.Get("X-Mailer") != "" {
		if autoresponder_history(user, domain, sender, 604800) {
			ar := jwemail.NewEmail()
			ar.From = "<"+message.Recipient+">"
			ar.To[0] = "<"+sender+">"
			if message.Object.Headers.Get("Subject") == "" {
				ar.Subject = "Autoresponder reply\n"
			} else {
				ar.Subject = "Auto: "+message.Object.Headers.Get("Subject")
			}
			ar.Text = []byte(autoresponder_text(user, domain))

			arbytes, _ := ar.Bytes()
			_, arsuccess, _ := sysexec("/var/qmail/bin/qmail-inject",
						   []string{"-f"+message.Recipient, sender},
						   arbytes)
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
	dreport.Size = message.Length
	dreport.Destinations = destinations
	dreport.Results = deliveryresults
	dreport.Exitcode = exitcode
	dreport.ProcessingTime = time.Duration(time.Since(start)).Seconds()
	dreport.UseObject = message.UseObject
	dreport.ObjectOK = message.ObjectOK
	dreport.IsSpam = message.IsSpam

	// Put delivery report into JSON
	json, _ := json.Marshal(dreport)
	if debug_enabled {
		fmt.Fprintf(os.Stderr, "%s", string(json))
	}

	syslog_write(fmt.Sprintf("%s / Report: %s", session, string(json)))
	syslog_write(fmt.Sprintf("%s / Finishing with code %d", session, exitcode))

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

func write_to_file (message email, filename string) (bool, error) {
	debug("START write_to_file\n")
	unix.Umask(077)

	// Never overwrite existing files
	debug("Checking for existing file\n")
	if file_exists(filename) {
		return false, errors.New("File already exists")
	}

	// Only accept absolute paths (starting with slash)
	debug("Checking for absolute path\n")
	re := regexp.MustCompile(`^/`)
	if !re.MatchString(filename) {
		return false, errors.New("Not an absolute path")
	}

	debug("Writing to "+filename+"\n")
	var werr error
	if message.UseObject && message.ObjectOK {
		// This has never failed so far, but we check anyway
		objbytes, byteerr := message.Object.Bytes()
		if byteerr == nil {
			werr = ioutil.WriteFile(filename, objbytes, 0600)
		} else {
			werr = byteerr
		}
	} else {
		werr = ioutil.WriteFile(filename, []byte(message.Raw), 0600)
	}

	return werr == nil, werr
}

func file_exists (filename string) (bool) {
	debug("START file_exists: "+filename+"\n")
        _, err := os.Stat(filename)
	return !os.IsNotExist(err)
}

func rewrite_domain (domain string) string {
        // Query DB for domain rewrite
        var rewrite sql.NullString
        stmt1, err := db.Prepare("SELECT rewrite FROM domains WHERE domain = ? AND rewrite != ''")
        if err != nil {
		debug("Failed to prepare statement in rewrite_domain")
		os.Exit(111)
        }

        rows1, err := stmt1.Query(domain)
        if err != nil {
		debug("Failed to execute query in rewrite_domain")
                os.Exit(111)
        }
        defer stmt1.Close()

        for rows1.Next() {
                err := rows1.Scan(&rewrite)
                if err != nil {
			debug("Failed to scan row in rewrite_domain "+err.Error())
                        os.Exit(111)
                }
        }

	// See https://stackoverflow.com/questions/40092155/difference-between-string-and-sql-nullstring
	if rewrite.Valid {
		return rewrite.String
	}
	return domain
}

func get_destinations (user string, domain string) ([]destination) {
	var result []destination
	var homedir string
	var spamdir string
	var dbhomedir string
	var dbspamdir string

	debug("Preparing statement in get_destinations\n")
        stmt1, err := db.Prepare("SELECT DISTINCT COALESCE(homedir,''), COALESCE(spamdir,'') FROM passwd WHERE uid IN (?)")
        if err != nil {
		os.Exit(111)
        }
	debug("Running query in get_destinations\n")
        rows1, err := stmt1.Query(email_to_uids(user, domain))
        if err != nil {
                os.Exit(111)
        }
        defer stmt1.Close()

        for rows1.Next() {
		debug("Scanning row in get_destinations\n")
                err := rows1.Scan(&dbhomedir, &dbspamdir)
                if err != nil {
                        os.Exit(111)
                }

		// By default we take the DB's homedir as-is
		homedir = dbhomedir

		// Add `INBOX` suffix and make sure homedir is clean
		if dbhomedir[0:1] == "/" {
			homedir = path.Clean(dbhomedir + "/" + chomp(file_content(configdir + "/inbox")))
		}

		// If `spamdir` is empty, we use `homedir` instead
		// Otherwise, `spamdir` is a relative path to `homedir`, which we clean before using it
		if dbspamdir == "" {
			spamdir = homedir
		} else {
			spamdir = path.Clean(dbhomedir + "/" + dbspamdir)
		}

		result = append(result, destination{homedir, spamdir})
        }

	debug("Reached end of get_destinations\n")
	return result
}

func feature_enabled (user string, domain string, feature string) (bool) {
	// Currently supported:
	// `antispam`
	// `antivir`
	// `autoresponder`
	// `dupfilter`
	var count int
	debug("Preparing statement in feature_enabled ["+feature+"]\n")
	stmt1, err := db.Prepare("SELECT COUNT("+feature+") FROM passwd WHERE uid = ? AND "+feature+" > 0")
        if err != nil {
		debug("ERROR: Failed to prepare feature query ["+err.Error()+"]")
		return false
        }
	debug("Running query in feature_enabled ["+feature+"]\n")
	err = stmt1.QueryRow(email_to_uid(user, domain)).Scan(&count)
        if err != nil {
		debug("ERROR: Failed to get features from DB ["+err.Error()+"]")
		return false
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

func directory_filelist_recursive (directory string) ([]string, error) {
	re := regexp.MustCompile("permission denied")
	var filelist []string = []string{}

	debug("Indexing "+directory+" in directory_filelist_recursive\n")
	err := filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		// We ignore "permission denied" errors"
		if err != nil && !re.MatchString(err.Error()) {
			debug("ERROR: Walk encountered an error ["+err.Error()+"]")
			return err
		}

		if !info.IsDir() {
			// If it's not a directory, stick it into filelist
			filelist = append(filelist, path)
		}
		return nil
	})
	debug("Indexing complete\n")

	// if Walk ran into an error we return an empty list and pass the error up
	if err != nil {
		debug("directory_filelist_recursive failed\n")
		return []string{}, err
	}

	// On success we return a filelist and a nil error
	debug("directory_filelist_recursive OK\n")
	return filelist, nil
}

func is_duplicate (directory string, hash string) (bool) {
	debug("Getting file list for "+directory+" in is_duplicate\n")
	filelist, err := directory_filelist_recursive(directory)
	if err != nil {
		return false
	}

	// filelist can be empty, handle this
	for _, file := range filelist {
		if strings.Contains(file, hash) {
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

func write_to_maildir (message email, directory string) (bool, error, int64) {
	// If homedir is set to /dev/null, silently discard the message
	if strings.HasPrefix(directory, "/dev/null") {
		return true, nil, -1
	}
	// Make sure that destination actually is a directory
	if !is_directory(directory) {
		return false, errors.New("Not a directory"), -1
	}
	// Check if directory is writable
	if !directory_is_writable(directory) {
		return false, errors.New("Permission denied"), -1
	}
	// Example filename:
	// 1576429450084839306.27056.bart.lordy.de.7a3e892ba01ce9899d101745da2757a81ac55779
	filename := epoch()+`.`+strconv.Itoa(os.Getpid())+`.`+sys_hostname()+`.`+message.Sha1
	debug("Designated filename is "+filename+"\n")
	writesuccess, err := write_to_file(message, directory+"/tmp/"+filename)
	ondisk := filesize(directory+"/tmp/"+filename)

	if writesuccess {
		linkerr := os.Link(directory+"/tmp/"+filename, directory+"/new/"+filename)
		if linkerr == nil {
			rmerr := os.Remove(directory+"/tmp/"+filename)
			if rmerr == nil {
				return true, nil, ondisk
			} else {
				return false, rmerr, ondisk
			}
		} else {
			return false, linkerr, ondisk
		}
	}

	return false, err, ondisk
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

func env_defined (key string) (bool) {
	_, exists := os.LookupEnv(key)
	return exists
}

func autoresponder_history (user string, domain string, sender string, duration int) (bool) {
	var count int
	debug("Preparing statement in autoresponder_history\n")
	stmt1, err := db.Prepare("SELECT COUNT(*) FROM responses WHERE uid = ? AND rcpt = ? AND time > (UNIX_TIMESTAMP() - "+strconv.Itoa(duration)+")")
        if err != nil {
		fmt.Println(err)
		os.Exit(111)
        }
	debug("Running query in autoresponder_history\n")
	err = stmt1.QueryRow(email_to_uid(user, domain), sender).Scan(&count)
        if err != nil {
		fmt.Println(err)
                os.Exit(111)
        }

	return count > 0
}

func email_to_uid (user string, domain string) (int) {
	// This is bad code because one email can map to multiple UIDs
	var uid int = -1
	debug("Preparing statement in email_to_uid\n")
	stmt1, err := db.Prepare("SELECT passwd.uid FROM passwd INNER JOIN mapping ON passwd.uid = mapping.uid WHERE user = ? AND domain = ?")
        if err != nil {
		fmt.Println(err)
		os.Exit(111)
        }
	debug("Running query in email_to_uid\n")
	err = stmt1.QueryRow(user, domain).Scan(&uid)

	// If the first query procudes no result, check for wildcard mapping
	if err == sql.ErrNoRows {
		err = stmt1.QueryRow("*", domain).Scan(&uid)
	}

	// If error is still not nil, we have no mapping and need to defer delivery
        if err != nil {
		fmt.Println(err)
                os.Exit(111)
        }

	return uid
}

func email_to_uids (user string, domain string) ([]int) {
	// This is bad code because one email can map to multiple UIDs
	var uids []int
	var rows *sql.Rows

	debug("Preparing statement in email_to_uids\n")
	stmt1, err := db.Prepare("SELECT passwd.uid FROM passwd INNER JOIN mapping ON passwd.uid = mapping.uid WHERE user = ? AND domain = ?")
        if err != nil {
		fmt.Println(err)
		os.Exit(111)
        }
	debug("Running query in email_to_uids\n")
	rows, err = stmt1.Query(user, domain)

	// If the first query procudes no result, check for wildcard mapping
	if err == sql.ErrNoRows {
		rows, err = stmt1.Query("*", domain)
	}

	// Iterate over results
	for rows.Next() {
		var nextuid int
		rows.Scan(&nextuid)
		uids = append(uids, nextuid)
	}

	// If error is still not nil, we have no mapping and need to defer delivery
        if err != nil {
		fmt.Println(err)
                os.Exit(111)
        }

	debug(fmt.Sprintf("Returning %d results from email_to_uids: %v", len(uids), uids))
	return uids
}

func autoresponder_text (user string, domain string) (string) {
	var artext string
	debug("Preparing statement in autresponder_text\n")
	stmt1, err := db.Prepare("SELECT artext FROM passwd WHERE uid = ?")
        if err != nil {
		fmt.Println(err)
		os.Exit(111)
        }
	debug("Running query in autresponder_text\n")
	err = stmt1.QueryRow(email_to_uid(user, domain)).Scan(&artext)
        if err != nil {
		fmt.Println(err)
                os.Exit(111)
        }

	return artext
}

func record_autoresponse (from int, to string) (bool) {
	debug("Preparing statement in record_autoresponse\n")
	stmt1, err := db.Prepare("INSERT INTO responses VALUES ('', ?, ?, UNIX_TIMESTAMP() )")
        if err != nil {
		fmt.Println(err)
		return false
        }
	debug("Running query in record_autoresponse\n")
	_, err = stmt1.Exec(from, to)

	return err == nil
}

func array_sum (input []int) (int) {
        var sum int
        for _, i := range input {
                sum += i
        }

        return sum
}

func is_directory (path string) (bool) {
	fileInfo, err := os.Stat(path)
	if err != nil { return false }
	return fileInfo.IsDir()
}

func is_executable (file string) (bool) {
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

func spamd_scan (input *string) (*spamc.ResponseCheck, error) {
	var spamd_url string = "127.0.0.1:783"
	// read config file
	if file_exists(configdir+"/spamd") {
		spamd_url = file_content(configdir+"/spamd")
	}
	// initialize client
	spamc := spamc.New(spamd_url, &net.Dialer{ Timeout: 2 * time.Second })
	// do scan
	check, err := spamc.Check(context.Background(), strings.NewReader(*input), nil)
	return check, err
}

func clamd_scan (input *string) (*clamd.Response, error) {
	var clamd_url string = "127.0.0.1:3310"
	// read config file
	if file_exists(configdir+"/clamd") {
		clamd_url = file_content(configdir+"/clamd")
	}
	// initialize client
	clamc, _ := clamd.NewClient("tcp", clamd_url)
	// do scan
	avresult, err := clamc.ScanReader(context.Background(), strings.NewReader(*input))
	if err == nil {
		return avresult[0], err
	} else {
		return nil, err
	}
}

func directory_is_writable (directory string) (bool) {
	return unix.Access(directory, unix.W_OK) == nil
}

func forward_sender () (string) {
	var result string
	if file_exists(configdir+"/forward_sender") {
		result = file_content(configdir+"/forward_sender")
		return chomp(result)
	}

	return "postmaster@"+sys_hostname()
}

func chomp (s string) (string) {
	return strings.TrimRight(s, "\n")
}

func not_negative (i int) (int) {
	if i < 0 { return 0 }
	return i
}

func remove_extension (s string) (string) {
	// https://stackoverflow.com/a/29581738
	if idx := strings.Index(s, "+"); idx != -1 {
		return s[:idx]
	}
	return s
}

func list_destinations (dst []destination) (string) {
	var pairs []string

	for _, item := range dst {
		pairs = append(pairs, fmt.Sprintf("[%s -> %s]", item.Default, item.Spam))
	}

	return strings.Join(pairs[:], ",")
}

func is_valid_maildir (dir string) (bool) {
	return	directory_is_writable(dir+"/cur") &&
		directory_is_writable(dir+"/new") &&
		directory_is_writable(dir+"/tmp")
}

func user_spamlimit (user string, domain string) (float64) {
	var spamlimit float64

	debug("Preparing statement in user_spamlimit\n")
	stmt1, err := db.Prepare("SELECT COALESCE(spamlimit,0) FROM passwd WHERE uid = ?")
        if err != nil {
		fmt.Println(err)
		return 0
        }

	debug("Running query in user_spamlimit\n")
	err = stmt1.QueryRow(email_to_uid(user,domain)).Scan(&spamlimit)

	if err != nil { return 100 }
	return spamlimit
}

func filesize (filename string) (int64) {
	fi, err := os.Stat(filename)
	if err != nil {
		return -1
	}

	return fi.Size()
}

func syslog_write (message string) (error) {
	// If run in debug mode, we write to STDERR, not syslog
	if debug_enabled {
		fmt.Fprint(os.Stderr, message)
		return nil
	} else {
		syslogger, _ := syslog.New(22, os.Args[0])
		_, err := syslogger.Write([]byte(message))
		_ = syslogger.Close()
		return err
	}
}
