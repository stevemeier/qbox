package main

// Author: Steve Meier
// Date:   2019-02-15

// Load modules
import "bytes"
import "encoding/json"
import "flag"
import "fmt"
import "io"
	"io/ioutil"
import "log"
import "log/syslog"
import "net/http"
import "os"
import "regexp"
import "strings"
import "syscall"
import "strconv"
import "time"

var Version string
var configdir string = "/etc/qbox"

func main() {
	var showver bool
	flag.BoolVar(&showver, "v", false, "")
	flag.Parse()

	if showver {
		fmt.Printf("Version %s\n", Version)
		os.Exit(0)
	}

	// Checkpassword server endpoint
	var cpurl string = "http://127.0.0.1:7520/"

	// Try to read config for URL
	buf, err := ioutil.ReadFile(configdir + "/checkpassword-url")
	if err == nil { cpurl = strings.TrimRight(string(buf), "\n") }

	// Dovecot mode indicator
	// Dovecot does not support the classic checkpassword concept
	// see: https://wiki2.dovecot.org/AuthDatabase/CheckPassword#Security
	// Dovecot will call this program as the `dovecot` user which does not have any rights
	// in the system, so we do not check access to the maildir
	var dovecot bool = false

	// Setup syslogger
	// The priority value is calculated using the formula (Priority = Facility * 8 + Level)
	// https://success.trendmicro.com/solution/TP000086250-What-are-Syslog-Facilities-and-Levels
	// Mail is facility 2 and level should be error, which is 3
	// 2*8 + 3 = 19
	syslog, err := syslog.New(19, "checkpassword-client")
	if err != nil {
		log.Fatal(err)
		os.Exit(3)
	}

	// Open fd3
	fd3 := os.NewFile(3, "/proc/self/fd/3")

	// Read a complete, bounded checkpassword record. The third field is optional.
	data, err := io.ReadAll(io.LimitReader(fd3, 513))
	fd3.Close()
	if err != nil || len(data) > 512 {
		os.Exit(2)
	}
	input := bytes.Split(data, []byte{0})
	if len(input) < 3 || len(input[0]) == 0 || len(input[2]) != 0 {
		os.Exit(2)
	}
	// A missing timestamp is represented by an empty third field.
	if len(input) > 4 || (len(input) == 4 && len(input[3]) != 0) {
		os.Exit(2)
	}

	// Username should always be lowercase, hence ToLower
	username := strings.ToLower(string(input[0]))
	password := string(input[1])
	// Timestamp is either provided or filled with epoch
	timestamp := timestamp_or_epoch(string(input[2]))

	// Determine client IP address from environment
	// sslserver sets $SSLREMOTEIP
	// tcpserver sets $TCPREMOTEIP or $TCP6REMOTEIP
	// stunnel sets $REMOTE_HOST
	var ipaddr string = ip_from_env("SSLREMOTEIP")
	if len(ipaddr) == 0 {
		ipaddr = ip_from_env("TCPREMOTEIP")
	}
	if len(ipaddr) == 0 {
		ipaddr = ip_from_env("TCP6REMOTEIP")
	}
	if len(ipaddr) == 0 {
		ipaddr = ip_from_env("REMOTE_HOST")
	}
	if len(ipaddr) == 0 {
		ipaddr = "127.0.0.1"
	}

	// Determine service called by TCP port (smtp/pop/imap)
	var service string = service_name()

	// Make HTTP call to authentication backend
	// Construct JSON body
	body, _ := json.Marshal(map[string]string{
		"username": username,
		"password": password,
		"timestamp": timestamp,
		"service": service,
		"source": ipaddr,
	})

	// Setup HTTP client, request and headers
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest("POST", cpurl, bytes.NewBuffer(body))
	if err != nil { log.Panic(err) }
	req.Header.Set("Content-Type", "application/json")

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		// If the backend is unreachable, exit 3
		syslog.Write([]byte(fmt.Sprintf("Backend (checkpassword-server at %s) is unreachable", cpurl)))
		os.Exit(3)
	}
	defer resp.Body.Close()

	// Check if we are called from Dovecot
	dovecot, _ = regexp.MatchString("(?i)checkpassword-reply", strings.Join(os.Args[1:], " "))

	// 200 means authentication successful
	if resp.StatusCode == 200 {
		var response struct {
			Home string `json:"home"`
			User string `json:"user"`
			UID int64 `json:"uid"`
			GID int64 `json:"gid"`
			QboxUID int64 `json:"qboxuid"`
			QboxGID int64 `json:"qboxgid"`
		}

		// Unmarshal response from checkpassword-server
		err := json.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			syslog.Write([]byte("Failed to unmarshal checkpassword-server response"))
			os.Exit(4)
		}

		if response.Home == "" || response.User == "" || response.UID <= 0 || response.GID <= 0 || response.QboxUID <= 0 || response.QboxGID <= 0 {
			os.Exit(4)
		}

		// Store ORIG_UID (Dovecot expects this)
		// checkpassword: ORIG_UID environment was dropped by checkpassword.
		// Can't verify if we're safe to run. See http://wiki2.dovecot.org/AuthDatabase/CheckPassword#Security
		var env_orig_uid string = os.Getenv("ORIG_UID")

		// Start with a clean environment
		os.Clearenv()

		// Restore ORIG_UID
		os.Setenv("ORIG_UID", env_orig_uid)

		// Set up the environment for the authenticated user
		os.Setenv("HOME", response.Home)
		os.Setenv("USER", response.User)
		os.Setenv("UID", strconv.FormatInt(response.UID, 10))
		os.Setenv("QBOXUID", strconv.FormatInt(response.QboxUID, 10))
		os.Setenv("QBOXGID", strconv.FormatInt(response.QboxGID, 10))

		// Go to the home directory
		err = os.Chdir(response.Home)
		if err != nil && !dovecot {
			// For Dovecot this is not a problem as it will open the folder itself later
			syslog.Write([]byte(fmt.Sprintf("Failed to chdir to user's homedir %s [%s]", response.Home, err.Error())))
			os.Exit(5)
		}

		if dovecot {
			// Dovecot expects special variables in the environment
			os.Setenv("userdb_uid",  strconv.FormatInt(response.UID, 10))
			os.Setenv("userdb_gid",  strconv.FormatInt(response.GID, 10))
			os.Setenv("userdb_mail", fmt.Sprintf("maildir:%s:LAYOUT=fs:INBOX=%s/INBOX", response.Home, response.Home))
			os.Setenv("EXTRA", "userdb_uid userdb_gid userdb_mail")
		}

		// Run the programm from parameters
		err = syscall.Exec(os.Args[1], os.Args[1:], os.Environ())
		if err != nil {
			syslog.Write([]byte("Failed to exec: "+err.Error()))
			log.Fatal(err)
		}

	} else {
		time.Sleep(3 * time.Second)
		os.Exit(1)
	}
}

func ip_from_env(variable string) string {
	val, ok := os.LookupEnv(variable)
	if !ok {
		return ""
	} else {
		return val
	}
}

func timestamp_or_epoch(timestamp string) string {
	if len(timestamp) > 0 {
		return timestamp
	} else {
		now := time.Now()
		return strconv.FormatInt(now.Unix(), 10)
	}
}

func service_name() string {

	ports := map[int64]string{25: "smtp",
		110: "pop",
		143: "imap",
		465: "smtp",
		587: "smtp",
		993: "imaps",
		995: "pops",
	       1430: "imap",
               9930: "imaps",
               9950: "pops"}

	var ssllocalport int64
	ssllocalport, _ = strconv.ParseInt(os.Getenv("SSLLOCALPORT"), 10, 64)
	if ssllocalport > 0 {
		return ports[ssllocalport]
	}

	var tcplocalport int64
	tcplocalport, _ = strconv.ParseInt(os.Getenv("TCPLOCALPORT"), 10, 64)
	if tcplocalport > 0 {
		return ports[tcplocalport]
	}

	tcplocalport, _ = strconv.ParseInt(os.Getenv("TCP6LOCALPORT"), 10, 64)
	if tcplocalport > 0 {
		return ports[tcplocalport]
	}

	return "smtp"
}
