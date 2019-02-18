package main

// Author: Steve Meier
// Date:   2019-02-15

// Load modules
import "bytes"
import "fmt"
import "gopkg.in/resty.v1"
import "os"
import "log"
import "time"
import "encoding/json"
import "regexp"
import "strings"
import "syscall"
import "strconv"

func main() {

  // Open fd3
  fd3 := os.NewFile(3, "/proc/self/fd/3")

  // Read 512 bytes from fd3
  data := make([]byte, 512)
  count, err := fd3.Read(data)
  // we need to do something with `count` so the compiler doesn't complain
  _ = count
  if err != nil {
    log.Fatal(err)
    os.Exit(2)
  }

  // Close fd3
  fd3.Close()

  // Split input by nullbyte
  input := bytes.Split(data, []byte("\x00"))

  // Username should always be lowercase, hence ToLower
  username := strings.ToLower(string(input[0]))
  password := string(input[1])
  // Timestamp is either provided or filled with epoch
  timestamp := timestamp_or_epoch(string(input[2]))

  // Determine client IP address from environment
  var ipaddr string
  ipaddr = ip_from_env("SSLREMOTEIP")
  if len(ipaddr) == 0 {
    ipaddr = ip_from_env("TCPREMOTEIP")
  }
  if len(ipaddr) == 0 {
    ipaddr = "127.0.0.1"
  }

  // Determine service called by TCP port (smtp/pop/imap)
  var service string = service_name()

  // Make HTTP call to authentication backend
  resp, err := resty.R().
               SetHeader("Content-Type", "application/json").
  	       SetBody(`{"username":"`  + username +
                     `", "password":"`  + password +
                     `", "timestamp":"` + timestamp +
                     `", "service":"`   + service +
                     `", "source":"`    + ipaddr + `"}`).
               Post("http://127.0.0.1:7520/")

  // If the backend is unreachable, exit 3
  if err != nil {
    os.Exit(3)
  }

  // 200 means authentication successful
  if resp.StatusCode() == 200 {
    var response map[string]interface{}
    json.Unmarshal(resp.Body(), &response)

    // Store ORIG_UID (Dovecot expects this)
    // checkpassword: ORIG_UID environment was dropped by checkpassword.
    // Can't verify if we're safe to run. See http://wiki2.dovecot.org/AuthDatabase/CheckPassword#Security
    var env_orig_uid string = os.Getenv("ORIG_UID")

    // Start with a clean environment
    os.Clearenv()

    // Restore ORIG_UID
    os.Setenv("ORIG_UID", env_orig_uid)

    // Set up the environment for the authenticated user
    os.Setenv("HOME", response["home"].(string))
    os.Setenv("USER", response["user"].(string))
    os.Setenv("UID",  fmt.Sprintf("%.0f", response["uid"]))
    os.Setenv("QBOXUID", fmt.Sprintf("%.0f", response["qboxuid"]))
    os.Setenv("QBOXGID", fmt.Sprintf("%.0f", response["qboxgid"]))

    // Go to the home directory
    os.Chdir(response["home"].(string))

    var args string = strings.Join(os.Args[1:]," ")

    // If called by checkpassword-reply (from Dovecot) return userdb id
    // If not, setuid/gid to for the user
    match, _ := regexp.MatchString("(?i)checkpassword-reply", args)
    if match { 
      os.Setenv("userdb_uid", fmt.Sprintf("%.0f", response["uid"]))
      os.Setenv("userdb_gid", fmt.Sprintf("%.0f", response["gid"]))
      os.Setenv("EXTRA", "userdb_uid userdb_gid")
    } else {
      syscall.Setgid(int(response["gid"].(float64)))
      syscall.Setuid(int(response["uid"].(float64)))
    }

    // Run the programm from parameters
    err := syscall.Exec(os.Args[1], os.Args[1:], os.Environ())
    if err != nil { log.Fatal(err) }

  } else {
    time.Sleep(3)
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

  ports := map[int64]string{ 25:"smtp",
                            110:"pop",
                            143:"imap",
                            465:"smtp",
                            587:"smtp",
                            993:"imap",
                            995:"pop"}

  ssllocalport, _ := strconv.ParseInt(os.Getenv("SSLLOCALPORT"), 10, 64)
  if ssllocalport > 0 {
    return ports[ssllocalport]
  }

  tcplocalport, _ := strconv.ParseInt(os.Getenv("TCPLOCALPORT"), 10, 64)
  if tcplocalport > 0 {
    return ports[tcplocalport]
  }
  
  return "smtp"
}
