package main

import "crypto/hmac"
import "crypto/md5"
import "encoding/json"
import "fmt"
import "io"
import "io/ioutil"
import "log"
import "net/http"
import "os"
import "os/exec"
import "strconv"
import "syscall"
import "time"
// Debugging
//import "github.com/davecgh/go-spew/spew"
// HTTP Routing
import "github.com/gorilla/mux"
// DB
import "database/sql"
import _ "github.com/go-sql-driver/mysql"
// Crypt (unix_md5_crypt)
// import "github.com/GehirnInc/crypt"
// OTP
import "github.com/hgfischer/go-otp"
// Getopt
import "github.com/DavidGamba/go-getoptions"

const configdir = "/etc/qbox"

//type authcachedata struct {
//	uid	int64
//	gid	int64
//	user	string
//	home	string
//	qboxuid	int64
//	qboxgid	int64
//}
//
//type authcachemeta struct {
//	epoch	int64
//	data	authcachedata
//}

type authfaildata struct {
	epoch	int64
	message	string
}

var authfail = make(map[string][]authfaildata)
var maxfail int
var failscript string

type clientreqdata struct {
	Username	string
	Password	string
	Timestamp	string
	Service		string
	Source		string
}

var db *sql.DB

func authenticate(w http.ResponseWriter, r *http.Request) {
	var services = [...]string {"smtp","smtps","pop","pops","pop3","pop3s","imap","imaps"}

	var authok bool = false
	var reqdata clientreqdata

	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "{\"error\":\"Could not read request body\"}\n")
		return
	}

	if len(reqBody) == 0 {
		// GET
		reqdata.Username  = mux.Vars(r)["username"]
		reqdata.Password  = mux.Vars(r)["password"]
		reqdata.Service   = mux.Vars(r)["service"]
		reqdata.Source    = mux.Vars(r)["source"]
		reqdata.Timestamp = mux.Vars(r)["timestamp"]
//		if err != nil {
//			w.WriteHeader(http.StatusBadRequest)
//			fmt.Fprintf(w, "{\"error\":\"Could not parse parameters\"}\n")
//			return
//		}
	} else {
		// POST
		err := json.Unmarshal(reqBody, &reqdata)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "{\"error\":\"Could not parse JSON\"}\n")
			return
		}
	}

	// Check if serice is supported
	var servicesupported bool = false
	for _, v := range(services) {
		if v == reqdata.Service { servicesupported = true }
	}
	if !servicesupported {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "{\"error\":\"Service '%s' is not supported\"}\n", reqdata.Service)
		return
	}

	// `root` is always denied
	if (reqdata.Username == "root") {
		fmt.Fprintf(os.Stderr, "User root denied on %s from %s\n", reqdata.Service, reqdata.Source)
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, "{\"error\":\"root logins are prohibited\"}\n")
		return
	}

	// Check that DB is still there
	err = db.Ping()
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintf(w, "{\"error\":\"Database unavailable\"}\n")
		return
	}

	// Query DB
	type dbschema struct {
		password	string
		homedir		string
		sysuid		int64
		sysgid		int64
		quota		int64
		uid		int64
		gid		int64
		oathtoken	string
		aliasof		string
	}
	var dbdata dbschema

	// Prepare and execute query
	stmt1, err := db.Prepare("SELECT password,homedir,sysuid,sysgid,quota,uid,gid,oath_token,alias_of FROM passwd WHERE username = ? AND ? != '' limit 1")
	if err != nil {
		fmt.Println("Prepare SELECT FROM passwd failed: "+err.Error())
	}
	rows1, err := stmt1.Query(reqdata.Username, reqdata.Service)
	if err != nil {
		fmt.Println("Executing SELECT FROM passwd failed: "+err.Error())
	}
	defer stmt1.Close()

	// Read query results
	for rows1.Next() {
		err := rows1.Scan(&dbdata.password,
				  &dbdata.homedir,
				  &dbdata.sysuid,
				  &dbdata.sysgid,
				  &dbdata.quota,
				  &dbdata.uid,
				  &dbdata.gid,
				  &dbdata.oathtoken,
			          &dbdata.aliasof)
		if err != nil {
			fmt.Println("Scaning SELECT FROM passwd result failed: "+err.Error())
		}
	}
	rows1.Close()

	if (reqdata.Password == dbdata.password) { authok = true }
	// CRAM-MD5
	if (reqdata.Password == hmac_md5_hex(reqdata.Timestamp, dbdata.password)) { authok = true }
	// APOP
	if (reqdata.Password == md5_hex(reqdata.Timestamp, dbdata.password)) { authok = true }
	// OTP
	if (otp_verify(dbdata.oathtoken, reqdata.Password)) { authok = true }

	if authok {
		// Write to log
		fmt.Fprintf(os.Stderr, "Authentication succeeded for %s on %s from %s\n", reqdata.Username, reqdata.Service, reqdata.Source);

		// Support aliasing
		if (dbdata.aliasof != "") {
			stmt2, err := db.Prepare("SELECT password,homedir,sysuid,sysgid,quota,uid,gid,oath_token,alias_of FROM passwd WHERE username = ? limit 1")
			if err != nil {
				fmt.Println("Prepare SELECT FROM passwd failed for alias: "+err.Error())
			}
			rows2, err := stmt2.Query(dbdata.aliasof)
			if err != nil {
				fmt.Println("Executing SELECT FROM passwd failed for alias: "+err.Error())
			}
			defer stmt2.Close()

			for rows2.Next() {
				err := rows2.Scan(&dbdata.password,
						  &dbdata.homedir,
						  &dbdata.sysuid,
						  &dbdata.sysgid,
						  &dbdata.quota,
						  &dbdata.uid,
						  &dbdata.gid,
						  &dbdata.oathtoken,
					          &dbdata.aliasof)

				if err != nil {
					fmt.Println("Scaning SELECT FROM passwd result failed for alias: "+err.Error())
				}
			}
			rows2.Close()
		}

		// Send response to checkpassword-client
		w.WriteHeader(http.StatusOK)
		rawin := json.RawMessage(`{"user":"`+reqdata.Username+`",`+
					 `"home":"`+dbdata.homedir+`",`+
					 `"uid":`+strconv.FormatInt(dbdata.sysuid, 10)+`,`+
					 `"gid":`+strconv.FormatInt(dbdata.sysgid, 10)+`,`+
					 `"qboxuid":`+strconv.FormatInt(dbdata.uid, 10)+`,`+
					 `"qboxgid":`+strconv.FormatInt(dbdata.gid, 10)+`}`)
		bytes, err := rawin.MarshalJSON()
		if err != nil {
			fmt.Println("Failed to marshal response: "+err.Error())
		}
		fmt.Fprintf(w, string(bytes))

		// Update `lastlogin` table
		if !update_lastlogin(dbdata.uid, reqdata.Username, reqdata.Service) {
			fmt.Println("Failed to update lastlogin table for "+reqdata.Username)
		}
	} else {
		// Write to log
		var logline string
		if dbdata.uid > 0 {
			logline = fmt.Sprintf("Authentication failed for %s on %s from %s [password: %s]\n", reqdata.Username, reqdata.Service, reqdata.Source, reqdata.Password)
		} else {
			logline = fmt.Sprintf("User %s unknown on %s from %s [password: %s]\n", reqdata.Username, reqdata.Service, reqdata.Source, reqdata.Password)
		}
		fmt.Fprint(os.Stderr, logline)

		// Send response to checkpassword-client
		w.WriteHeader(http.StatusForbidden)

		// Record auth failure for later
		authfail[reqdata.Source] = append(authfail[reqdata.Source], authfaildata{epoch: time.Now().Unix(), message: timestamp()+` - `+logline} )

		// If maximum authentication failures are reached, call failscript
		if len(authfail[reqdata.Source]) >= maxfail &&
		   len(failscript) > 0 {
                        // We copy the data to a temporary structure to prevent
                        // a race-condition. If a client is trying rapidly, the
                        // failscript could otherwise be called multiple times
                        var authhistory []authfaildata = authfail[reqdata.Source]
			delete(authfail, reqdata.Source)

			fmt.Println("Calling "+failscript+" for "+reqdata.Source)
			cmd := exec.Command(failscript, reqdata.Source)
			cmdstdin, err := cmd.StdinPipe()
			if err != nil {
				fmt.Println("Failed to connect to stdin: ", err)
			}
			err = cmd.Start()
			if err != nil {
				fmt.Println("Failed to run failscript: ", err)
			}
			//for _, v := range authfail[reqdata.Source] {
			for _, v := range authhistory {
				_, err := cmdstdin.Write([]byte(v.message))
				if err != nil {
					fmt.Println("Failed to write to stdin: ", err)
				}
			}
			cmdstdin.Close()
			err = cmd.Wait()
			if err != nil {
				fmt.Println("Failed to wait for failscript: ", err)
			}
			//delete(authfail, reqdata.Source)
			// ^^ moved to top
		}
	}
}

func fileExists(filename string) bool {
        info, err := os.Stat(filename)
        if os.IsNotExist(err) {
                return false
        }

        return !info.IsDir()
}

func main () {
	// Option parsing
	var listenport int
	opt := getoptions.New()
	opt.IntVar(&listenport, "port", 17520)
	opt.IntVar(&maxfail, "maxfail", 10)
	opt.StringVar(&failscript, "failscript", "")
	_, parseerr := opt.Parse(os.Args[1:])
	if parseerr != nil {
		fmt.Print(opt.Help())
		log.Fatal(parseerr)
	}

	// Check that failscript exists
	if failscript != "" {
		if _, err := os.Stat(failscript); os.IsNotExist(err) {
			log.Fatal(err)
		}
	}

	// Running as root is discouraged
	if (syscall.Getuid() == 0) {
		fmt.Println("Running as root is not supported!")
		os.Exit(2)
	}

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

	var err error
        db, err = sql.Open("mysql", dbuser+":"+dbpass+"@tcp("+dbserver+")/qbox")
	if err == nil {
		err = db.Ping()
		if err != nil {
			log.Fatal(err)
			os.Exit(1)
		}
		defer db.Close()
	}

	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/", authenticate).Methods("POST")
        router.HandleFunc("/{service}/{username}/{password}/{timestamp}/{source}", authenticate).Methods("GET")
	log.Fatal(http.ListenAndServe("127.0.0.1:"+strconv.FormatInt(int64(listenport), 10), router))
}

func hmac_md5_hex(salt string, password string) string {
	hash := hmac.New(md5.New, []byte(password))
	_, err := io.WriteString(hash, salt)
	if err != nil {
		fmt.Println("Failed to write to hash function: ", err)
	}

	return fmt.Sprintf("%x", hash.Sum(nil))
}

func md5_hex(timestamp string, password string) string {
	hash :=	md5.New()
	_, err := io.WriteString(hash, timestamp + password)
	if err != nil {
		fmt.Println("Failed to write to hash function: ", err)
	}

	return fmt.Sprintf("%x", hash.Sum(nil))
}

// Unix authentication is not supported so the below is dead code
//func unix_md5_crypt(salt string, password string) string {
//        crypt := crypt.MD5.New()
//        ret, _ := crypt.Generate([]byte(password), []byte(salt))
//
//        return ret
//}

func otp_verify(token string, password string) bool {
	totp := otp.TOTP{Secret: token, IsBase32Secret: true, WindowBack: 20, WindowForward: 20}
	return totp.Verify(password)
}

func update_lastlogin(uid int64, username string, service string) bool {
	stmt, err := db.Prepare("INSERT INTO lastlogin VALUES (?, ?, UNIX_TIMESTAMP(NOW()), TIMESTAMP(NOW()), ?) ON DUPLICATE KEY UPDATE epoch=UNIX_TIMESTAMP(NOW()), timestamp=TIMESTAMP(NOW()), protocol=?")
	if err != nil {
		fmt.Println(err)
		return false
	}
	defer stmt.Close()

	_, err = stmt.Exec(strconv.FormatInt(uid, 10), username, service, service)
	if err != nil {
		fmt.Println(err)
		return false
	} else {
		return true
	}
}

func timestamp() string {
	const timelayout = "2006-01-02 15:04:05"
	return time.Unix(time.Now().Unix(), 0).Format(timelayout)
}
