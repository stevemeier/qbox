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
import "strconv"
import "syscall"
import "github.com/davecgh/go-spew/spew"
import "github.com/gorilla/mux"
// DB
import "database/sql"
import _ "github.com/go-sql-driver/mysql"
// Crypt
import "github.com/GehirnInc/crypt"
// OTP
import "github.com/hgfischer/go-otp"
// Getopt
import "github.com/DavidGamba/go-getoptions"

const configdir = "/etc/qbox"

type authcachedata struct {
	uid	int64
	gid	int64
	user	string
	home	string
	qboxuid	int64
	qboxgid	int64
}

type authcachemeta struct {
	epoch	int64
	data	authcachedata
}

var authcache map[string]authcachemeta

type clientreqdata struct {
	username	string
	password	string
//	timestamp	int64
	timestamp	string
	service		string
	source		string
}

var db *sql.DB

func authenticate(w http.ResponseWriter, r *http.Request) {
	var services = [...]string {"smtp","smtps","pop3","pop3s","imap","imaps"}

	var authok bool = false
	var reqdata clientreqdata

	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if len(reqBody) == 0 {
		// GET
		fmt.Println("Copying mux vars")
		reqdata.username  = mux.Vars(r)["username"]
		reqdata.password  = mux.Vars(r)["password"]
		reqdata.service   = mux.Vars(r)["service"]
		reqdata.source    = mux.Vars(r)["source"]
//		fmt.Println("Parsing timestamp parameter")
//		reqdata.timestamp, err = strconv.ParseInt(mux.Vars(r)["timestamp"], 10, 64)
		reqdata.timestamp = mux.Vars(r)["timestamp"]
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	} else {
		// POST
		spew.Dump(reqBody)
		err := json.Unmarshal(reqBody, &reqdata)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	}

	// Check if serice is supported
	var servicesupported bool = false
	for _, v := range(services) {
		if v == reqdata.service { servicesupported = true }
	}
	if !servicesupported {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// `root` is always denied
	fmt.Println("Checking if root")
	if (reqdata.username == "root") {
		fmt.Fprintf(os.Stderr, "User root denied on %s from %s\n", reqdata.service, reqdata.source)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// Check that DB is still there
	fmt.Println("Checking DB")
	err = db.Ping()
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
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
	}
	var dbdata dbschema

	// Prepare and execute query
	stmt1, err := db.Prepare("SELECT password,homedir,sysuid,sysgid,quota,uid,gid,oath_token FROM passwd WHERE username = ? AND ? != '' limit 1")
	rows1, err := stmt1.Query(reqdata.username, reqdata.service)
	if err != nil {
		log.Fatal(err)
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
				  &dbdata.oathtoken)
		if err != nil {
			log.Fatal(err)
		}
	}

	spew.Dump(reqdata)
	spew.Dump(dbdata)

	if (reqdata.password == dbdata.password) { authok = true }
	// CRAM-MD5
	if (reqdata.password == hmac_md5_hex(reqdata.timestamp, dbdata.password)) { authok = true }
	// APOP
	if (reqdata.password == md5_hex(reqdata.timestamp, dbdata.password)) { authok = true }
	// OTP
	if (otp_verify(dbdata.oathtoken, reqdata.password)) { authok = true }

	if authok {
		fmt.Fprintf(os.Stderr, "Authentication succeeded for %s on %s from %s\n", reqdata.username, reqdata.service, reqdata.source);
		w.WriteHeader(http.StatusOK)
		rawin := json.RawMessage(`{"user":"`+reqdata.username+`",`+
					 `"home":"`+dbdata.homedir+`",`+
					 `"uid":`+strconv.FormatInt(dbdata.sysuid, 10)+`,`+
					 `"gid":`+strconv.FormatInt(dbdata.sysgid, 10)+`,`+
					 `"qboxuid":`+strconv.FormatInt(dbdata.uid, 10)+`,`+
					 `"qboxgid":`+strconv.FormatInt(dbdata.gid, 10)+`}`)
		bytes, err := rawin.MarshalJSON()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Fprintf(w, string(bytes))
		if !update_lastlogin(dbdata.uid, reqdata.username, reqdata.service) {
			fmt.Println("Failed to update lastlogin table for "+reqdata.username)
		}
	} else {
		fmt.Fprintf(os.Stderr, "Authentication failed for %s on %s from %s [password: %s]\n", reqdata.username, reqdata.service, reqdata.source, reqdata.password)
		w.WriteHeader(http.StatusForbidden)

	}
	fmt.Println("Reached end of authenticate function")
	return
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
	_, parseerr := opt.Parse(os.Args[1:])
	if parseerr != nil {
		fmt.Print(opt.Help())
		log.Fatal(parseerr)
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
		fmt.Println("DB connection established")
		defer db.Close()
	}

	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/", authenticate).Methods("POST")
        router.HandleFunc("/{service}/{username}/{password}/{timestamp}/{source}", authenticate).Methods("GET")
	log.Fatal(http.ListenAndServe("127.0.0.1:"+strconv.FormatInt(int64(listenport), 10), router))
}

func hmac_md5_hex(salt string, password string) string {
	hash := hmac.New(md5.New, []byte(password))
	io.WriteString(hash, salt)

	return fmt.Sprintf("%x", hash.Sum(nil))
}

func md5_hex(timestamp string, password string) string {
	hash :=	md5.New()
	io.WriteString(hash, timestamp + password)

	return fmt.Sprintf("%x", hash.Sum(nil))
}

func unix_md5_crypt(salt string, password string) string {
        crypt := crypt.MD5.New()
        ret, _ := crypt.Generate([]byte(password), []byte(salt))

        return ret
}

func otp_verify(token string, password string) bool {
	totp := otp.TOTP{Secret: token, IsBase32Secret: false, WindowBack: 20, WindowForward: 20}
	return totp.Verify(password)
}

func update_lastlogin(uid int64, username string, service string) bool {
	stmt, _ := db.Prepare("INSERT INTO lastlogin VALUES (?, ?, UNIX_TIMESTAMP(NOW()), TIMESTAMP(NOW()), ?) ON DUPLICATE KEY UPDATE epoch=UNIX_TIMESTAMP(NOW()), timestamp=TIMESTAMP(NOW()), protocol=?")
	_, err := stmt.Exec(strconv.FormatInt(uid, 10), username, service, service)
	if err != nil {
		fmt.Println(err)
		return false
	} else {
		return true
	}
}
