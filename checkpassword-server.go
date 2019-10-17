package main

import "encoding/json"
import "fmt"
import "io/ioutil"
import "log"
import "net/http"
import "os"
import "github.com/davecgh/go-spew/spew"
import "github.com/gorilla/mux"
// DB
import "database/sql"
import _ "github.com/go-sql-driver/mysql"

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
	timestamp	int64
	service		string
	source		string
}

var db *sql.DB

func authenticate(w http.ResponseWriter, r *http.Request) {
	var reqdata clientreqdata

	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if len(reqBody) == 0 {
		// GET
	} else {
		// POST
		spew.Dump(reqBody)
		err := json.Unmarshal(reqBody, &reqdata)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
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
	const configdir = "/etc/qbox"
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
        db, err := sql.Open("mysql", dbuser+":"+dbpass+"@tcp("+dbserver+")/qbox")
	_ = db
	if err == nil {
		err = db.Ping()
		if err != nil {
			log.Fatal(err)
			os.Exit(1)
		}
		fmt.Println("DB connection established")
	}

	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/", authenticate).Methods("POST")
        router.HandleFunc("/{service}/{username}/{password}/{timestamp}/{source}", authenticate).Methods("GET")
	log.Fatal(http.ListenAndServe("127.0.0.1:17520", router))
}
