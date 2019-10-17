package main

//import "encoding/json"
//import "fmt"
import "io/ioutil"
import "log"
import "net/http"
import "github.com/davecgh/go-spew/spew"
import "github.com/gorilla/mux"

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

func authenticate(w http.ResponseWriter, r *http.Request) {
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
	}
}

func main () {
	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/", authenticate).Methods("POST")
        router.HandleFunc("/{service}/{username}/{password}/{timestamp}/{source}", authenticate).Methods("GET")
	log.Fatal(http.ListenAndServe("127.0.0.1:7520", router))
}
