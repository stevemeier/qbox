package main

import "bufio"
import "io"
import "io/ioutil"
import "fmt"
import "os"
import "regexp"
//import "strings"
import "strconv"
import "time"
import "crypto/sha1"

import "github.com/davecgh/go-spew/spew"
import "golang.org/x/sys/unix"

const configdir = "/etc/qbox"

type email struct {
	Length		int
	Recipient	string
	Sha1		string
	Text		string
}

func main() {
	// Default exit code is 111
	var exitcode int = 111

	var message email
	var err error
	message.Text, err = read_from_stdin()
	if err != nil {
		os.Exit(1)
	}

	message.Length = len(message.Text)
	message.Recipient = os.Getenv("RECIPIENT")
	message.Sha1 = sha1sum(message.Text)

	if (len(message.Recipient) == 0) {
		fmt.Println("RECIPIENT not set!")
		os.Exit(1)
	}

	spew.Dump(message)
	hostname, _ := os.Hostname()
	writesuccess := write_to_file(message, `/tmp/`+epoch()+`.`+strconv.Itoa(os.Getpid())+`.`+hostname+`.`+message.Sha1)
	if (writesuccess) {
		exitcode = 0
	}
	spew.Dump(writesuccess)
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

func epoch () (string) {
	now := time.Now()
	// Using UnixNano instead of just Unix gives us greater entropy in the filename
	return strconv.FormatInt(now.UnixNano(), 10)
}

func write_to_file (message email, filename string) (bool) {
	unix.Umask(077)

	// Never overwrite existing files
	if fileExists(filename) {
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

func fileExists(filename string) bool {
        info, err := os.Stat(filename)
        if os.IsNotExist(err) {
                return false
        }

        return !info.IsDir()
}
