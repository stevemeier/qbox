package main

import "bufio"
import "fmt"
import "net"
import "os"
import "regexp"
import "strings"

// IPs and their AS numbers for code verification
// 1.1.1.1 from 13335
// 4.2.2.4 from 3356
// 8.8.8.8 from 15169
// 9.9.9.9 from 19281
// 17.1.1.1 from 714
// 26.1.1.1 from 4294967295 (!)
// 38.1.1.1 from 174
// 44.1.1.1 from 7377
// 45.238.58.58 from {27947,264668,266834} (!)
// 51.163.160.1 from {203101} (!)
// 53.1.1.1 from 31399
// 214.1.1.1 from UNANNOUNCED (!) [results in nxdomain]

func main() {

	if env_defined("RELAYCLIENT") ||
		env_defined("TRUSTCLIENT") ||
		!env_defined("TCPREMOTEIP") {
		fmt.Println()
		os.Exit(0)
	}

	if !file_exists("/var/qmail/control/asndeny") ||
		!file_exists("/var/qmail/control/asntrust") {
		fmt.Println()
		os.Exit(0)
	}

	if is_private_ip(net.ParseIP(os.Getenv("TCPREMOTEIP"))) ||
		is_ipv6(os.Getenv("TCPREMOTEIP")) {
		fmt.Println()
		os.Exit(0)
	}

	asnumber := ip_to_asn(os.Getenv("TCPREMOTEIP"))
	// fmt.Println("AS number is " + asnumber)

	if grep_file(asnumber, "/var/qmail/control/asndeny") {
		// AS is denied
		fmt.Fprintf(os.Stderr, "%d Client %s (AS %s) is blocked due to listing in asndeny\n", os.Getppid(), os.Getenv("TCPREMOTEIP"), asnumber)
		fmt.Println("E541 Your AS is blocked from delivering mail to this system\n")
		os.Exit(0)
	}

	if grep_file(asnumber, "/var/qmail/control/asntrust") {
		// AS is trusted
		fmt.Fprintf(os.Stderr, "%d Client %s (AS %s) is trusted due to listing in asntrust\n", os.Getppid(), os.Getenv("TCPREMOTEIP"), asnumber)
		fmt.Println("O")
		os.Exit(0)
	}

	// Clean Exit
	fmt.Println()
	os.Exit(0)

}

func env_defined(key string) bool {
	value, exists := os.LookupEnv(key)
	_ = value

	return exists
}

func file_exists(filename string) bool {
	_, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}

	return true
}

func is_private_ip(ip net.IP) bool {
	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
	} {
		_, block, _ := net.ParseCIDR(cidr)
		if block.Contains(ip) {
			return true
		}
	}

	return false
}

func is_ipv6(address string) bool {
	if strings.Count(address, ":") >= 2 {
		return true
	} else {
		return false
	}
}

func reverse_ip(ip net.IP) string {
	if ip.To4() != nil {
		addressSlice := strings.Split(ip.String(), ".")
		reverseSlice := []string{}

		for i := range addressSlice {
			octet := addressSlice[len(addressSlice)-1-i]
			reverseSlice = append(reverseSlice, octet)
		}

		return strings.Join(reverseSlice, ".")
	}

	return ""
}

func grep_file(regex string, file string) bool {
	if !file_exists(file) {
		return false
	}

	filehandle, err := os.Open(file)
	if err != nil {
		return false
	}

	scanner := bufio.NewScanner(filehandle)
	for scanner.Scan() {
		match, _ := regexp.MatchString(`^`+regex, scanner.Text())
		if match {
			return true
		}
	}
	return false
}

func ip_to_asn(ipaddr string) string {
	qname := reverse_ip(net.ParseIP(ipaddr)) + ".asn.routeviews.org"

	asninfo, err := net.LookupTXT(qname)
	if err != nil ||
		len(asninfo) != 1 {
		// Lookup has failed (e.g. NXDOMAIN)
		return "-1"
	}

	// LookupTXT is stupid.
	// It returns one concatenated string instead of an array (like Perl does)
	// So we need to do some regexp matching to extract the ASN numer

	re1 := regexp.MustCompile(`^(\d+)`)
	firstoctet := re1.FindString(os.Getenv("TCPREMOTEIP"))

	re2 := regexp.MustCompile(firstoctet + `$`)

	for _, txt := range asninfo {
		asnumber := re1.FindString(txt)
		asnumber = re2.ReplaceAllString(asnumber, "")

		if len(asnumber) > 0 {
			return asnumber
		} else {
			return "-1"
		}
	}

	return "-1"
}
