package rdns

import "net"
import "fmt"
import "regexp"

var re_validHostName = regexp.MustCompile(`^([a-zA-Z0-9][a-zA-Z0-9-]*\.)*[a-zA-Z0-9][a-zA-Z0-9-]*\.?$`)

var ErrForwardMismatch = fmt.Errorf("address from forward RDNS lookup doesn't match actual address")

func Lookup(ip net.IP) (string, error) {
	ips := ip.String()

	names, err := net.LookupAddr(ips)
	if err != nil {
		return "", err
	}

	if len(names) == 0 {
		return "", fmt.Errorf("no RDNS name found")
	}

	if len(names) != 1 {
		return "", fmt.Errorf("got multiple RDNS names (%#v), not using any of them", names)
	}

	n := names[0]
	if !re_validHostName.MatchString(n) {
		return "", fmt.Errorf("invalid hostname received from RDNS")
	}

	addrs, err := net.LookupHost(n)
	if err != nil {
		return n, err
	}

	if len(addrs) == 0 {
		return n, fmt.Errorf("no results for forward lookup on received RDNS name")
	}

	if len(addrs) != 1 {
		// XXX
		return n, fmt.Errorf("got multiple results for forward lookup on received RDNS name")
	}

	a := addrs[0]
	if a != ips {
		return n, ErrForwardMismatch
	}

	return n, nil
}

func LookupRemote(conn net.Conn) (string, error) {
	ra, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return "", fmt.Errorf("not a TCP connection")
	}

	return Lookup(ra.IP)
}
