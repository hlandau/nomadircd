package ident

import "net"
import "fmt"
import "io"
import "bufio"
import "strings"
import "time"
import "regexp"

var re_validUserName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_-]{0,31}$`)

// Look up the ident for the TCP connection which underlies subjectConn. The
// connection must be a TCP connection. Returns the identified username or an
// error.
func Lookup(subjectConn net.Conn, timeout time.Duration) (string, error) {
	ra, ok := subjectConn.RemoteAddr().(*net.TCPAddr)
	la, ok2 := subjectConn.LocalAddr().(*net.TCPAddr)
	if !ok || !ok2 {
		return "", fmt.Errorf("subjectConn must be a TCP connection")
	}

	if timeout == time.Duration(0) {
		timeout = 5 * time.Second
	}

	d := net.Dialer{
		Timeout:   timeout,
		LocalAddr: &net.TCPAddr{la.IP, 0, la.Zone},
	}

	identConn, err := d.Dial("tcp", net.JoinHostPort(ra.IP.String(), "113"))
	if err != nil {
		return "", err
	}

	defer identConn.Close()
	identConn.SetDeadline(time.Now().Add(timeout))

	s := fmt.Sprintf("%d, %d\r\n", ra.Port, la.Port)
	_, err = identConn.Write([]byte(s))
	if err != nil {
		return "", err
	}

	r := bufio.NewReader(identConn)
	L, err := r.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}

	L = strings.Trim(L, " \r\n")
	La := strings.Split(L, ":")
	if len(La) < 4 {
		return "", fmt.Errorf("Malformed response from ident server: %s", L)
	}

	cmdName := strings.Trim(La[1], " ")

	switch cmdName {
	case "USERID":
		username := strings.Trim(La[3], " ")

		if !re_validUserName.MatchString(username) {
			return "", fmt.Errorf("Got malformed username from ident server: %s", username)
		}

		return username, nil

	default:
		return "", fmt.Errorf("Got error or unknown response from ident server: %s", cmdName)
	}
}
