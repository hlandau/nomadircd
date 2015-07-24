package portscan

import "net"
import "fmt"
import "time"
import "strconv"

var ErrClosed = fmt.Errorf("port is closed")

func Scan(ip net.IP, port uint16, timeout time.Duration) error {
	d := net.Dialer{
		Timeout: timeout,
	}

	conn, err := d.Dial("tcp", net.JoinHostPort(ip.String(), strconv.FormatUint(uint64(port), 10)))
	if err != nil {
		return err
	}

	defer conn.Close()
	return nil
}
