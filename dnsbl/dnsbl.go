package dnsbl

import "sync"
import "time"
import "net"
import "fmt"

type cacheItem struct {
	ip net.IP
	t  time.Time
}

type DNSBL struct {
	domain string
	cache  map[string]cacheItem
	mutex  sync.Mutex
}

func New(domain string) *DNSBL {
	d := &DNSBL{
		domain: domain,
		cache:  map[string]cacheItem{},
	}
	go d.expireLoop()
	return d
}

func (d *DNSBL) expireLoop() {
	for {
		time.Sleep(time.Duration(30) * time.Minute)

		d.mutex.Lock()
		d.mutex.Unlock()

		for k, v := range d.cache {
			if v.t.Add(time.Duration(8) * time.Hour).Before(time.Now()) {
				delete(d.cache, k)
			}
		}
	}
}

func (d *DNSBL) query(ip net.IP) (r net.IP, err error) {
	ip4 := ip.To4()
	if ip4 == nil {
		return d.queryv6(ip)
	}

	ds := fmt.Sprintf("%v.%v.%v.%v.%s", ip4[3], ip4[2], ip4[1], ip4[0], d.domain)

	addrs, err := net.LookupIP(ds)
	if err != nil {
		return
	}

	if len(addrs) == 0 {
		r = nil
		return
	}

	if len(addrs) != 1 {
		err = fmt.Errorf("several DNSBL replies received, ignoring all of them")
		return
	}

	r = addrs[0].To4()
	return
}

func (d *DNSBL) queryv6(ip net.IP) (r net.IP, err error) {
	return nil, fmt.Errorf("IPv6 not yet supported")
}

func (d *DNSBL) Check(ip net.IP) (r net.IP, err error) {
	if !ip.IsGlobalUnicast() {
		// Don't even bother looking up 127.0.0.0/8, RFC1918, etc.
		// Don't put this check in query() as we needn't pollute the cache.
		return
	}

	ip_s := ip.String()

	d.mutex.Lock()
	defer d.mutex.Unlock()

	cr, ok := d.cache[ip_s]
	if ok {
		r = cr.ip
		return
	}

	r, err = d.query(ip)
	if err != nil {
		return
	}

	d.cache[ip_s] = cacheItem{r, time.Now()}
	return
}
