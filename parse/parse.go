package parse

import "fmt"

//import "github.com/hlandau/degoutils/log"

type IRCMessage struct {
	// :server.name
	ServerName string

	// :nick!user@host
	NickName string
	UserName string
	HostName string

	// Command name (uppercase) or numeric
	Command string

	// All arguments including trailing argument.
	// Note that the trailing argument is not in any way
	// semantically distinct from the other arguments.
	Args []string
}

func (m *IRCMessage) IsFromServer() bool {
	return m.ServerName != ""
}

func (m *IRCMessage) IsFromClient() bool {
	return m.NickName != ""
}

func (m *IRCMessage) String() string {
	s := ""
	if m.ServerName != "" {
		s += ":"
		s += m.ServerName
		s += " "
	} else if m.NickName != "" {
		s += ":"
		s += m.NickName
		s += "!"
		s += m.UserName
		s += "@"
		s += m.HostName
		s += " "
	}

	s += m.Command

	if len(m.Args) > 0 {
		a := m.Args[0 : len(m.Args)-1]
		for _, v := range a {
			s += " "
			s += v
		}

		ta := m.Args[len(m.Args)-1]
		s += " :"
		s += ta
	}

	s += "\r\n"
	return s
}

type parseState int

const (
	psDRIFTING parseState = iota
	psFROMSTART
	psFROMCONT
	psFROMSERVERNPSTART
	psFROMSERVERNPCONT
	psFROMUSERUSTART
	psFROMUSERUCONT
	psFROMUSERHSTART
	psFROMUSERHCONT
	psFROMUSERHNPSTART
	psFROMUSERHNPCONT
	psFROMUSERHIPV6
	psCOMMANDSTART
	psCOMMANDCONT
	psCOMMANDNCONT
	psCOMMANDNCONT2
	psPREARGSTART
	psARGSTART
	psARGCONT
	psTARGCONT
	psEXPECTLF
	psEND
)

type IRCParser struct {
	state parseState
	s     string
	msgs  []*IRCMessage
	m     *IRCMessage

	// The number of malformed messages that have been received.
	MalformedMessageCount int
}

var errMalformedMessage = fmt.Errorf("Malformed IRC protocol message")

// Retrirves an array of parsed messages. The internal slice of such mssages
// is then cleared, so subsequent calls to GetMessages() will return an empty slice.
func (p *IRCParser) GetMessages() []*IRCMessage {
	k := p.msgs
	p.msgs = p.msgs[0:0]
	return k
}

// Parse arbitrary IRC protocol input. This does not need to be line-aligned.
//
// Complete messages are placed in an internal slice and can be retrieved
// by calling GetMessages().
//
// Malformed messages are skipped until their terminating newline, and parsing
// continues from there. The MalformedMessageCount is incremented.
func (p *IRCParser) Parse(s string) (err error) {
	if p.m == nil {
		p.m = &IRCMessage{}
	}

	recovery := false
	for _, c := range s {
		if recovery {
			if c == '\n' {
				recovery = false
			}
			continue
		}

		err = p.pdispatch(c)
		if err != nil {
			// error recovery: start ignoring until the end of the line
			p.state = psDRIFTING
			p.s = ""
			p.m = &IRCMessage{}
			recovery = true
			p.MalformedMessageCount++
		}
	}

	return nil
}

func (p *IRCParser) pdispatch(c rune) error {
	//log.Info(fmt.Sprintf("state %+v", p.state))
	switch p.state {
	case psDRIFTING:
		if c == ':' {
			p.state = psFROMSTART
		} else {
			// psCOMMANDSTART
			p.state = psCOMMANDSTART
			return p.pdispatch(c) // reissue
		}

	case psFROMSTART:
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '_' || c == '-' {
			p.s += string(c)
			p.state = psFROMCONT
		} else {
			return errMalformedMessage
		}

	case psFROMCONT:
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '_' || c == '-' {
			p.s += string(c)
		} else if c == '.' {
			p.s += string(c)
			p.state = psFROMSERVERNPSTART
		} else if c == '!' {
			p.m.NickName = p.s
			p.state = psFROMUSERUSTART
			p.s = ""
		} else if c == ' ' {
			p.m.ServerName = p.s
			p.state = psCOMMANDSTART
			p.s = ""
		} else {
			return errMalformedMessage
		}

	case psFROMSERVERNPSTART:
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '_' || c == '-' {
			p.s += string(c)
			p.state = psFROMSERVERNPCONT
		} else if c == ' ' {
			// server name with trailing .
			p.m.ServerName = p.s[0 : len(p.s)-1]
			p.state = psCOMMANDSTART
			p.s = ""
		} else {
			return errMalformedMessage
		}

	case psFROMSERVERNPCONT:
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '_' || c == '-' {
			p.s += string(c)
		} else if c == '.' {
			p.s += string(c)
			p.state = psFROMSERVERNPSTART
		} else if c == ' ' {
			p.m.ServerName = p.s
			p.state = psCOMMANDSTART
			p.s = ""
		} else {
			return errMalformedMessage
		}

	case psFROMUSERUSTART:
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '_' || c == '-' || c == '~' {
			p.s += string(c)
		} else if c == '@' {
			p.m.UserName = p.s
			p.state = psFROMUSERHSTART
			p.s = ""
		} else {
			return errMalformedMessage
		}

	case psFROMUSERUCONT:
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '_' || c == '-' || c == '~' {
			p.s += string(c)
		} else if c == '@' {
			p.m.UserName = p.s
			p.state = psFROMUSERHSTART
			p.s = ""
		} else {
			return errMalformedMessage
		}

	case psFROMUSERHSTART:
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '_' || c == '-' {
			p.s += string(c)
			p.state = psFROMUSERHCONT
		} else if c == ' ' {
			p.state = psCOMMANDSTART
			p.m.HostName = p.s
			p.s = ""
		} else {
			return errMalformedMessage
		}

	case psFROMUSERHCONT:
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '_' || c == '-' {
			p.s += string(c)
		} else if c == '.' {
			p.s += string(c)
			p.state = psFROMUSERHNPSTART
		} else if c == ' ' {
			p.state = psCOMMANDSTART
			p.m.HostName = p.s
			p.s = ""
		} else if c == ':' {
			p.s += string(c)
			p.state = psFROMUSERHIPV6
		} else {
			return errMalformedMessage
		}

	case psFROMUSERHNPSTART:
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '_' || c == '-' {
			p.s += string(c)
			p.state = psFROMUSERHNPCONT
		} else if c == ' ' {
			p.state = psCOMMANDSTART
			p.m.HostName = p.s
			p.s = ""
		} else {
			return errMalformedMessage
		}

	case psFROMUSERHNPCONT:
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '_' || c == '-' {
			p.s += string(c)
		} else if c == '.' {
			p.s += string(c)
			p.state = psFROMUSERHNPSTART
		} else if c == ' ' {
			p.state = psCOMMANDSTART
			p.m.HostName = p.s
			p.s = ""
		} else {
			return errMalformedMessage
		}

	case psFROMUSERHIPV6:
		if (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || (c >= '0' && c <= '9') ||
			c == ':' {
			p.s += string(c)
		} else if c == ' ' {
			p.state = psCOMMANDSTART
			p.m.HostName = p.s
			p.s = ""
		} else {
			return errMalformedMessage
		}

	case psCOMMANDSTART:
		if c >= '0' && c <= '9' {
			p.s += string(c)
			p.state = psCOMMANDNCONT
		} else if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			p.s += string(c)
			p.state = psCOMMANDCONT
		} else {
			return errMalformedMessage
		}

	case psCOMMANDCONT:
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			p.s += string(c)
		} else if c == ' ' {
			p.m.Command = p.s
			p.state = psARGSTART
			p.s = ""
		} else if c == '\r' {
			p.m.Command = p.s
			p.state = psEXPECTLF
			p.s = ""
		} else {
			return errMalformedMessage
		}

	case psCOMMANDNCONT:
		if c >= '0' && c <= '9' {
			p.s += string(c)
			p.state = psCOMMANDNCONT2
		} else {
			return errMalformedMessage
		}

	case psCOMMANDNCONT2:
		if c >= '0' && c <= '9' {
			p.s += string(c)
			p.state = psPREARGSTART
			p.m.Command = p.s
			p.s = ""
		} else {
			return errMalformedMessage
		}

	case psPREARGSTART:
		if c == ' ' {
			p.state = psARGSTART
		} else if c == '\r' {
			p.state = psEXPECTLF
		} else {
			return errMalformedMessage
		}

	case psARGSTART:
		if c == ':' {
			p.state = psTARGCONT
		} else if c == '\r' || c == '\n' || c == '\x00' || c == ' ' {
			return errMalformedMessage
		} else {
			p.s += string(c)
			p.state = psARGCONT
		}

	case psARGCONT:
		if c == ' ' || c == '\r' {
			p.m.Args = append(p.m.Args, p.s)
			p.s = ""
			if c == '\r' {
				p.state = psEXPECTLF
			} else {
				p.state = psARGSTART
			}
		} else if c == '\n' || c == '\x00' {
			return errMalformedMessage
		} else {
			p.s += string(c)
		}

	case psTARGCONT:
		if c == '\r' {
			p.m.Args = append(p.m.Args, p.s)
			p.s = ""
			p.state = psEXPECTLF
		} else if c == '\n' || c == '\x00' {
			return errMalformedMessage
		} else {
			p.s += string(c)
		}

	case psEXPECTLF:
		if c != '\n' {
			return errMalformedMessage
		} else {
			p.state = psDRIFTING
			p.msgs = append(p.msgs, p.m)
			p.m = &IRCMessage{}
		}
	}

	return nil
}

// © 2014 Hugo Landau <hlandau@devever.net>    GPLv3 or later
