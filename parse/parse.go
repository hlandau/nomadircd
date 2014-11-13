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

func (m *IRCMessage) Serialize() string {
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
	PS_DRIFTING parseState = iota
	PS_FROMSTART
	PS_FROMCONT
	PS_FROMSERVERNPSTART
	PS_FROMSERVERNPCONT
	PS_FROMUSERUSTART
	PS_FROMUSERUCONT
	PS_FROMUSERHSTART
	PS_FROMUSERHCONT
	PS_FROMUSERHNPSTART
	PS_FROMUSERHNPCONT
	PS_FROMUSERHIPV6
	PS_COMMANDSTART
	PS_COMMANDCONT
	PS_COMMANDNCONT
	PS_COMMANDNCONT2
	PS_PREARGSTART
	PS_ARGSTART
	PS_ARGCONT
	PS_TARGCONT
	PS_EXPECTLF
	PS_END
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
			p.state = PS_DRIFTING
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
	case PS_DRIFTING:
		if c == ':' {
			p.state = PS_FROMSTART
		} else {
			// PS_COMMANDSTART
			p.state = PS_COMMANDSTART
			return p.pdispatch(c) // reissue
		}

	case PS_FROMSTART:
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '_' || c == '-' {
			p.s += string(c)
			p.state = PS_FROMCONT
		} else {
			return errMalformedMessage
		}

	case PS_FROMCONT:
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '_' || c == '-' {
			p.s += string(c)
		} else if c == '.' {
			p.s += string(c)
			p.state = PS_FROMSERVERNPSTART
		} else if c == '!' {
			p.m.NickName = p.s
			p.state = PS_FROMUSERUSTART
			p.s = ""
		} else if c == ' ' {
			p.m.ServerName = p.s
			p.state = PS_COMMANDSTART
			p.s = ""
		} else {
			return errMalformedMessage
		}

	case PS_FROMSERVERNPSTART:
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '_' || c == '-' {
			p.s += string(c)
			p.state = PS_FROMSERVERNPCONT
		} else if c == ' ' {
			// server name with trailing .
			p.m.ServerName = p.s[0 : len(p.s)-1]
			p.state = PS_COMMANDSTART
			p.s = ""
		} else {
			return errMalformedMessage
		}

	case PS_FROMSERVERNPCONT:
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '_' || c == '-' {
			p.s += string(c)
		} else if c == '.' {
			p.s += string(c)
			p.state = PS_FROMSERVERNPSTART
		} else if c == ' ' {
			p.m.ServerName = p.s
			p.state = PS_COMMANDSTART
			p.s = ""
		} else {
			return errMalformedMessage
		}

	case PS_FROMUSERUSTART:
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '_' || c == '-' || c == '~' {
			p.s += string(c)
		} else if c == '@' {
			p.m.UserName = p.s
			p.state = PS_FROMUSERHSTART
			p.s = ""
		} else {
			return errMalformedMessage
		}

	case PS_FROMUSERUCONT:
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '_' || c == '-' || c == '~' {
			p.s += string(c)
		} else if c == '@' {
			p.m.UserName = p.s
			p.state = PS_FROMUSERHSTART
			p.s = ""
		} else {
			return errMalformedMessage
		}

	case PS_FROMUSERHSTART:
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '_' || c == '-' {
			p.s += string(c)
			p.state = PS_FROMUSERHCONT
		} else if c == ' ' {
			p.state = PS_COMMANDSTART
			p.m.HostName = p.s
			p.s = ""
		} else {
			return errMalformedMessage
		}

	case PS_FROMUSERHCONT:
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '_' || c == '-' {
			p.s += string(c)
		} else if c == '.' {
			p.s += string(c)
			p.state = PS_FROMUSERHNPSTART
		} else if c == ' ' {
			p.state = PS_COMMANDSTART
			p.m.HostName = p.s
			p.s = ""
		} else if c == ':' {
			p.s += string(c)
			p.state = PS_FROMUSERHIPV6
		} else {
			return errMalformedMessage
		}

	case PS_FROMUSERHNPSTART:
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '_' || c == '-' {
			p.s += string(c)
			p.state = PS_FROMUSERHNPCONT
		} else if c == ' ' {
			p.state = PS_COMMANDSTART
			p.m.HostName = p.s
			p.s = ""
		} else {
			return errMalformedMessage
		}

	case PS_FROMUSERHNPCONT:
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '_' || c == '-' {
			p.s += string(c)
		} else if c == '.' {
			p.s += string(c)
			p.state = PS_FROMUSERHNPSTART
		} else if c == ' ' {
			p.state = PS_COMMANDSTART
			p.m.HostName = p.s
			p.s = ""
		} else {
			return errMalformedMessage
		}

	case PS_FROMUSERHIPV6:
		if (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || (c >= '0' && c <= '9') ||
			c == ':' {
			p.s += string(c)
		} else if c == ' ' {
			p.state = PS_COMMANDSTART
			p.m.HostName = p.s
			p.s = ""
		} else {
			return errMalformedMessage
		}

	case PS_COMMANDSTART:
		if c >= '0' && c <= '9' {
			p.s += string(c)
			p.state = PS_COMMANDNCONT
		} else if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			p.s += string(c)
			p.state = PS_COMMANDCONT
		} else {
			return errMalformedMessage
		}

	case PS_COMMANDCONT:
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			p.s += string(c)
		} else if c == ' ' {
			p.m.Command = p.s
			p.state = PS_ARGSTART
			p.s = ""
		} else if c == '\r' {
			p.m.Command = p.s
			p.state = PS_EXPECTLF
			p.s = ""
		} else {
			return errMalformedMessage
		}

	case PS_COMMANDNCONT:
		if c >= '0' && c <= '9' {
			p.s += string(c)
			p.state = PS_COMMANDNCONT2
		} else {
			return errMalformedMessage
		}

	case PS_COMMANDNCONT2:
		if c >= '0' && c <= '9' {
			p.s += string(c)
			p.state = PS_PREARGSTART
			p.m.Command = p.s
			p.s = ""
		} else {
			return errMalformedMessage
		}

	case PS_PREARGSTART:
		if c == ' ' {
			p.state = PS_ARGSTART
		} else if c == '\r' {
			p.state = PS_EXPECTLF
		} else {
			return errMalformedMessage
		}

	case PS_ARGSTART:
		if c == ':' {
			p.state = PS_TARGCONT
		} else if c == '\r' || c == '\n' || c == '\x00' || c == ' ' {
			return errMalformedMessage
		} else {
			p.s += string(c)
			p.state = PS_ARGCONT
		}

	case PS_ARGCONT:
		if c == ' ' || c == '\r' {
			p.m.Args = append(p.m.Args, p.s)
			p.s = ""
			if c == '\r' {
				p.state = PS_EXPECTLF
			} else {
				p.state = PS_ARGSTART
			}
		} else if c == '\n' || c == '\x00' {
			return errMalformedMessage
		} else {
			p.s += string(c)
		}

	case PS_TARGCONT:
		if c == '\r' {
			p.m.Args = append(p.m.Args, p.s)
			p.s = ""
			p.state = PS_EXPECTLF
		} else if c == '\n' || c == '\x00' {
			return errMalformedMessage
		} else {
			p.s += string(c)
		}

	case PS_EXPECTLF:
		if c != '\n' {
			return errMalformedMessage
		} else {
			p.state = PS_DRIFTING
			p.msgs = append(p.msgs, p.m)
			p.m = &IRCMessage{}
		}
	}

	return nil
}

// © 2014 Hugo Landau <hlandau@devever.net>    GPLv3 or later
