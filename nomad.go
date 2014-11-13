package main

import "net"
import "github.com/hlandau/degoutils/log"
import "github.com/hlandau/nomadircd/parse"
import "fmt"
import "regexp"
import "strings"
import "container/list"
import "time"
import "code.google.com/p/go.crypto/salsa20"
import "crypto/rand"
import "crypto/tls"
import "encoding/binary"
import "encoding/base64"
import "strconv"
import "bufio"
import "io"
import "sync"

var re_validNickName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_-]{0,31}$`)
var re_validUserName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_-]{0,31}$`)
var re_validRealName = regexp.MustCompile(`^[^\r\n\t]{0,64}$`)
var re_validChannelName = regexp.MustCompile(`^[#&][a-zA-Z0-9_#.<>-]{1,32}$`)
var re_validHostName = regexp.MustCompile(`^([a-zA-Z0-9][a-zA-Z0-9-]*\.)*[a-zA-Z0-9][a-zA-Z0-9-]*\.?$`)

type IRCServer struct {
	Name        string
	Description string

	clientsByNick  map[string]*IRCClient
	channelsByName map[string]*IRCChannel

	unregisteredClients list.List

	pingTokenKey     [32]byte
	pingTokenCounter uint64
	motd             []string

	cloakKey [32]byte
}

func (s *IRCServer) FindClientByNickName(nickName string) *IRCClient {
	if c, ok := s.clientsByNick[canonicalizeNickName(nickName)]; ok {
		return c
	} else {
		return nil
	}
}

func (s *IRCServer) FindChannelByName(channelName string) *IRCChannel {
	if ch, ok := s.channelsByName[canonicalizeChannelName(channelName)]; ok {
		return ch
	} else {
		return nil
	}
}

func (s *IRCServer) FindOrCreateChannelByName(channelName string) *IRCChannel {
	ch := s.FindChannelByName(channelName)
	if ch != nil {
		return ch
	}

	return s.NewChannel(channelName)
}

func (s *IRCServer) NewChannel(channelName string) *IRCChannel {
	ch := &IRCChannel{}
	ch.Name = channelName
	ch.clientsByNick = map[string]*IRCChannelMember{}
	ch.s = s
	ch.mNoExt = true
	ch.mTopicLock = true
	ch.mLimit = -1
	s.channelsByName[canonicalizeChannelName(channelName)] = ch

	return ch
}

type IRCClient struct {
	s      *IRCServer
	conn   net.Conn
	txChan chan string

	NickName          string
	SpecifiedUserName string
	RealName          string
	RealHostName      string // always the real hostname/IP
	VirtualHostName   string
	AccountName       string
	Ident             string

	registered bool

	channels list.List // of *IRCChannelMember

	lastPrivmsg time.Time
	lastMessage time.Time
	lastPing    time.Time
	logonTime   time.Time
	pingToken   string

	isSecure   bool
	isOperator bool

	mInvisible bool
	mCloaked   bool

	isTerminated bool

	// map canonical channel name to dummy byte 0
	invitations map[string]byte

	unregisteredClientElement *list.Element

	sendqMax uint
	sendqCur uint

	numRegChecks       uint
	regCheckFinishChan chan struct{}
	identConn          net.Conn
}

func (c *IRCClient) UserName() string {
	if c.Ident != "" {
		return c.Ident
	} else {
		return "~" + c.SpecifiedUserName
	}
}

func (c *IRCClient) HostName() string {
	if c.VirtualHostName != "" {
		return c.VirtualHostName
	}

	if c.mCloaked {
		return c.encloakHostName(c.RealHostName)
	}

	return c.RealHostName
}

func (c *IRCClient) encloakHostName(realHostName string) string {
	// TODO
	return realHostName
}

func (c *IRCClient) serializeModes(rc *IRCClient) (mspec string, margs []string) {
	mspec = "+"
	if c.mInvisible {
		mspec += "i"
	}
	if c.mCloaked {
		mspec += "x"
	}

	return
}

func (c *IRCClient) pingTime() time.Duration {
	return time.Duration(30) * time.Second
}

func (c *IRCClient) checkPing() {
	if !c.registered {
		if time.Now().Sub(c.logonTime) > c.pingTime() {
			c.terminate("Failed to complete registration")
		}
		return
	}

	// A. T+0: Client sends some non-ping message which updates lastMessage and perhaps lastPrivmsg
	// B. T+pingTime: It has been pingTime without any activity, so a PING is sent
	// C. T+2*pingTime: The PING has not been responded to, the client is disconnected
	//
	// It is an intentional feature of this design that once a PING is sent, it MUST be responded to.
	// Once a PING has been sent, the connection cannot be kept alive simply by sending any message.
	//
	// pingToken is reset to "" after a successful PONG response.
	if c.pingToken != "" && time.Now().Sub(c.lastPing) > c.pingTime() {
		// C. Expiry
		c.terminate("Ping timeout")
		return
	}

	// B. Too long without any messages received, so send a ping
	// PONGs update lastMessage, so we don't need to bother checking lastPing
	if time.Now().Sub(c.lastMessage) > c.pingTime() {
		c.sendPing()
	}
}

func (s *IRCServer) generatePingToken() string {
	token := make([]byte, 6)
	nonce := make([]byte, 8)
	s.pingTokenCounter++
	binary.BigEndian.PutUint64(nonce, s.pingTokenCounter)
	salsa20.XORKeyStream(token, token, nonce, &s.pingTokenKey)
	return base64.StdEncoding.EncodeToString(token)
}

func (c *IRCClient) sendPing() {
	c.lastPing = time.Now()
	c.pingToken = c.s.generatePingToken()
	c.sendCommandBare("PING", c.pingToken)
}

func (c *IRCClient) terminateIdentCheck() {
	if c.identConn != nil {
		c.identConn.Close()
		c.identConn = nil
	}
}

func (c *IRCClient) terminate(reason string) {
	if c.isTerminated {
		return
	}

	log.Info("terminating client")

	cname := canonicalizeNickName(c.NickName)

	for e := c.channels.Front(); e != nil; e = e.Next() {
		m := e.Value.(*IRCChannelMember)
		m.channel.NotifyUserQuit(c, reason)
		m.channel.RemoveUser(c)
	}

	c.sendLinkError(reason)

	c.isTerminated = true
	close(c.txChan)
	c.terminateIdentCheck()

	if cname != "" {
		delete(c.s.clientsByNick, cname)
	}
}

type IRCMask struct {
	NickName string
	UserName string
	HostName string
}

func (m *IRCMask) String() string {
	return m.NickName + "!" + m.UserName + "@" + m.HostName
}

func (m *IRCMask) CheckMatch(c *IRCClient) bool {
	return false
}

type IRCChannel struct {
	Name          string
	Topic         string
	clientsByNick map[string]*IRCChannelMember
	s             *IRCServer

	mNoExt      bool
	mTopicLock  bool
	mInviteOnly bool
	mSecret     bool
	mModerated  bool
	mKey        string
	mLimit      int // -1: no limit
	mNoKnock    bool

	banList    list.List // of *IRCMask
	exemptList list.List // of *IRCMask
	invexList  list.List // of *IRCMask
}

func (ch *IRCChannel) serializeModes(c *IRCClient) (mspec string, margs []string) {
	mspec = "+"
	if ch.mNoExt {
		mspec += "n"
	}
	if ch.mTopicLock {
		mspec += "t"
	}
	if ch.mInviteOnly {
		mspec += "i"
	}
	if ch.mModerated {
		mspec += "m"
	}
	if ch.mKey != "" {
		mspec += "k"
		margs = append(margs, ch.mKey)
	}
	if ch.mLimit >= 0 {
		mspec += "l"
		margs = append(margs, fmt.Sprintf("%d", ch.mLimit))
	}
	if ch.mNoKnock {
		mspec += "K"
	}

	return
}

func (ch *IRCChannel) testCanKnock(k *IRCClient) bool {
	if ch.mNoKnock {
		return false
	}

	return true
}

func (ch *IRCChannel) sendCommandFromUser(from *IRCClient, cmd string, args ...string) {
	for _, m := range ch.clientsByNick {
		m.client.sendCommandFromUser(from, cmd, args...)
	}
}

func (ch *IRCChannel) SendMsg(from *IRCClient, msg string, cmd string) {
	for _, m := range ch.clientsByNick {
		m.client.sendCommandFromUser(from, cmd, m.client.NickName, msg)
	}
}

func (ch *IRCChannel) SetTopic(setter *IRCClient, topic string) {
	ch.Topic = topic
	for _, m := range ch.clientsByNick {
		m.client.sendCommandFromUser(setter, "TOPIC", ch.Name, topic)
	}
}

func (ch *IRCChannel) AddUser(c *IRCClient) *IRCChannelMember {
	cnick := canonicalizeNickName(c.NickName)

	if m, ok := ch.clientsByNick[cnick]; ok {
		// already in the channel
		return m
	}

	chmem := &IRCChannelMember{}
	chmem.channel = ch
	chmem.client = c
	if len(ch.clientsByNick) == 0 {
		chmem.isOp = true
	}

	c.channels.PushBack(chmem)
	ch.clientsByNick[cnick] = chmem

	// announce
	ch.sendCommandFromUser(c, "JOIN", ch.Name, "*", c.RealName)
	c.sendCommandFromServer("TOPIC", ch.Topic)
	ch.sendNames(c)

	return chmem
}

func (ch *IRCChannel) sendNames(c *IRCClient) {
	for _, m := range ch.clientsByNick {
		c.sendNumericFromServer(353, c.NickName, "=", ch.Name, m.DecoratedName())
	}
	c.sendNumericFromServer(366, c.NickName, ch.Name, "End of /NAMES list.")
}

func (ch *IRCChannel) sendWho(c *IRCClient) {
	for _, m := range ch.clientsByNick {
		hopcount := 0
		hereGone := "H"
		if m.client.isOperator {
			hereGone += "*"
		}
		c.sendNumericFromServer(352, c.NickName, ch.Name, m.client.UserName(), m.client.HostName(), m.client.s.Name, m.client.NickName, hereGone+m.Decoration(),
			fmt.Sprintf("%d %s", hopcount, m.client.RealName))
	}
	c.sendNumericFromServer(315, c.NickName, ch.Name, "End of /WHO list.")
}

func (ch *IRCChannel) NotifyUserPart(c *IRCClient, reason string) {
	ch.sendCommandFromUser(c, "PART", ch.Name, reason)
}

func (ch *IRCChannel) NotifyUserKick(c *IRCClient, kicker *IRCClient, reason string) {
	ch.sendCommandFromUser(kicker, "KICK", ch.Name, c.NickName, reason)
}

func (ch *IRCChannel) NotifyUserKill(c *IRCClient, killer *IRCClient, reason string) {
	ch.sendCommandFromUser(killer, "KILL", c.NickName, reason)
}

func (ch *IRCChannel) NotifyUserQuit(c *IRCClient, reason string) {
	ch.sendCommandFromUser(c, "QUIT", reason)
}

func (ch *IRCChannel) NotifyUserInvite(invitee *IRCClient, inviter *IRCClient) {
	ch.sendCommandFromUser(inviter, "INVITE", invitee.NickName, ch.Name)
}

func (ch *IRCChannel) NotifyUserNick(c *IRCClient, newNickName string) {
	ch.sendCommandFromUser(c, "NICK", newNickName)
}

func (ch *IRCChannel) NotifyKnock(k *IRCClient, reason string) {
	ch.sendCommandFromUser(k, "KNOCK", ch.Name, reason)
}

func (ch *IRCChannel) RemoveUser(c *IRCClient) {
	cnick := canonicalizeNickName(c.NickName)
	if _, ok := ch.clientsByNick[cnick]; ok {
		delete(ch.clientsByNick, cnick)
		for e := c.channels.Front(); e != nil; e = e.Next() {
			if e.Value == ch {
				c.channels.Remove(e)
			}
		}
	}
}

func (ch *IRCChannel) KickUser(kickee *IRCClient, kicker *IRCClient, reason string) {
	ch.NotifyUserKick(kickee, kicker, reason)
	ch.RemoveUser(kickee)
}

func (ch *IRCChannel) InviteUser(invitee *IRCClient, inviter *IRCClient) {
	if ch.mInviteOnly {
		if m, ok := ch.clientsByNick[canonicalizeNickName(inviter.NickName)]; ok {
			if !m.isOp {
				return
			}
		} else {
			return
		}
	}

	invitee.invitations[canonicalizeChannelName(ch.Name)] = 0
	ch.NotifyUserInvite(invitee, inviter)
}

type IRCChannelMember struct {
	channel *IRCChannel
	client  *IRCClient
	isOp    bool
	isVoice bool
}

func (m *IRCChannelMember) Decoration() string {
	if m.isOp {
		return "@"
	} else if m.isVoice {
		return "+"
	} else {
		return ""
	}
}

func (m *IRCChannelMember) DecoratedName() string {
	return m.Decoration() + m.client.NickName
}

func validateNickName(nickName string) bool {
	return re_validNickName.MatchString(nickName)
}

func canonicalizeNickName(nickName string) string {
	return strings.ToLower(nickName)
}

func canonicalizeChannelName(channelName string) string {
	return strings.ToLower(channelName)
}

func canonicalizeCommandName(cmd string) string {
	return strings.ToUpper(cmd)
}

func validateUserName(userName string) bool {
	return re_validUserName.MatchString(userName)
}

func validateRealName(realName string) bool {
	return re_validRealName.MatchString(realName)
}

func validateChannelName(channelName string) bool {
	return re_validChannelName.MatchString(channelName)
}

type DestinationType int

const (
	DT_UNKNOWN DestinationType = iota
	DT_USER
	DT_CHANNEL
)

func determineDestinationType(dest string) (mtype DestinationType) {
	if len(dest) > 0 {
		if validateChannelName(dest) {
			return DT_CHANNEL
		}

		if validateNickName(dest) {
			return DT_USER
		}
	}

	return DT_UNKNOWN
}

func (c *IRCClient) SetNickName(nickName string) error {
	if !validateNickName(nickName) {
		return fmt.Errorf("invalid nickname")
	}

	cNickName := canonicalizeNickName(nickName)
	cOldNickName := canonicalizeNickName(c.NickName)

	if cNickName == cOldNickName {
		c.NickName = nickName
		return nil
	}

	if _, ok := c.s.clientsByNick[cNickName]; ok {
		return fmt.Errorf("nickname already in use")
	}

	if cOldNickName != "" {
		delete(c.s.clientsByNick, cOldNickName)
	}

	c.s.clientsByNick[cNickName] = c

	for e := c.channels.Front(); e != nil; e = e.Next() {
		m := e.Value.(*IRCChannelMember)
		ch := m.channel
		delete(ch.clientsByNick, cOldNickName)

		ch.clientsByNick[cNickName] = m

		ch.NotifyUserNick(c, nickName)
	}

	c.NickName = nickName
	return nil
}

func (c *IRCClient) SetUserName(userName string) error {
	if !validateUserName(userName) {
		return fmt.Errorf("invalid username")
	}

	c.SpecifiedUserName = userName
	return nil
}

func (c *IRCClient) SetRealName(realName string) error {
	if !validateRealName(realName) {
		return fmt.Errorf("invalid realname")
	}

	c.RealName = realName
	return nil
}

// Message must be CRLF terminated.
func (c *IRCClient) send(msg *parse.IRCMessage) {
	if c.isTerminated {
		return
	}

	s := msg.Serialize()

	if c.sendqCur+uint(len(s)) > c.sendqMax {
		c.terminate("sendq exceeded")
		return
	}

	c.sendqCur += uint(len(s))
	c.txChan <- s
}

// Message must not be CRLF terminated.
func (c *IRCClient) sendFromServer(msg *parse.IRCMessage) {
	msg.ServerName = c.s.Name
	c.send(msg)
}

func (c *IRCClient) sendLinkError(reason string) {
	msg := parse.IRCMessage{}
	msg.Command = "ERROR"
	msg.Args = append(msg.Args, "Closing Link: "+c.RealHostName+" ("+reason+")")
	c.send(&msg)
}

func (c *IRCClient) sendFromUser(from *IRCClient, msg *parse.IRCMessage) {
	msg.NickName = from.NickName
	msg.UserName = from.UserName()
	msg.HostName = from.HostName()
	c.send(msg)
}

func (c *IRCClient) sendNumericFromServer(n int, args ...string) {
	m := parse.IRCMessage{}
	m.Command = fmt.Sprintf("%03d", n)
	m.Args = args
	c.sendFromServer(&m)
}

func (c *IRCClient) sendCommandFromUser(from *IRCClient, cmd string, args ...string) {
	m := parse.IRCMessage{}
	m.Command = cmd
	m.Args = args
	c.sendFromUser(from, &m)
}

func (c *IRCClient) sendCommandFromServer(cmd string, args ...string) {
	m := parse.IRCMessage{}
	m.Command = cmd
	m.Args = args
	c.sendFromServer(&m)
}

func (c *IRCClient) sendCommandBare(cmd string, args ...string) {
	m := parse.IRCMessage{}
	m.Command = cmd
	m.Args = args
	c.send(&m)
}

func (c *IRCClient) sendMOTD() {
	for i := range c.s.motd {
		c.sendNumericFromServer(372, c.NickName, c.s.motd[i])
	}
	c.sendNumericFromServer(376, c.NickName, "End of /MOTD command.")
}

func (c *IRCClient) rxLoop() {
	defer c.conn.Close()

	buf := make([]byte, 512)
	p := parse.IRCParser{}

	for {
		n, err := c.conn.Read(buf)
		if err != nil {
			c.terminate("Connection reset")
			return
		}

		p.Parse(string(buf[0:n]))
		msgs := p.GetMessages()

		for _, m := range msgs {
			// message to process
			m.Command = canonicalizeCommandName(m.Command)
			c.processIncomingMessage(m)
		}
	}
}

func (c *IRCClient) processIncomingMessage(m *parse.IRCMessage) {
	log.Info(fmt.Sprintf("rx msg: %+v", m))
	c.lastMessage = time.Now()

	switch m.Command {
	case "USER":
		if c.registered || c.SpecifiedUserName != "" {
			return
		}

		if len(m.Args) < 4 {
			// ...
			return
		}

		err := c.SetUserName(m.Args[0])
		if err != nil {
			return
		}

		err = c.SetRealName(m.Args[3])
		if err != nil {
			return
		}

		c.tryCompleteRegistration()

	case "NICK":
		if len(m.Args) < 1 {
			// ...
			return
		}

		c.SetNickName(m.Args[0])
		c.tryCompleteRegistration()

	case "PING":
		if len(m.Args) < 1 {
			return
		}

		token := m.Args[0]
		c.sendCommandFromServer("PONG", c.s.Name, token)
		// ...

	case "PONG":
		if len(m.Args) < 1 {
			return
		}

		token := m.Args[0]
		if token != c.pingToken {
			return
		}

		c.pingToken = ""

	case "GET", "PUT", "POST", "DELETE", "OPTIONS", "HEAD":
		c.terminate("Attempt to connect to IRC with HTTP")

	default:
		if c.registered {
			c.processIncomingMessageRegistered(m)
		}
	}
}

func (c *IRCClient) processIncomingMessageRegistered(m *parse.IRCMessage) {
	switch m.Command {
	case "PRIVMSG", "NOTICE":
		if len(m.Args) < 2 {
			return
		}

		c.lastPrivmsg = time.Now()

		mtype := determineDestinationType(m.Args[0])
		switch mtype {
		case DT_CHANNEL:
			ch := c.s.FindChannelByName(m.Args[0])
			chm, hasM := ch.clientsByNick[canonicalizeNickName(c.NickName)]
			if (ch.mNoExt || ch.mModerated) && !hasM {
				return
			}

			if ch.mModerated && !chm.isOp && !chm.isVoice {
				return
			}

			ch.SendMsg(c, m.Args[1], m.Command)

		case DT_USER:
			rc := c.s.FindClientByNickName(m.Args[0])
			if rc != nil {
				rc.sendCommandFromUser(c, m.Command, rc.NickName, m.Args[1])
			}

		default:
		}

	case "WHOIS":
		if len(m.Args) < 1 {
			return
		}

		rc := c.s.FindClientByNickName(m.Args[0])
		if rc == nil {
			c.sendNumericFromServer(402, c.NickName, m.Args[0], "No such server")
		} else {
			chanlist := ""
			first := true
			for e := c.channels.Front(); e != nil; e = e.Next() {
				m := e.Value.(*IRCChannelMember)
				if !first {
					chanlist += " "
				} else {
					first = false
				}
				chanlist += m.Decoration() + m.channel.Name
			}
			c.sendNumericFromServer(311, c.NickName, rc.NickName, rc.UserName(), rc.HostName(), "*", rc.RealName)
			c.sendNumericFromServer(319, c.NickName, rc.NickName, chanlist)
			c.sendNumericFromServer(312, c.NickName, rc.NickName, c.s.Name, c.s.Description)
			if c.isSecure {
				c.sendNumericFromServer(671, c.NickName, rc.NickName, "is using a secure connection")
			}
			c.sendNumericFromServer(378, c.NickName, rc.NickName, "is connecting from "+rc.RealHostName+" ("+c.conn.RemoteAddr().(*net.TCPAddr).IP.String()+")")
			c.sendNumericFromServer(317, c.NickName, rc.NickName, fmt.Sprintf("%d", int64(time.Now().Sub(c.lastMessage).Seconds())), fmt.Sprintf("%d", c.logonTime.Unix()), "seconds idle, logon time")
			if c.AccountName != "" {
				c.sendNumericFromServer(330, c.NickName, rc.NickName, c.AccountName, "is logged on as")
			}
			c.sendNumericFromServer(318, c.NickName, rc.NickName, "End of /WHOIS list.")
		}

		// ...

	case "MOTD":
		c.sendMOTD()

	case "LIST":
		// TODO

	case "INVITE":
		if len(m.Args) < 2 {
			return
		}

		cnick := m.Args[0]
		cname := m.Args[1]
		if !validateChannelName(cname) {
			return
		}

		invitee := c.s.FindClientByNickName(cnick)
		if invitee == nil {
			return
		}

		ch := c.s.FindChannelByName(cname)
		if ch == nil {
			return
		}

		ch.InviteUser(invitee, c)

	case "KNOCK":
		if len(m.Args) < 1 {
			return
		}

		cname := m.Args[0]
		reason := ""
		if len(m.Args) > 1 {
			reason = m.Args[1]
		}

		if !validateChannelName(cname) {
			return
		}

		ch := c.s.FindChannelByName(cname)
		if ch == nil {
			return
		}

		if ch.mKey == "" && !ch.mInviteOnly {
			// Channel must have a key or be invite-only in order to knock.
			return
		}

		if !ch.testCanKnock(c) {
			return
		}

		ch.NotifyKnock(c, reason)

	case "JOIN":
		if len(m.Args) < 1 {
			return
		}

		cname := m.Args[0]
		if !validateChannelName(cname) {
			return
		}

		ch := c.s.FindOrCreateChannelByName(cname)

		if _, ok := ch.clientsByNick[canonicalizeNickName(c.NickName)]; ok {
			// already in channel
			return
		}

		if ch.mKey != "" {
			if len(m.Args) < 2 {
				return
			}

			k := m.Args[1]
			if k != ch.mKey { // XXX: SECURITY: COMPARISON TIME
				return
			}
		}

		if ch.mLimit >= 0 && len(ch.clientsByNick) >= ch.mLimit {
			return
		}

		if ch.mInviteOnly {
			if _, ok := c.invitations[canonicalizeChannelName(ch.Name)]; !ok {
				// no invite
				return
			}
		}

		ch.AddUser(c)

	case "NAMES":
		if len(m.Args) < 1 {
			return
		}

		cname := m.Args[0]
		if !validateChannelName(cname) {
			return
		}

		ch := c.s.FindChannelByName(cname)
		ch.sendNames(c)

	case "WHO":
		if len(m.Args) < 1 {
			return
		}

		cname := m.Args[0]
		if !validateChannelName(cname) {
			return
		}

		ch := c.s.FindChannelByName(cname)
		ch.sendWho(c)

	case "MODE":
		if len(m.Args) < 1 {
			return
		}

		changes := ""
		if len(m.Args) > 1 {
			changes = m.Args[1]
		}

		target := m.Args[0]
		mtype := determineDestinationType(m.Args[0])
		switch mtype {
		case DT_CHANNEL:
			if changes == "" {
				// read
				ch := c.s.FindChannelByName(target)
				if ch == nil {
					return
				}

				mspec, margs := ch.serializeModes(c)
				ms := []string{ch.Name, mspec}
				ms = append(ms, margs...)
				c.sendCommandBare("MODE", ms...)
			} else {
				// change
				ch := c.s.FindChannelByName(target)
				if ch == nil {
					return
				}

				chm, ok := ch.clientsByNick[canonicalizeNickName(c.NickName)]
				if !ok {
					return
				}

				if !chm.isOp {
					return
				}

				if len(changes) < 1 || (changes[0] != '+' && changes[0] != '-') {
					return
				}

				add := true
				argi := 2
				chactual := ""
				chactualputsymbol := false
				chargs := []string{}
				for _, x := range changes {
					switch x {
					case '+':
						if !add {
							chactualputsymbol = false
						}
						add = true
					case '-':
						if add {
							chactualputsymbol = false
						}
						add = false
					case 'n':
						ch.mNoExt = add
					case 't':
						ch.mTopicLock = add
					case 'i':
						ch.mInviteOnly = add
					case 'm':
						ch.mModerated = add
					case 'K':
						ch.mNoKnock = add
					case 'k':
						if !add {
							ch.mKey = ""
						} else {
							if len(m.Args) <= argi {
								continue
							}
							ch.mKey = m.Args[argi]
							chargs = append(chargs, ch.mKey)
							argi++
						}

					case 'l':
						if !add {
							ch.mLimit = -1
						} else {
							if len(m.Args) <= argi {
								continue
							}
							n, err := strconv.ParseUint(m.Args[argi], 10, 15)
							if err != nil {
								continue
							}
							ch.mLimit = int(n)
							chargs = append(chargs, fmt.Sprintf("%d", ch.mLimit))
							argi++
						}

					default:
					}

					if !chactualputsymbol {
						if add {
							chactual += "+"
						} else {
							chactual += "-"
						}
						chactualputsymbol = true
					}
					chactual += string(x)
				}

				ms := []string{ch.Name, chactual}
				ms = append(ms, chargs...)
				ch.sendCommandFromUser(c, "MODE", ms...)
			}

		case DT_USER:
			if changes == "" {
				// read
				rc := c.s.FindClientByNickName(target)
				if rc == nil {
					return
				}

				mspec, margs := rc.serializeModes(c)
				ms := []string{rc.NickName, mspec}
				ms = append(ms, margs...)
				c.sendCommandBare("MODE", ms...)
			} else {
				// change
			}

		default:
			return
		}

	case "TOPIC":
		if len(m.Args) < 1 {
			return
		}

		cname := m.Args[0]
		if !validateChannelName(cname) {
			return
		}

		ch := c.s.FindChannelByName(cname)
		if ch == nil {
			return
		}

		doSet := (len(m.Args) > 1)
		if doSet {
			if cm, ok := ch.clientsByNick[canonicalizeNickName(c.NickName)]; ok {
				if !cm.isOp && ch.mTopicLock {
					return
				}

				topic := m.Args[1]
				ch.SetTopic(c, topic)
			}
		} else {
			c.sendNumericFromServer(332, c.NickName, ch.Name, ch.Topic)
			//c.sendNumericFromServer(333, c.NickName, ch.Name, userSetMask, userSetUNIXTime)
		}

	case "PART":
		if len(m.Args) < 1 {
			return
		}

		cname := m.Args[0]
		reason := ""
		if len(m.Args) > 1 {
			reason = m.Args[1]
		}

		if !validateChannelName(cname) {
			return
		}

		ch := c.s.FindChannelByName(cname)
		if ch == nil {
			return
		}

		ch.NotifyUserPart(c, reason)
		ch.RemoveUser(c)

	case "KICK":
		if len(m.Args) < 2 {
			return
		}

		cname := m.Args[0]
		cnick := m.Args[1]

		reason := ""
		if len(m.Args) > 2 {
			reason = m.Args[2]
		}

		if !validateChannelName(cname) {
			return
		}

		ch := c.s.FindChannelByName(cname)
		if ch == nil {
			return
		}

		kc := c.s.FindClientByNickName(cnick)
		if kc == nil {
			return
		}

		if chm, ok := ch.clientsByNick[canonicalizeNickName(c.NickName)]; ok {
			if !chm.isOp {
				return
			}

			ch.KickUser(kc, c, reason)
		}

		// ...

	case "QUIT":
		reason := "Quit"
		if len(m.Args) > 0 {
			reason = m.Args[0]
		}

		c.terminate("Quit: " + reason)
		// ...

	default:
		// unknown command
	}
}

func (c *IRCClient) tryCompleteRegistration() {
	if c.SpecifiedUserName == "" || c.NickName == "" || c.registered {
		return
	}

	// wait for registration checks to complete
	// This means that further commands won't be processed, but this is fine.
	// If the registration checks take a really long time, a ping timeout may occur
	// as the host won't be able to ping. This could happen if the host's ident server
	// is very slow. We don't want to let malicious clients chew up resources in this way,
	// so I think that's actually desirable.
	for i := uint(0); i < c.numRegChecks; i++ {
		<-c.regCheckFinishChan
	}

	c.registered = true
	c.s.unregisteredClients.Remove(c.unregisteredClientElement)
	c.unregisteredClientElement = nil

	c.sendNumericFromServer(1, c.NickName, "Welcome to IRC.")
	c.sendNumericFromServer(5, c.NickName, "CHANTYPES=#", "EXCEPTS", "INVEX", "CHANMODES=b,k,j,nt", "CHANLIMIT=#:50", "PREFIX=(ov)@+", "MAXLIST=bqeI:100", "MODES=4", "NETWORK="+c.s.Name, "KNOCK", "are supported by this server")
	c.sendNumericFromServer(5, c.NickName, "CASEMAPPING=rfc1459", "NICKLEN=30", "MAXNICKLEN=30", "CHANNELLEN=50", "TOPICLEN=390", "CPRIVMSG", "CNOTICE")
	c.sendMOTD()
}

func (c *IRCClient) txLoop() {
	defer c.conn.Close()

	for x := range c.txChan {
		xb := []byte(x)
		_, err := c.conn.Write(xb)
		if err != nil {
			c.terminate("Connection reset")
			return
		}

		c.sendqCur -= uint(len(xb))
	}
}

func (s *IRCServer) newClient(c net.Conn) {
	cl := &IRCClient{}
	cl.s = s
	cl.conn = c
	cl.RealHostName = c.RemoteAddr().(*net.TCPAddr).IP.String()
	cl.lastMessage = time.Now()
	cl.lastPrivmsg = time.Now()
	cl.lastPing = time.Now()
	cl.logonTime = time.Now()
	cl.mInvisible = true
	cl.invitations = map[string]byte{}
	cl.sendqMax = 400 * 1024
	cl.regCheckFinishChan = make(chan struct{}, 100)

	if _, ok := cl.conn.(*tls.Conn); ok {
		cl.isSecure = true
	}

	cl.txChan = make(chan string, 100)

	cl.unregisteredClientElement = s.unregisteredClients.PushBack(cl)

	cl.numRegChecks += 2
	go cl.lookupHostname()
	go cl.lookupIdent()

	go cl.rxLoop()
	go cl.txLoop()
}

func (c *IRCClient) lookupIdent() {
	defer func() {
		c.regCheckFinishChan <- struct{}{}
	}()

	ra := c.conn.RemoteAddr().(*net.TCPAddr)
	la := c.conn.LocalAddr().(*net.TCPAddr)

	dla := net.TCPAddr{la.IP, 0, la.Zone}

	d := net.Dialer{}
	d.Timeout = time.Duration(5) * time.Second
	d.LocalAddr = &dla

	ic, err := d.Dial("tcp", net.JoinHostPort(ra.IP.String(), "113"))
	if err != nil {
		log.Info("Couldn't connect to ident server")
		return
	}

	c.identConn = ic
	defer ic.Close()

	s := fmt.Sprintf("%d, %d\r\n", ra.Port, la.Port)
	_, err = ic.Write([]byte(s))
	if err != nil {
		log.Info("Couldn't write to ident server")
		return
	}

	r := bufio.NewReader(ic)
	L, err := r.ReadString('\n')
	if err != nil && err != io.EOF {
		log.Info("Couldn't read from ident server: ", err)
		return
	}

	L = strings.Trim(L, " \r\n")
	La := strings.Split(L, ":")
	if len(La) < 4 {
		log.Info("Malformed response from ident server: ", L)
		return
	}

	switch strings.Trim(La[1], " ") {
	case "USERID":
		//domain   := strings.Trim(La[2], " ")
		username := strings.Trim(La[3], " ")

		if !re_validUserName.MatchString(username) {
			log.Info("Malformed username received from ident server")
			return
		}

		c.Ident = username
		log.Info("Ident: ", username)

	default:
		log.Info("Got error from ident server")
		return
	}
}

func (c *IRCClient) lookupHostname() {
	defer func() {
		c.regCheckFinishChan <- struct{}{}
	}()

	ra := c.conn.RemoteAddr().(*net.TCPAddr).IP.String()

	names, err := net.LookupAddr(ra)
	if err != nil {
		log.Info("Couldn't lookup RDNS: ", err)
		return
	}

	names = names[0:1]

	if len(names) != 1 {
		log.Info("Got multiple RDNS names (", names, "), not using any of them.")
		return
	}

	n := names[0]
	if !re_validHostName.MatchString(n) {
		log.Info("Invalid hostname received from RDNS.")
		return
	}

	addrs, err := net.LookupHost(n)
	if err != nil {
		log.Info("Failed to do forward consistency check on RDNS result: ", err)
		return
	}

	if len(addrs) != 1 {
		log.Info("Got ", len(addrs), " results when doing forward consistency check on RDNS result, not using any of them.")
		return
	}

	a := addrs[0]
	if a != ra {
		log.Info("Forward address from RDNS does not match original IP, not using RDNS.")
		return
	}

	log.Info("RDNS lookup successful: ", n)
	c.RealHostName = n
}

type dnsblCacheItem struct {
	ip net.IP
	t  time.Time
}

type DNSBL struct {
	domain string
	cache  map[string]dnsblCacheItem
	mutex  sync.Mutex
}

func NewDNSBL(domain string) *DNSBL {
	d := &DNSBL{
		domain: domain,
		cache:  map[string]dnsblCacheItem{},
	}
	go d.expireLoop()
	return d
}

func (d *DNSBL) expireLoop() {
	for {
		time.Sleep(time.Duration(30) * time.Minute)

		d.mutex.Lock()
		defer d.mutex.Unlock()

		for k, v := range d.cache {
			if v.t.Add(time.Duration(8) * time.Hour).Before(time.Now()) {
				delete(d.cache, k)
			}
		}
	}
}

func (d *DNSBL) query(ip net.IP) (r net.IP, err error) {
	ip4 := ip.To4()

	ds := fmt.Sprintf("%u.%u.%u.%u.%s", ip4[3], ip4[2], ip4[1], ip4[0], d.domain)

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

	d.cache[ip_s] = dnsblCacheItem{r, time.Now()}
	return
}

func (s *IRCServer) pingLoop() {
	for {
		time.Sleep(time.Duration(30) * time.Second)
		for _, c := range s.clientsByNick {
			c.checkPing()
		}

		for e := s.unregisteredClients.Front(); e != nil; e = e.Next() {
			c := e.Value.(*IRCClient)
			c.checkPing()
		}
	}
}

func (s *IRCServer) Run() error {
	_, err := rand.Read(s.pingTokenKey[0:32])
	log.Fatale(err)

	_, err = rand.Read(s.cloakKey[0:32])
	log.Fatale(err)

	s.clientsByNick = map[string]*IRCClient{}
	s.channelsByName = map[string]*IRCChannel{}

	if s.Name == "" {
		s.Name = "irc-server"
	}

	if s.Description == "" {
		s.Description = "An IRC Server"
	}

	listeners := make([]net.Listener, 0)

	//
	listener, err := net.Listen("tcp", ":6668")
	log.Fatale(err)
	listeners = append(listeners, listener)

	//
	cert, err := tls.LoadX509KeyPair("ssl.crt", "ssl.key")
	log.Fatale(err)

	tlsConfig := tls.Config{
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
		NextProtos: []string{"irc"},
		Certificates: []tls.Certificate{
			cert,
		},
		MinVersion: tls.VersionTLS12,
	}

	tlsL, err := tls.Listen("tcp", ":6697", &tlsConfig)
	log.Fatale(err)
	listeners = append(listeners, tlsL)

	//
	for _, L := range listeners {
		go s.listenLoop(L)
	}

	s.pingLoop()

	return nil
}

func (s *IRCServer) listenLoop(L net.Listener) {
	for {
		c, err := L.Accept()
		log.Fatale(err)

		s.newClient(c)
	}
}

func main() {
	s := IRCServer{}
	s.Run()
}

// © 2014 Hugo Landau <hlandau@devever.net>    GPLv3 or later
