package parse
import "testing"

func TestParse(t *testing.T) {
  type item struct {
    s string
    ok bool
  }

  ss := []item {
    item { "PING\r\n", true },
    item { "PING foo\r\n", true },
    item { "PING foo bar\r\n", true },
    item { "PING foo bar baz\r\n", true },
    item { "PING foo bar baz :alpha beta gamma delta\r\n", true},
    item { "043 okay well :this is a numeric\r\n", true},
    item { "01 bad numeric\r\n", false },
    item { "\r\n", false },
    item { ":server PING\r\n", true},
    item { ":server.name PING\r\n", true},
    item { ":the.server-name PING\r\n", true},
    item { ":the.server-name. PING\r\n", true},
    item { ":nick!user@host PING\r\n", true},
    item { ":nick!user@host.name PING\r\n", true},
    item { ":nick!user@111.222.101.104 PING\r\n", true},
    item { ":nick!user@dead:beef:dead:beef:1234:4567:89ad:beef PING\r\n", true},
    item { ":nick!~user@host.name PING\r\n", true},
  }

  for _, i := range ss {
    p := &IRCParser{}
    p.Parse(i.s)
    if i.ok != (p.MalformedMessageCount == 0) {
      t.Errorf("test was supposed to return %s but didn't: %s", i.ok, i.s)
    }
    if p.MalformedMessageCount == 0 {
      msgs := p.GetMessages()
      if len(msgs) != 1 {
        t.Errorf("returned wrong number of messages: %s", len(msgs))
      }
    }
  }
}
