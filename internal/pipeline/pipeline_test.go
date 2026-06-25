package pipeline

import (
	"testing"
)

func TestStripURLToHost(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"https://sub.example.com/path?q=1", "sub.example.com"},
		{"http://sub.example.com", "sub.example.com"},
		{"https://sub.example.com:8443/x", "sub.example.com"},
		{"sub.example.com", "sub.example.com"},
		{"sub.example.com:443", "sub.example.com"},
		{"HTTPS://UPPER.Example.COM", "upper.example.com"},
		{"", ""},
		{"   ", ""},
	}
	for _, c := range cases {
		got := stripURLToHost(c.in)
		if got != c.want {
			t.Errorf("stripURLToHost(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestGuessPortService(t *testing.T) {
	cases := map[int]string{
		22:   "ssh",
		80:   "http",
		443:  "https",
		3306: "mysql",
		8080: "http-alt",
		1:    "unknown",
		0:    "unknown",
	}
	for port, want := range cases {
		if got := guessPortService(port); got != want {
			t.Errorf("guessPortService(%d) = %q, want %q", port, got, want)
		}
	}
}
