package ssh

import (
	"io"
	"os"
	"strings"
)

func (c *Client) Command(path string, args ...string) (*Cmd, os.Error) {
	ch, err := c.OpenChannel()
	if err != nil {
		return nil, err
	}
	return &Cmd{
		ch:   ch,
		Path: path,
		Args: args,
	}, nil
}

type Cmd struct {
	ch             *ClientChan
	Path           string
	Args           []string
	Env            []string
	Stdin          io.Reader
	Stdout, Stderr io.Writer
}

// start remote command
func (c *Cmd) Start() os.Error {
	return c.ch.Exec(c.Path + strings.Join(c.Args, " "))
}
