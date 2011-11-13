// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"net"
	"net/http"
	"testing"
)

func TestTcpipProxy(t *testing.T) {
	if *sshuser == "" {
		t.Log("ssh.user not defined, skipping test")
		return
	}
	config := &ClientConfig{
		User: *sshuser,
		Auth: []ClientAuth{
			ClientAuthPassword(password(*sshpass)),
		},
	}
	conn, err := Dial("tcp", "localhost:22", config)
	if err != nil {
		t.Fatalf("Unable to connect: %s", err)
	}
	defer conn.Close()
	tr := &http.Transport{
		Dial: func(n, addr string) (net.Conn, error) {
			return conn.Dial(n, addr)
		},
	}
	client := &http.Client{
		Transport: tr,
	}
	resp, err := client.Get("http://www.google.com/")
	if err != nil {
		t.Fatalf("unable to proxy: %s", err)
	}
	t.Log(resp)
}

// currently disabled
func testTcpipInception(t *testing.T) {
	if *sshuser == "" {
		t.Log("ssh.user not defined, skipping test")
		return
	}
	config := &ClientConfig{
		User: *sshuser,
		Auth: []ClientAuth{
			ClientAuthPassword(password(*sshpass)),
		},
	}
	conn, err := Dial("tcp", "localhost:22", config)
	if err != nil {
		t.Fatalf("Unable to connect: %s", err)
	}
	defer conn.Close()
	conn2, err := conn.Dial("tcp", "192.168.1.200:22")
	if err != nil {
		t.Fatalf("unable to request direct-tcpip channel: %s", err)
	}
	defer conn2.Close()

	conn3, err := Client(conn2, config)
	if err != nil {
		t.Fatalf("unable to connect to ssh server via tcpip bridge: %s", err)
	}
	defer conn3.Close()
}
