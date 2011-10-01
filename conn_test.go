// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"net"
	"testing"
)

const PEM = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA19lGVsTqIT5iiNYRgnoY1CwkbETW5cq+Rzk5v/kTlf31XpSU
70HVWkbTERECjaYdXM2gGcbb+sxpq6GtXf1M3kVomycqhxwhPv4Cr6Xp4WT/jkFx
9z+FFzpeodGJWjOH6L2H5uX1Cvr9EDdQp9t9/J32/qBFntY8GwoUI/y/1MSTmMiF
tupdMODN064vd3gyMKTwrlQ8tZM6aYuyOPsutLlUY7M5x5FwMDYvnPDSeyT/Iw0z
s3B+NCyqeeMd2T7YzQFnRATj0M7rM5LoSs7DVqVriOEABssFyLj31PboaoLhOKgc
qoM9khkNzr7FHVvi+DhYM2jD0DwvqZLN6NmnLwIDAQABAoIBAQCGVj+kuSFOV1lT
+IclQYA6bM6uY5mroqcSBNegVxCNhWU03BxlW//BE9tA/+kq53vWylMeN9mpGZea
riEMIh25KFGWXqXlOOioH8bkMsqA8S7sBmc7jljyv+0toQ9vCCtJ+sueNPhxQQxH
D2YvUjfzBQ04I9+wn30BByDJ1QA/FoPsunxIOUCcRBE/7jxuLYcpR+JvEF68yYIh
atXRld4W4in7T65YDR8jK1Uj9XAcNeDYNpT/M6oFLx1aPIlkG86aCWRO19S1jLPT
b1ZAKHHxPMCVkSYW0RqvIgLXQOR62D0Zne6/2wtzJkk5UCjkSQ2z7ZzJpMkWgDgN
ifCULFPBAoGBAPoMZ5q1w+zB+knXUD33n1J+niN6TZHJulpf2w5zsW+m2K6Zn62M
MXndXlVAHtk6p02q9kxHdgov34Uo8VpuNjbS1+abGFTI8NZgFo+bsDxJdItemwC4
KJ7L1iz39hRN/ZylMRLz5uTYRGddCkeIHhiG2h7zohH/MaYzUacXEEy3AoGBANz8
e/msleB+iXC0cXKwds26N4hyMdAFE5qAqJXvV3S2W8JZnmU+sS7vPAWMYPlERPk1
D8Q2eXqdPIkAWBhrx4RxD7rNc5qFNcQWEhCIxC9fccluH1y5g2M+4jpMX2CT8Uv+
3z+NoJ5uDTXZTnLCfoZzgZ4nCZVZ+6iU5U1+YXFJAoGBANLPpIV920n/nJmmquMj
orI1R/QXR9Cy56cMC65agezlGOfTYxk5Cfl5Ve+/2IJCfgzwJyjWUsFx7RviEeGw
64o7JoUom1HX+5xxdHPsyZ96OoTJ5RqtKKoApnhRMamau0fWydH1yeOEJd+TRHhc
XStGfhz8QNa1dVFvENczja1vAoGABGWhsd4VPVpHMc7lUvrf4kgKQtTC2PjA4xoc
QJ96hf/642sVE76jl+N6tkGMzGjnVm4P2j+bOy1VvwQavKGoXqJBRd5Apppv727g
/SM7hBXKFc/zH80xKBBgP/i1DR7kdjakCoeu4ngeGywvu2jTS6mQsqzkK+yWbUxJ
I7mYBsECgYB/KNXlTEpXtz/kwWCHFSYA8U74l7zZbVD8ul0e56JDK+lLcJ0tJffk
gqnBycHj6AhEycjda75cs+0zybZvN4x65KZHOGW/O/7OAWEcZP5TPb3zf9ned3Hl
NsZoFj52ponUM6+99A2CmezFCN16c4mbA//luWF+k3VVqR6BpkrhKw==
-----END RSA PRIVATE KEY-----`

var (
	serverConfig = &ServerConfig{
		NoClientAuth:          true,
		SupportedKexAlgos:     supportedKexAlgos,
		SupportedHostKeyAlgos: supportedHostKeyAlgos,
		SupportedCiphers:      supportedCiphers,
		SupportedMACs:         supportedMACs,
		SupportedCompressions: supportedCompressions,
	}

	clientConfig = &ClientConfig{
		SupportedKexAlgos:     supportedKexAlgos,
		SupportedHostKeyAlgos: supportedHostKeyAlgos,
		SupportedCiphers:      supportedCiphers,
		SupportedMACs:         supportedMACs,
		SupportedCompressions: supportedCompressions,
		User:                  "scott",
		Password:              "tiger",
	}
)

func init() {
	serverConfig.SetRSAPrivateKey([]byte(PEM))
}

// shabby bufferedPipe implementation to avoid the 
// deadlocks using a net.Pipe() directly
func bufferedPipe() (net.Conn, net.Conn) {
	a, b := net.Pipe()
	c, d := net.Pipe()
	go func() {
		defer c.Close()
		for {
			buf := make([]byte, 1024)
			read, err := b.Read(buf)
			if err != nil {
				return
			}
			c.Write(buf[:read])
		}
	}()
	go func() {
		defer b.Close()
		for {
			buf := make([]byte, 1024)
			read, err := c.Read(buf)
			if err != nil {
				return
			}
			b.Write(buf[:read])
		}
	}()
	return a, d
}

// test handshaking without going via a
// loopback socket
func TestClientServerPipeConn(t *testing.T) {
	c, s := bufferedPipe()
	client, server := newClientConn(c, clientConfig), newServerConn(s, serverConfig)
	defer client.Close()
	defer server.Close()
	go func() {
		if err := server.Handshake(); err != nil {
			t.Fatal("error: serverHandshake:", err)
		}
	}()
	if err := client.handshake(); err != nil {
		t.Fatal("error: clientHandshake:", err)
	}
}

// test Listen/Dial functionality
func TestClientServerNetConn(t *testing.T) {
	l, err := Listen("localhost:0", serverConfig)
	if err != nil {
		t.Fatal("error listening on loopback:", err)
	}
	defer l.Close()
	go func() {
		server, err := l.Accept()
		if err != nil {
			t.Fatal("error accepting incoming connection:", err)
		}
		defer server.Close()
		if err := server.Handshake(); err != nil {
			t.Fatal("error: serverHandshake:", err)
		}
	}()
	c, err := Dial(l.Addr().String(), clientConfig)
	if err != nil {
		t.Fatal("error connecting to server socket:", err)
	}
	defer c.Close()
}
