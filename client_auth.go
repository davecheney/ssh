// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"big"
	"errors"
	"fmt"
)

type set map[string]string

func (s set) contains(v string) bool {
	_, ok := s[v]
	return ok
}

// authenticate authenticates with the remote server. See RFC 4252. 
func (c *ClientConn) authenticate() error {
	// initiate user auth session
	if err := c.writePacket(marshal(msgServiceRequest, serviceRequestMsg{serviceUserAuth})); err != nil {
		return err
	}
	packet, err := c.readPacket()
	if err != nil {
		return err
	}
	var serviceAccept serviceAcceptMsg
	if err := unmarshal(&serviceAccept, packet, msgServiceAccept); err != nil {
		return err
	}
	// during the authentication phase the client first attempts the "none" method
	// then any untried methods suggested by the server. 
	tried, remain := make(set), make(set)
	for auth := ClientAuth(new(noneAuth)); auth != nil; {
                fmt.Printf("tried: %s, remain: %s\n", tried, remain)
		ok, methods, err := auth.auth(c.config.User, c.transport)
		if err != nil {
			return err
		}
		if ok {
			// success
			return nil
		}
		tried[auth.method()] = auth.method()
		delete(remain, auth.method())
		auth = nil
		for _, meth := range methods {
			if tried.contains(meth) {
				continue
			}
			if !remain.contains(meth) {
				remain[meth] = meth
			}
			for _, a := range c.config.Auth {
				if a.method() == meth && auth == nil {
					auth = a
					break
				}
			}
		}
	}
	return errors.New("ssh: unable to authenticate, no supported methods remain")
}

// A ClientAuth represents an instance of an RFC 4252 authentication method.
type ClientAuth interface {
	// auth authenticates user over transport t. 
	// Returns true if authentication is successful.
	// If authentication is not successful, a []string of alternative 
	// method names is returned.
	auth(user string, t *transport) (bool, []string, error)

	// method returns the RFC 4252 method name.
	method() string
}

// "none" authentication, RFC 4252 section 5.2.
type noneAuth int

func (n *noneAuth) auth(user string, t *transport) (bool, []string, error) {
	if err := t.writePacket(marshal(msgUserAuthRequest, userAuthRequestMsg{
		User:    user,
		Service: serviceSSH,
		Method:  "none",
	})); err != nil {
		return false, nil, err
	}

	packet, err := t.readPacket()
	if err != nil {
		return false, nil, err
	}

	switch packet[0] {
	case msgUserAuthSuccess:
		return true, nil, nil
	case msgUserAuthFailure:
		msg := decode(packet).(*userAuthFailureMsg)
		return false, msg.Methods, nil
	}
	return false, nil, UnexpectedMessageError{msgUserAuthSuccess, packet[0]}
}

func (n *noneAuth) method() string {
	return "none"
}

// "password" authentication, RFC 4252 Section 8.
type passwordAuth struct {
	ClientPassword
}

func (p *passwordAuth) auth(user string, t *transport) (bool, []string, error) {
	type passwordAuthMsg struct {
		User     string
		Service  string
		Method   string
		Reply    bool
		Password string
	}

	pw, err := p.Password(user)
	if err != nil {
		return false, nil, err
	}

	if err := t.writePacket(marshal(msgUserAuthRequest, passwordAuthMsg{
		User:     user,
		Service:  serviceSSH,
		Method:   "password",
		Reply:    false,
		Password: pw,
	})); err != nil {
		return false, nil, err
	}

	packet, err := t.readPacket()
	if err != nil {
		return false, nil, err
	}

	switch packet[0] {
	case msgUserAuthSuccess:
		return true, nil, nil
	case msgUserAuthFailure:
		msg := decode(packet).(*userAuthFailureMsg)
		return false, msg.Methods, nil
	}
	return false, nil, UnexpectedMessageError{msgUserAuthSuccess, packet[0]}
}

func (p *passwordAuth) method() string {
	return "password"
}

// A ClientPassword implements access to a client's passwords.
type ClientPassword interface {
	// Password returns the password to use for authentication as id.
	Password(id string) (password string, err error)
}

// A ClientPublicKey implements access to a client key ring.
type ClientPublicKey interface {
	// Key returns the i'th key, or ssh.ErrNoKeys if there is no i'th key.
	// The algorithm is typically "ssh-rsa" or "ssh-dsa".
	// For "ssh-rsa" the pub list is {ek, mod}.
	// For "ssh-dsa" the pub list is {p, q, alpha, key}.
	Key(i int) (alg string, pub []*big.Int, err error)

	// Sign returns a signature of the given data using the i'th key.
	Sign(i int, data []byte) (sig []byte, err error)
}

// ClientAuthPassword returns a ClientAuth using password authentication.
func ClientAuthPassword(impl ClientPassword) ClientAuth {
	return &passwordAuth{impl}
}

type publicKeyAuth struct {
	ClientPublicKey
}

func (p *publicKeyAuth) auth(user string, t *transport) (bool, []string, error) {
	type publickeyAuthMsg struct {
		User     string
		Service  string
		Method   string
		Reply    bool
		Algoname string
		Blob     string
	}

	if err := t.writePacket(marshal(msgUserAuthRequest, publickeyAuthMsg{
		User:     user,
		Service:  serviceSSH,
		Method:   "publicKey",
		Reply:    false,
		Algoname: "sshrsa",
	})); err != nil {
		return false, nil, err
	}

	packet, err := t.readPacket()
	if err != nil {
		return false, nil, err
	}

	switch packet[0] {
	case msgUserAuthSuccess:
		return true, nil, nil
	case msgUserAuthFailure:
		msg := decode(packet).(*userAuthFailureMsg)
		return false, msg.Methods, nil
	default:
		return false, nil, UnexpectedMessageError{msgUserAuthSuccess, packet[0]}
	}
	panic("unreachable")

}

func (p *publicKeyAuth) method() string {
	return "publickey"
}

// ClientAuthPublicKey returns a ClientAuth using public key authentication.
func ClientAuthPublicKey(impl ClientPublicKey) ClientAuth {
	return &publicKeyAuth{impl}
}
