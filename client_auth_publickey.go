// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"errors"
	"math/big"
)

var ErrNoKeys = errors.New("No more keys")

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

type publicKeyAuth struct {
	ClientPublicKey
}

func (p *publicKeyAuth) auth(session []byte, user string, t *transport) (bool, []string, error) {
	type publickeyAuthMsg struct {
		User     string
		Service  string
		Method   string
		Reply    bool
		Algoname string
		Blob     string
		Sig      []byte `rest`
	}

	for i := 0; ; i++ {
		alg, pub, err := p.Key(i)
		if err != nil {
			break
		}
		algoBytes := make([]byte, stringLength([]byte(alg)))
		marshalString(algoBytes, []byte(alg))
		var length int
		for _, j := range pub {
			length += intLength(j)
		}
		pubKey := make([]byte, length)
		s := pubKey
		for _, j := range pub {
			s = marshalInt(s, j)
		}
		stringPubKey := make([]byte, stringLength(pubKey))
		marshalString(stringPubKey, pubKey)
		sig, err := p.Sign(i, buildDataSignedForAuth(session, userAuthRequestMsg{
			User:    user,
			Service: serviceSSH,
			Method:  p.method(),
		}, []byte(alg), append(algoBytes, pubKey...)))
		if err != nil {
			return false, nil, err
		}
		msg := publickeyAuthMsg{
			User:     user,
			Service:  serviceSSH,
			Method:   p.method(),
			Reply:    true,
			Algoname: alg,
			Blob:     string(append(algoBytes, pubKey...)),
			Sig:      serializeRSASignature(sig),
		}
		p := marshal(msgUserAuthRequest, msg)
		if err := t.writePacket(p); err != nil {
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
	}
	return false, nil, nil
}

func (p *publicKeyAuth) method() string {
	return "publickey"
}

// ClientAuthPublicKey returns a ClientAuth using public key authentication.
func ClientAuthPublicKey(impl ClientPublicKey) ClientAuth {
	return &publicKeyAuth{impl}
}
