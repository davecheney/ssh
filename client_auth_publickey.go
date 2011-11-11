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
		Sig      []byte
	}

	for i := 0; ; i++ {
		alg, pub, err := p.Key(i)
		if err != nil {
			break
		}
		pubkey := serializePublickey(alg, pub)
		sig, err := p.Sign(i, buildDataSignedForAuth(session, userAuthRequestMsg{
			User:    user,
			Service: serviceSSH,
			Method:  p.method(),
		}, []byte(alg), pubkey))
		if err != nil {
			return false, nil, err
		}
		msg := publickeyAuthMsg{
			User:     user,
			Service:  serviceSSH,
			Method:   p.method(),
			Reply:    true,
			Algoname: alg,
			Blob:     string(pubkey),
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

func serializePublickey(alg string, pub []*big.Int) []byte {
	length := stringLength([]byte(alg))
	for _, i := range pub {
		length += intLength(i)
	}
	ret := make([]byte, length)
	key := marshalString(ret, []byte(alg))
	for _, i := range pub {
		key = marshalInt(key, i)
	}
	return ret
}
