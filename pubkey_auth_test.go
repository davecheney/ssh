// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"testing"
)

const _pem = `-----BEGIN RSA PRIVATE KEY-----
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

type keychain struct {
	keys []*rsa.PrivateKey
}

func (k *keychain) Key(i int) (string, []*big.Int, error) {
	if i < 0 || i >= len(k.keys) {
		return "", nil, ErrNoKeys
	}
	pub := k.keys[i].PublicKey
	e := new(big.Int).SetInt64(int64(pub.E))
	return "ssh-rsa", []*big.Int{e, pub.N}, nil
}

// Sign returns a signature of the given data using the i'th key.
func (k *keychain) Sign(i int, data []byte) (sig []byte, err error) {
	hashFunc := crypto.SHA1
	h := hashFunc.New()
	h.Write(data)
	digest := h.Sum()
	return rsa.SignPKCS1v15(rand.Reader, k.keys[i], hashFunc, digest)
}

func TestClientPubkeyAuth(t *testing.T) {
	pkey, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		t.Fatalf("unable to generate private key: %s", err)
	}
	t.Log("public key generated")

	k := new(keychain)
	k.keys = append(k.keys, pkey)

	sConfig := &ServerConfig{
		PubKeyCallback: func(user, algo string, pubkey []byte) bool {
			t.Logf("%s, %s, %v", user, algo, pubkey)
			return true
		},
	}

	if err := sConfig.SetRSAPrivateKey([]byte(_pem)); err != nil {
		t.Fatalf("Failed to parse private key: %s", err)
	}

	l, err := Listen("tcp", "0.0.0.0:0", sConfig)
	if err != nil {
		t.Fatalf("unable to listen: %s", err)
	}
	t.Logf("Listening on %s", l.Addr())
	done := make(chan bool)
	go func() {
		c, err := l.Accept()
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Handshake(); err != nil {
			t.Error(err)
		}
		defer c.Close()
		done <- true
	}()

	config := &ClientConfig{
		User: "testuser",
		Auth: []ClientAuth{ClientAuthPublicKey(k)},
	}

	t.Logf("Dialing %s", l.Addr())
	c, err := Dial("tcp", l.Addr().String(), config)
	if err != nil {
		t.Errorf("unable to dial remote side: %s", err)
	}
	defer c.Close()
	<-done
}
