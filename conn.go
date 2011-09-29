// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"big"
	"crypto"
	"encoding/pem"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"os"
	"net"
)

// versionString is the fixed identification string that both 
// the Client and Server will use.
var versionString = []byte("SSH-2.0-Go\r\n")

// An ssh.Conn represents one end of a multiplexed ssh connection.
type Conn struct {
	*transport
	config   *Config
	isServer bool
	channels map[uint32]*channel
}

func newConn(c net.Conn, config *Config) *Conn {
	conn := &Conn{
		transport: newTransport(c),
		config:    config,
		channels:  make(map[uint32]*channel),
	}
	return conn
}

func (c *Conn) Handshake() os.Error {
	if c.isServer {
		return c.serverHandshake()
	}
	return c.clientHandshake()
}

func (c *Conn) serverHandshake() os.Error {
	var magics handshakeMagics
	if _, err := c.Write(versionString); err != nil {
		return err
	}
	if err := c.Flush(); err != nil {
		return err
	}
	magics.serverVersion = versionString[:len(versionString)-2]

	version, ok := readVersion(c.transport)
	if !ok {
		return os.NewError("failed to read version string from client")
	}
	magics.clientVersion = version

	serverKexInit := kexInitMsg{
		KexAlgos:                supportedKexAlgos,
		ServerHostKeyAlgos:      supportedHostKeyAlgos,
		CiphersClientServer:     supportedCiphers,
		CiphersServerClient:     supportedCiphers,
		MACsClientServer:        supportedMACs,
		MACsServerClient:        supportedMACs,
		CompressionClientServer: supportedCompressions,
		CompressionServerClient: supportedCompressions,
	}
	kexInitPacket := marshal(msgKexInit, serverKexInit)
	magics.serverKexInit = kexInitPacket

	if err := c.writePacket(kexInitPacket); err != nil {
		return err
	}

	packet, err := c.readPacket()
	if err != nil {
		return err
	}

	magics.clientKexInit = packet

	var clientKexInit kexInitMsg
	if err = unmarshal(&clientKexInit, packet, msgKexInit); err != nil {
		return err
	}

	kexAlgo, hostKeyAlgo, ok := findAgreedAlgorithms(c.transport, c.transport, &clientKexInit, &serverKexInit)
	if !ok {
		return os.NewError("ssh: no common algorithms")
	}

	if clientKexInit.FirstKexFollows && kexAlgo != clientKexInit.KexAlgos[0] {
		// The client sent a Kex message for the wrong algorithm,
		// which we have to ignore.
		_, err := c.readPacket()
		if err != nil {
			return err
		}
	}

	var H, K []byte
	var hashFunc crypto.Hash
	switch kexAlgo {
	case kexAlgoDH14SHA1:
		hashFunc = crypto.SHA1
		dhGroup14Once.Do(initDHGroup14)
		H, K, err = c.serverKexDH(dhGroup14, hashFunc, &magics, hostKeyAlgo)
	default:
		err = os.NewError("ssh: internal error")
	}

	if err != nil {
		return err
	}

	if err = c.writePacket([]byte{msgNewKeys}); err != nil {
		return err
	}

	if err = c.transport.writer.setupKeys(serverKeys, K, H, H, hashFunc); err != nil {
		return err
	}

	if packet, err = c.readPacket(); err != nil {
		return err
	}

	if packet[0] != msgNewKeys {
		return UnexpectedMessageError{msgNewKeys, packet[0]}
	}

	c.transport.reader.setupKeys(clientKeys, K, H, H, hashFunc)

	if packet, err = c.readPacket(); err != nil {
		return err
	}

	var serviceRequest serviceRequestMsg
	if err = unmarshal(&serviceRequest, packet, msgServiceRequest); err != nil {
		return err
	}

	if serviceRequest.Service != serviceUserAuth {
		return os.NewError("ssh: requested service '" + serviceRequest.Service + "' before authenticating")
	}

	serviceAccept := serviceAcceptMsg{
		Service: serviceUserAuth,
	}

	if err = c.writePacket(marshal(msgServiceAccept, serviceAccept)); err != nil {
		return err
	}

	if err = c.authenticate(H); err != nil {
		return err
	}
	return nil
}

// serverKexDH performs Diffie-Hellman key agreement on a ServerConnection. The
// returned values are given the same names as in RFC 4253, section 8.
func (c *Conn) serverKexDH(group *dhGroup, hashFunc crypto.Hash, magics *handshakeMagics, hostKeyAlgo string) (H, K []byte, err os.Error) {
	packet, err := c.readPacket()
	if err != nil {
		return
	}
	var kexDHInit kexDHInitMsg
	if err = unmarshal(&kexDHInit, packet, msgKexDHInit); err != nil {
		return
	}

	if kexDHInit.X.Sign() == 0 || kexDHInit.X.Cmp(group.p) >= 0 {
		return nil, nil, os.NewError("client DH parameter out of bounds")
	}

	y, err := rand.Int(rand.Reader, group.p)
	if err != nil {
		return
	}

	Y := new(big.Int).Exp(group.g, y, group.p)
	kInt := new(big.Int).Exp(kexDHInit.X, y, group.p)

	var serializedHostKey []byte
	switch hostKeyAlgo {
	case hostAlgoRSA:
		serializedHostKey = c.config.rsaSerialized
	default:
		return nil, nil, os.NewError("internal error")
	}

	h := hashFunc.New()
	writeString(h, magics.clientVersion)
	writeString(h, magics.serverVersion)
	writeString(h, magics.clientKexInit)
	writeString(h, magics.serverKexInit)
	writeString(h, serializedHostKey)
	writeInt(h, kexDHInit.X)
	writeInt(h, Y)
	K = make([]byte, intLength(kInt))
	marshalInt(K, kInt)
	h.Write(K)

	H = h.Sum()

	h.Reset()
	h.Write(H)
	hh := h.Sum()

	var sig []byte
	switch hostKeyAlgo {
	case hostAlgoRSA:
		sig, err = rsa.SignPKCS1v15(rand.Reader, c.config.rsa, hashFunc, hh)
		if err != nil {
			return
		}
	default:
		return nil, nil, os.NewError("internal error")
	}

	serializedSig := serializeRSASignature(sig)

	kexDHReply := kexDHReplyMsg{
		HostKey:   serializedHostKey,
		Y:         Y,
		Signature: serializedSig,
	}
	packet = marshal(msgKexDHReply, kexDHReply)

	err = c.writePacket(packet)
	return
}

func (c *Conn) authenticate(H []byte) os.Error {
	var userAuthReq userAuthRequestMsg
	var err os.Error
	var packet []byte

userAuthLoop:
	for {
		if packet, err = c.readPacket(); err != nil {
			return err
		}
		if err = unmarshal(&userAuthReq, packet, msgUserAuthRequest); err != nil {
			return err
		}

		if userAuthReq.Service != serviceSSH {
			return os.NewError("ssh: client attempted to negotiate for unknown service: " + userAuthReq.Service)
		}

		switch userAuthReq.Method {
		case "none":
			if c.config.NoClientAuth {
				break userAuthLoop
			}
		case "password":
			if c.config.PasswordCallback == nil {
				break
			}
			payload := userAuthReq.Payload
			if len(payload) < 1 || payload[0] != 0 {
				return ParseError{msgUserAuthRequest}
			}
			payload = payload[1:]
			password, payload, ok := parseString(payload)
			if !ok || len(payload) > 0 {
				return ParseError{msgUserAuthRequest}
			}

			if c.config.PasswordCallback(userAuthReq.User, string(password)) {
				break userAuthLoop
			}
		case "publickey":
			if c.config.PubKeyCallback == nil {
				break
			}
			payload := userAuthReq.Payload
			if len(payload) < 1 {
				return ParseError{msgUserAuthRequest}
			}
			isQuery := payload[0] == 0
			payload = payload[1:]
			algoBytes, payload, ok := parseString(payload)
			if !ok {
				return ParseError{msgUserAuthRequest}
			}
			algo := string(algoBytes)

			pubKey, payload, ok := parseString(payload)
			if !ok {
				return ParseError{msgUserAuthRequest}
			}
			if isQuery {
				// The client can query if the given public key
				// would be ok.
				if len(payload) > 0 {
					return ParseError{msgUserAuthRequest}
				}
				if c.testPubKey(userAuthReq.User, algo, pubKey) {
					okMsg := userAuthPubKeyOkMsg{
						Algo:   algo,
						PubKey: string(pubKey),
					}
					if err = c.writePacket(marshal(msgUserAuthPubKeyOk, okMsg)); err != nil {
						return err
					}
					continue userAuthLoop
				}
			} else {
				sig, payload, ok := parseString(payload)
				if !ok || len(payload) > 0 {
					return ParseError{msgUserAuthRequest}
				}
				if !isAcceptableAlgo(algo) {
					break
				}
				rsaSig, ok := parseRSASig(sig)
				if !ok {
					return ParseError{msgUserAuthRequest}
				}
				signedData := buildDataSignedForAuth(H, userAuthReq, algoBytes, pubKey)
				switch algo {
				case hostAlgoRSA:
					hashFunc := crypto.SHA1
					h := hashFunc.New()
					h.Write(signedData)
					digest := h.Sum()
					rsaKey, ok := parseRSA(pubKey)
					if !ok {
						return ParseError{msgUserAuthRequest}
					}
					if rsa.VerifyPKCS1v15(rsaKey, hashFunc, digest, rsaSig) != nil {
						return ParseError{msgUserAuthRequest}
					}
				default:
					return os.NewError("ssh: isAcceptableAlgo incorrect")
				}
				if c.testPubKey(userAuthReq.User, algo, pubKey) {
					break userAuthLoop
				}
			}
		}

		var failureMsg userAuthFailureMsg
		if c.config.PasswordCallback != nil {
			failureMsg.Methods = append(failureMsg.Methods, "password")
		}
		if c.config.PubKeyCallback != nil {
			failureMsg.Methods = append(failureMsg.Methods, "publickey")
		}

		if len(failureMsg.Methods) == 0 {
			return os.NewError("ssh: no authentication methods configured but NoClientAuth is also false")
		}

		if err = c.writePacket(marshal(msgUserAuthFailure, failureMsg)); err != nil {
			return err
		}
	}

	packet = []byte{msgUserAuthSuccess}
	if err = c.writePacket(packet); err != nil {
		return err
	}

	return nil
}

// testPubKey returns true if the given public key is acceptable for the user.
func (c *Conn) testPubKey(user, algo string, pubKey []byte) bool {
	result := c.config.PubKeyCallback(user, algo, pubKey)
	return result
}

func (c *Conn) clientHandshake() os.Error {
	var magics handshakeMagics

	// send client version
	if _, err := c.transport.Write(versionString); err != nil {
		return err
	}
	if err := c.transport.Flush(); err != nil {
		return err
	}
	magics.clientVersion = versionString[:len(versionString)-2]

	// read remote server version
	version, ok := readVersion(c.transport)
	if !ok {
		return os.NewError("failed to read version string from string")
	}
	magics.serverVersion = version

	clientKexInit := kexInitMsg{
		KexAlgos:                c.config.SupportedKexAlgos,
		ServerHostKeyAlgos:      c.config.SupportedHostKeyAlgos,
		CiphersClientServer:     c.config.SupportedCiphers,
		CiphersServerClient:     c.config.SupportedCiphers,
		MACsClientServer:        c.config.SupportedMACs,
		MACsServerClient:        c.config.SupportedMACs,
		CompressionClientServer: c.config.SupportedCompressions,
		CompressionServerClient: c.config.SupportedCompressions,
	}
	kexInitPacket := marshal(msgKexInit, clientKexInit)
	magics.clientKexInit = kexInitPacket

	if err := c.writePacket(kexInitPacket); err != nil {
		return err
	}

	packet, err := c.readPacket()
	if err != nil {
		return err
	}

	magics.serverKexInit = packet

	var serverKexInit kexInitMsg
	if err = unmarshal(&serverKexInit, packet, msgKexInit); err != nil {
		return err
	}

	kexAlgo, hostKeyAlgo, ok := findAgreedAlgorithms(c.transport, c.transport, &clientKexInit, &serverKexInit)
	if !ok {
		return os.NewError("ssh: no common algorithms")
	}

	if serverKexInit.FirstKexFollows && kexAlgo != serverKexInit.KexAlgos[0] {
		// The server sent a Kex message for the wrong algorithm,
		// which we have to ignore.
		if _, err := c.readPacket(); err != nil {
			return err
		}
	}

	var H, K []byte
	var hashFunc crypto.Hash
	switch kexAlgo {
	case kexAlgoDH14SHA1:
		hashFunc = crypto.SHA1
		dhGroup14Once.Do(initDHGroup14)
		H, K, err = c.clientKexDH(dhGroup14, hashFunc, &magics, hostKeyAlgo)
	default:
		err = os.NewError("ssh: internal error")
	}
	if err != nil {
		return err
	}

	if err = c.writePacket([]byte{msgNewKeys}); err != nil {
		return err
	}
	if err = c.transport.writer.setupKeys(clientKeys, K, H, H, hashFunc); err != nil {
		return err
	}

	if packet, err = c.readPacket(); err != nil {
		return err
	}
	if packet[0] != msgNewKeys {
		return UnexpectedMessageError{msgNewKeys, packet[0]}
	}

	c.transport.reader.setupKeys(serverKeys, K, H, H, hashFunc)

	if err := c.sendServiceReq(serviceUserAuth); err != nil {
		return err
	}

	if packet, err = c.readPacket(); err != nil {
		return err
	}

	var serviceAccept serviceAcceptMsg
	if err = unmarshal(&serviceAccept, packet, msgServiceAccept); err != nil {
		return err
	}

	if err := c.sendUserAuthReq("none"); err != nil {
		return err
	}

	if packet, err = c.readPacket(); err != nil {
		return err
	}

	if packet[0] != msgUserAuthSuccess {
		return UnexpectedMessageError{msgUserAuthSuccess, packet[0]}
	}
	return nil
}

func (c *Conn) sendServiceReq(name string) os.Error {
	packet := marshal(msgServiceRequest, serviceRequestMsg{name})
	return c.writePacket(packet)
}

func (c *Conn) sendUserAuthReq(method string) os.Error {
	length := stringLength([]byte(c.config.Password)) + 1
	payload := make([]byte, length)
	marshalString(payload[1:], []byte(c.config.Password)) // payload[0] == 0 == boolean:false

	return c.writePacket(marshal(msgUserAuthRequest, userAuthRequestMsg{
		User:    c.config.User,
		Service: serviceSSH,
		Method:  method,
		Payload: payload,
	}))
}

// clientKexDH performs Diffie-Hellman key agreement on a ClientConnection. The
// returned values are given the same names as in RFC 4253, section 8.
func (c *Conn) clientKexDH(group *dhGroup, hashFunc crypto.Hash, magics *handshakeMagics, hostKeyAlgo string) ([]byte, []byte, os.Error) {
	x, err := rand.Int(rand.Reader, group.p)
	if err != nil {
		return nil, nil, err
	}
	X := new(big.Int).Exp(group.g, x, group.p)
	kexDHInit := kexDHInitMsg{
		X: X,
	}
	if err := c.writePacket(marshal(msgKexDHInit, kexDHInit)); err != nil {
		return nil, nil, err
	}

	packet, err := c.readPacket()
	if err != nil {
		return nil, nil, err
	}

	var kexDHReply = new(kexDHReplyMsg)
	if err = unmarshal(kexDHReply, packet, msgKexDHReply); err != nil {
		return nil, nil, err
	}

	if kexDHReply.Y.Sign() == 0 || kexDHReply.Y.Cmp(group.p) >= 0 {
		return nil, nil, os.NewError("server DH parameter out of bounds")
	}

	kInt := new(big.Int).Exp(kexDHReply.Y, x, group.p)
	h := hashFunc.New()
	writeString(h, magics.clientVersion)
	writeString(h, magics.serverVersion)
	writeString(h, magics.clientKexInit)
	writeString(h, magics.serverKexInit)
	writeString(h, kexDHReply.HostKey)
	writeInt(h, X)
	writeInt(h, kexDHReply.Y)
	K := make([]byte, intLength(kInt))
	marshalInt(K, kInt)
	h.Write(K)

	H := h.Sum()

	return H, K, nil
}

func Dial(addr string, config *Config) (*Conn, os.Error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	client := newConn(conn, config)
	if err := client.clientHandshake(); err != nil {
		defer client.Close()
		return nil, err
	}
	return client, nil
}

type Listener struct {
	listener net.Listener
	config   *Config
}

// Accept waits for and returns the next incoming SSH connection.
// The reciever should call Handshake() in another
// goroutine to avoid blocking the accepter
func (l *Listener) Accept() (*Conn, os.Error) {
	c, err := l.listener.Accept()
	if err != nil {
		return nil, err
	}
	conn := newConn(c, l.config)
	conn.isServer = true
	return conn, nil
}

func (l *Listener) Addr() net.Addr {
	return l.listener.Addr()
}

// Close closes the listener.
func (l *Listener) Close() os.Error {
	return l.listener.Close()
}

func Listen(laddr string, config *Config) (*Listener, os.Error) {
	l, err := net.Listen("tcp", laddr)
	if err != nil {
		return nil, err
	}
	return &Listener{
		l,
		config,
	}, nil
}

type Config struct {
	rsa           *rsa.PrivateKey
	rsaSerialized []byte

	// NoClientAuth is true if clients are allowed to connect without
	// authenticating.
	NoClientAuth bool

	// PasswordCallback, if non-nil, is called when a user attempts to
	// authenticate using a password. It may be called concurrently from
	// several goroutines.
	PasswordCallback func(user, password string) bool

	// PubKeyCallback, if non-nil, is called when a client attempts public
	// key authentication. It must return true iff the given public key is
	// valid for the given user.
	PubKeyCallback func(user, algo string, pubkey []byte) bool

	User     string
	Password string // used for "password" method authentication

	SupportedKexAlgos, SupportedHostKeyAlgos, SupportedCiphers, SupportedMACs, SupportedCompressions []string
}

// SetRSAPrivateKey sets the private key for a Server. A Server must have a
// private key configured in order to accept connections. The private key must
// be in the form of a PEM encoded, PKCS#1, RSA private key. The file "id_rsa"
// typically contains such a key.
func (c *Config) SetRSAPrivateKey(pemBytes []byte) os.Error {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return os.NewError("ssh: no key found")
	}
	var err os.Error
	c.rsa, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}

	c.rsaSerialized = marshalRSA(c.rsa)
	return nil
}
