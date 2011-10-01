// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"big"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"net"
)

// Represents the server side of a ssh connection.
type ServerConn struct {
	*transport
	config *ServerConfig
	nextChanId uint32
	channels   map[uint32]*channel
}

func (c *ServerConn) sendVersion(version []byte) os.Error {
	if _, err := c.Write(version); err != nil {
		return err
	}
	return c.Flush()
}

// Accept reads and processes messages on a Conn. It must be called
// in order to demultiplex messages to any resulting Channels.
func (s *ServerConn) Accept() (Channel, os.Error) {
	for {
		packet, err := s.readPacket()
		if err != nil {
			for _, c := range s.channels {
				c.dead = true
				c.handleData(nil)
			}

			return nil, err
		}

		switch msg := decode(packet).(type) {
		case *channelOpenMsg:
			c := &channel{
				chanType:      msg.ChanType,
				theirId:       msg.PeersId,
				theirWindow:   msg.PeersWindow,
				maxPacketSize: msg.MaxPacketSize,
				extraData:     msg.TypeSpecificData,
				myWindow:      defaultWindowSize,
				transport:     s.transport,
				pendingData:   make([]byte, defaultWindowSize),
				myId:          s.nextChanId,
			}
			s.nextChanId++
			s.channels[c.myId] = c
			return c, nil

		case *channelRequestMsg:
			c, ok := s.channels[msg.PeersId]
			if !ok {
				continue
			}
			c.handlePacket(msg)

		case *channelData:
			c, ok := s.channels[msg.PeersId]
			if !ok {
				continue
			}
			c.handleData(msg.Payload)

		case *channelEOFMsg:
			c, ok := s.channels[msg.PeersId]
			if !ok {
				continue
			}
			c.handlePacket(msg)

		case *channelCloseMsg:
			c, ok := s.channels[msg.PeersId]
			if !ok {
				continue
			}
			c.handlePacket(msg)

		case *globalRequestMsg:
			if msg.WantReply {
				if err := s.writePacket([]byte{msgRequestFailure}); err != nil {
					return nil, err
				}
			}

		case UnexpectedMessageError:
			return nil, msg
		case *disconnectMsg:
			return nil, os.EOF
		default:
			// Unknown message. Ignore.
		}
	}

	panic("unreachable")
}

// Construct a new Conn in server mode.
func newServerConn(c net.Conn, config *ServerConfig) *ServerConn {
	conn := &ServerConn{
		transport: newTransport(c),
		channels:  make(map[uint32]*channel),
		config: config,
	}
	return conn
}

func (c *ServerConn) Handshake() os.Error {
	var magics handshakeMagics
	if err := c.sendVersion(versionString); err != nil {
		return err
	}
	magics.serverVersion = versionString[:len(versionString)-2]

	version, ok := readVersion(c)
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

	kexAlgo, hostKeyAlgo, ok := findAgreedAlgorithms(c.transport, &clientKexInit, &serverKexInit)
	if !ok {
		return os.NewError("ssh: no common algorithms")
	}

	if clientKexInit.FirstKexFollows && kexAlgo != clientKexInit.KexAlgos[0] {
		// The client sent a Kex message for the wrong algorithm,
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
		H, K, err = c.kexDH(dhGroup14, hashFunc, &magics, hostKeyAlgo)
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

// KexDH performs Diffie-Hellman key agreement on a ServerConnection. The
// returned values are given the same names as in RFC 4253, section 8.
func (c *ServerConn) kexDH(group *dhGroup, hashFunc crypto.Hash, magics *handshakeMagics, hostKeyAlgo string) (H, K []byte, err os.Error) {
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
	err = c.writePacket(marshal(msgKexDHReply, kexDHReply))
	return
}

func (c *ServerConn) authenticate(H []byte) os.Error {
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
func (c *ServerConn) testPubKey(user, algo string, pubKey []byte) bool {
	result := c.config.PubKeyCallback(user, algo, pubKey)
	return result
}

type Listener struct {
	listener net.Listener
	config   *ServerConfig
}

// Accept waits for and returns the next incoming ssh connection.
// The reciever should call Handshake() in another
// goroutine to avoid blocking the accepter
func (l *Listener) Accept() (*ServerConn, os.Error) {
	c, err := l.listener.Accept()
	if err != nil {
		return nil, err
	}
	conn := newServerConn(c, l.config)
	return conn, nil
}

func (l *Listener) Addr() net.Addr {
	return l.listener.Addr()
}

// Close the listener.
func (l *Listener) Close() os.Error {
	return l.listener.Close()
}

// Open a new tcp socket on laddr and return a listener
// which can be used to Accept incoming ssh connections.
func Listen(laddr string, config *ServerConfig) (*Listener, os.Error) {
	l, err := net.Listen("tcp", laddr)
	if err != nil {
		return nil, err
	}
	return &Listener{
		l,
		config,
	}, nil
}

// A ServerConfig structure is used to configure a ssh listener. After one
// has been passed to a TLS function it must not be modified.
type ServerConfig struct {
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

	SupportedKexAlgos, SupportedHostKeyAlgos, SupportedCiphers, SupportedMACs, SupportedCompressions []string
}

// SetRSAPrivateKey sets the private key for a Server. A Server must have a
// private key configured in order to accept connections. The private key must
// be in the form of a PEM encoded, PKCS#1, RSA private key. The file "id_rsa"
// typically contains such a key.
func (c *ServerConfig) SetRSAPrivateKey(pemBytes []byte) os.Error {
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
