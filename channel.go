// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"bytes"
	"encoding/binary"
	"os"
)

// Base channel type to be embedded in other exported types
type channel struct {
	id, peerId	uint32
	in	chan interface{}	// incoming messages for this channel
	transport	// the underlying transport for this channel
}

func (c *channel) Close() os.Error {
        if err := c.sendMessage(msgChannelClose, channelCloseMsg{
                PeersId: c.peerId,
        }); err != nil {
                return err
        }
        switch resp := (<-c.in).(type) {
        case channelCloseMsg:
                return nil
        }
        panic("error")
}

// Pass an environment variable to a channel to be applied
// to any shell/command started later
func (c *channel) Setenv(name, value string) os.Error {
        namLen := stringLength([]byte(name))
        valLen := stringLength([]byte(value))
        payload := make([]byte, namLen+valLen)
        marshalString(payload[:namLen], []byte(name))
        marshalString(payload[namLen:], []byte(value))

        if err := c.sendMessage(msgChannelRequest, channelRequestMsg{
                PeersId:             c.peerId,
                Request:             "env",
                WantReply:           true,
                RequestSpecificData: payload,
        }); err != nil {
                return err
        }
        switch resp := (<-c.in).(type) {
        case channelRequestSuccessMsg:
                return nil
        case channelRequestFailureMsg:
                return os.NewError("unable to set env var \"" + name + "\"")
        }
        panic("unreachable")
}

// Request a pty to be allocated on the remote side for this channel
func (c *channel) PtyReq(term string, h, w int) os.Error {
        b := new(bytes.Buffer)
        binary.Write(b, binary.BigEndian, uint32(len(term)))
        binary.Write(b, binary.BigEndian, term)
        binary.Write(b, binary.BigEndian, uint32(h))
        binary.Write(b, binary.BigEndian, uint32(w))
        binary.Write(b, binary.BigEndian, uint32(h*8))
        binary.Write(b, binary.BigEndian, uint32(w*8))
        b.Write([]byte{0, 0, 0, 1, 0, 0, 0, 0, 0}) // empty mode list

        if err := c.sendMessage(msgChannelRequest, channelRequestMsg{
                PeersId:             c.peerId,
                Request:             "pty-req",
                WantReply:           true,
                RequestSpecificData: b.Bytes(),
        }); err != nil {
                return err
        }
        switch resp := (<-c.in).(type) {
        case channelRequestSuccessMsg:
                return nil
        case channelRequestFailureMsg:
                return os.NewError("unable to request a pty")
        }
        panic("unreachable")
}

func (c *channel) Exec(command string) os.Error {
        cmdLen := stringLength([]byte(command))
        payload := make([]byte, cmdLen)
        marshalString(payload, []byte(command))
        if err := c.sendMessage(msgChannelRequest, channelRequestMsg{
                PeersId:             c.peerId,
                Request:             "exec",
                WantReply:           true,
                RequestSpecificData: payload,
        }); err != nil {
                return err
        }
        switch resp := (<-c.in).(type) {
        case channelRequestSuccessMsg:
                return nil
        case channelRequestFailureMsg:
                return os.NewError("unable to execure \"" + command + "\"")
        }
        panic("unreachable")
}

