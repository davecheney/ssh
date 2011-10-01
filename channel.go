// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"fmt"
	"io"
	"os"
)

// A Channel is an ordered, reliable, duplex stream that is multiplexed over an
// SSH connection.
type Channel interface {
	// Accept accepts the channel creation request.
	Accept() os.Error
	// Reject rejects the channel creation request. After calling this, no
	// other methods on the Channel may be called. If they are then the
	// peer is likely to signal a protocol error and drop the connection.
	Reject(reason RejectionReason, message string) os.Error

	// AckRequest either sends an ack or nack to the channel request.
	AckRequest(ok bool) os.Error

	// ChannelType returns the type of the channel, as supplied by the
	// client.
	ChannelType() string
	// ExtraData returns the arbitary payload for this channel, as supplied
	// by the client. This data is specific to the channel type.
	ExtraData() []byte

	io.ReadWriteCloser
}

// ChannelRequest represents a request sent on a channel, outside of the normal
// stream of bytes. It may result from calling Read on a Channel.
type ChannelRequest struct {
	Request   string
	WantReply bool
	Payload   []byte
}

func (c ChannelRequest) String() string {
	return "channel request received"
}

// RejectionReason is an enumeration used when rejecting channel creation
// requests. See RFC 4254, section 5.1.
type RejectionReason int

const (
	Prohibited RejectionReason = iota + 1
	ConnectionFailed
	UnknownChannelType
	ResourceShortage
)

type channel struct {
	// immutable once created
	chanType  string
	extraData []byte

	theyClosed  bool
	theySentEOF bool
	weClosed    bool
	dead        bool

	*transport
	myId, theirId         uint32
	myWindow, theirWindow uint32
	maxPacketSize         uint32

	pendingRequests []ChannelRequest
	pendingData     []byte
	head, length    int
}

func (c *channel) Accept() os.Error {
	confirm := channelOpenConfirmMsg{
		PeersId:       c.theirId,
		MyId:          c.myId,
		MyWindow:      c.myWindow,
		MaxPacketSize: c.maxPacketSize,
	}
	return c.writePacket(marshal(msgChannelOpenConfirm, confirm))
}

func (c *channel) Reject(reason RejectionReason, message string) os.Error {
	reject := channelOpenFailureMsg{
		PeersId:  c.theirId,
		Reason:   uint32(reason),
		Message:  message,
		Language: "en",
	}
	return c.writePacket(marshal(msgChannelOpenFailure, reject))
}

func (c *channel) handlePacket(packet interface{}) {
	switch packet := packet.(type) {
	case *channelRequestMsg:
		req := ChannelRequest{
			Request:   packet.Request,
			WantReply: packet.WantReply,
			Payload:   packet.RequestSpecificData,
		}
		c.pendingRequests = append(c.pendingRequests, req)
	case *channelCloseMsg:
		c.theyClosed = true
	case *channelEOFMsg:
		c.theySentEOF = true
	default:
		panic(fmt.Sprintf("Unknown message: %#v", packet))
	}
}

func (c *channel) handleData(data []byte) {
	// The other side should never send us more than our window.
	if len(data)+c.length > len(c.pendingData) {
		// TODO(agl): we should tear down the channel with a protocol
		// error.
		return
	}

	c.myWindow -= uint32(len(data))
	for i := 0; i < 2; i++ {
		tail := c.head + c.length
		if tail > len(c.pendingData) {
			tail -= len(c.pendingData)
		}
		n := copy(c.pendingData[tail:], data)
		data = data[n:]
		c.length += n
	}
}

func (c *channel) Read(data []byte) (n int, err os.Error) {
	if c.myWindow <= uint32(len(c.pendingData))/2 {
		packet := marshal(msgChannelWindowAdjust, windowAdjustMsg{
			PeersId:         c.theirId,
			AdditionalBytes: uint32(len(c.pendingData)) - c.myWindow,
		})
		if err := c.writePacket(packet); err != nil {
			return 0, err
		}
	}

	for {
		if c.theySentEOF || c.theyClosed || c.dead {
			return 0, os.EOF
		}

		if len(c.pendingRequests) > 0 {
			req := c.pendingRequests[0]
			if len(c.pendingRequests) == 1 {
				c.pendingRequests = nil
			} else {
				oldPendingRequests := c.pendingRequests
				c.pendingRequests = make([]ChannelRequest, len(oldPendingRequests)-1)
				copy(c.pendingRequests, oldPendingRequests[1:])
			}

			return 0, req
		}

		if c.length > 0 {
			tail := c.head + c.length
			if tail > len(c.pendingData) {
				tail -= len(c.pendingData)
			}
			n = copy(data, c.pendingData[c.head:tail])
			c.head += n
			c.length -= n
			if c.head == len(c.pendingData) {
				c.head = 0
			}
			return
		}
	}

	panic("unreachable")
}

func (c *channel) Write(data []byte) (n int, err os.Error) {
	for len(data) > 0 {
		if c.dead || c.weClosed {
			return 0, os.EOF
		}

		if c.theirWindow == 0 {
			continue
		}

		todo := data
		if uint32(len(todo)) > c.theirWindow {
			todo = todo[:c.theirWindow]
		}

		packet := make([]byte, 1+4+4+len(todo))
		packet[0] = msgChannelData
		packet[1] = byte(c.theirId) >> 24
		packet[2] = byte(c.theirId) >> 16
		packet[3] = byte(c.theirId) >> 8
		packet[4] = byte(c.theirId)
		packet[5] = byte(len(todo)) >> 24
		packet[6] = byte(len(todo)) >> 16
		packet[7] = byte(len(todo)) >> 8
		packet[8] = byte(len(todo))
		copy(packet[9:], todo)

		if err = c.writePacket(packet); err != nil {
			return
		}

		n += len(todo)
		data = data[len(todo):]
	}

	return
}

func (c *channel) Close() os.Error {
	if c.weClosed {
		return os.NewError("ssh: channel already closed")
	}
	c.weClosed = true

	closeMsg := channelCloseMsg{
		PeersId: c.theirId,
	}
	return c.writePacket(marshal(msgChannelClose, closeMsg))
}

func (c *channel) AckRequest(ok bool) os.Error {
	if ok {
		ack := channelRequestSuccessMsg{
			PeersId: c.theirId,
		}
		return c.writePacket(marshal(msgChannelSuccess, ack))
	} else {
		ack := channelRequestFailureMsg{
			PeersId: c.theirId,
		}
		return c.writePacket(marshal(msgChannelFailure, ack))
	}
	panic("unreachable")
}

func (c *channel) ChannelType() string {
	return c.chanType
}

func (c *channel) ExtraData() []byte {
	return c.extraData
}
