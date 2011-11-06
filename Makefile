# Copyright 2011 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

include $(GOROOT)/src/Make.inc

TARG=exp/ssh
GOFILES=\
	buffer.go\
	channel.go\
	client.go\
	client_auth.go\
	common.go\
	keychain.go\
	messages.go\
	tcpip.go\
	transport.go\
	server.go\
	server_shell.go\
	session.go\

include $(GOROOT)/src/Make.pkg
