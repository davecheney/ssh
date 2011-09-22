# Copyright 2011 The Go Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

include ../../../Make.inc

TARG=exp/ssh
GOFILES=\
	client.go\
	common.go\
	messages.go\
	transport.go\
        channel.go\

include ../../../Make.pkg
