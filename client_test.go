// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"log"
	"testing"
	"os"
)

func TestClientConnect(t *testing.T) {
	config := &ClientConfig{
		User:                  os.Getenv("USER"),
		Password:              os.Getenv("PASSWD"),
		SupportedKexAlgos:     supportedKexAlgos,
		SupportedHostKeyAlgos: supportedHostKeyAlgos,
		SupportedCiphers:      supportedCiphers,
		SupportedMACs:         supportedMACs,
		SupportedCompressions: supportedCompressions,
	}
	conn, err := Dial("localhost:22", config)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("%#v", config)
	defer conn.Close()
	ch, err := conn.OpenChan("session")
	if err != nil {
		log.Fatal(err)
	}
	defer ch.Close()
	if err := ch.Setenv("LANG", "C"); err != nil {
		log.Fatal(err)
	}
	if err := ch.Ptyreq("vt100", 80, 24); err != nil {
		log.Fatal(err)
	}
	if err := ch.Exec("/bin/cat"); err != nil {
		log.Fatal(err)
	}
	if _, err := ch.Write([]byte("Hello world!")); err != nil {
		log.Fatal(err)
	}
	buf := make([]byte, 1024)
	read, err := ch.Read(nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(string(buf[:read]))
}
