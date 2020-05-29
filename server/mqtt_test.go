// Copyright 2020 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func testMQTTDefaultOptions() *Options {
	o := DefaultOptions()
	o.Cluster.Port = 0
	o.Gateway.Name = ""
	o.Gateway.Port = 0
	o.LeafNode.Port = 0
	o.Websocket.Port = 0
	o.MQTT.Host = "127.0.0.1"
	o.MQTT.Port = -1
	return o
}

func testMQTTDefaultTLSOptions(t *testing.T, verify bool) *Options {
	t.Helper()
	o := testMQTTDefaultOptions()
	tc := &TLSConfigOpts{
		CertFile: "../test/configs/certs/server-cert.pem",
		KeyFile:  "../test/configs/certs/server-key.pem",
		CaFile:   "../test/configs/certs/ca.pem",
		Verify:   verify,
		Timeout:  2.0,
	}
	var err error
	o.MQTT.TLSConfig, err = GenTLSConfig(tc)
	if err != nil {
		t.Fatalf("Error creating tls config: %v", err)
	}
	return o
}

func TestMQTTConfig(t *testing.T) {
	conf := createConfFile(t, []byte(`
		mqtt {
			port: -1
			tls {
				cert_file: "./configs/certs/server.pem"
				key_file: "./configs/certs/key.pem"
			}
		}
	`))
	defer os.Remove(conf)
	s, o := RunServerWithConfig(conf)
	defer s.Shutdown()
	if o.MQTT.TLSConfig == nil {
		t.Fatal("expected TLS config to be set")
	}
}

func TestMQTTStart(t *testing.T) {
	o := testMQTTDefaultOptions()
	s := RunServer(o)
	defer s.Shutdown()

	nc, err := net.Dial("tcp", fmt.Sprintf("%s:%d", o.MQTT.Host, o.MQTT.Port))
	if err != nil {
		t.Fatalf("Unable to create tcp connection to mqtt port: %v", err)
	}
	nc.Close()

	// Check failure to start due to port in use
	o2 := testMQTTDefaultOptions()
	o2.MQTT.Port = o.MQTT.Port
	s2, err := NewServer(o2)
	if err != nil {
		t.Fatalf("Error creating server: %v", err)
	}
	defer s2.Shutdown()
	l := &captureFatalLogger{fatalCh: make(chan string, 1)}
	s2.SetLogger(l, false, false)

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		s2.Start()
		wg.Done()
	}()

	select {
	case e := <-l.fatalCh:
		if !strings.Contains(e, "Unable to listen for MQTT connections") {
			t.Fatalf("Unexpected error: %q", e)
		}
	case <-time.After(time.Second):
		t.Fatal("Should have gotten a fatal error")
	}
}

func TestMQTTStartTLS(t *testing.T) {
	o := testMQTTDefaultTLSOptions(t, false)
	s := RunServer(o)
	defer s.Shutdown()

	nc, err := net.Dial("tcp", fmt.Sprintf("%s:%d", o.MQTT.Host, o.MQTT.Port))
	if err != nil {
		t.Fatalf("Unable to create tcp connection to mqtt port: %v", err)
	}
	defer nc.Close()
	// Set MaxVersion to TLSv1.2 so that we fail on handshake if there is
	// a disagreement between server and client.
	tlsc := &tls.Config{
		MaxVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
	}
	tlsConn := tls.Client(nc, tlsc)
	tlsConn.SetDeadline(time.Now().Add(time.Second))
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("Error doing tls handshake: %v", err)
	}
	nc.Close()
	s.Shutdown()

	// Force client cert verification
	o = testMQTTDefaultTLSOptions(t, true)
	s = RunServer(o)
	defer s.Shutdown()

	nc, err = net.Dial("tcp", fmt.Sprintf("%s:%d", o.MQTT.Host, o.MQTT.Port))
	if err != nil {
		t.Fatalf("Unable to create tcp connection to mqtt port: %v", err)
	}
	defer nc.Close()
	// Set MaxVersion to TLSv1.2 so that we fail on handshake if there is
	// a disagreement between server and client.
	tlsc = &tls.Config{
		MaxVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
	}
	tlsConn = tls.Client(nc, tlsc)
	tlsConn.SetDeadline(time.Now().Add(time.Second))
	if err := tlsConn.Handshake(); err == nil {
		t.Fatal("Handshake expected to fail since client did not provide cert")
	}
	nc.Close()

	// Add client cert.
	nc, err = net.Dial("tcp", fmt.Sprintf("%s:%d", o.MQTT.Host, o.MQTT.Port))
	if err != nil {
		t.Fatalf("Unable to create tcp connection to mqtt port: %v", err)
	}
	defer nc.Close()
	// Set MaxVersion to TLSv1.2 so that we fail on handshake if there is
	// a disagreement between server and client.
	cert, err := tls.LoadX509KeyPair("../test/configs/certs/client-cert.pem", "../test/configs/certs/client-key.pem")
	if err != nil {
		t.Fatalf("error loading client certificate: %v", err)
	}
	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("error parsing client certificate: %v", err)
	}
	tlsc = &tls.Config{
		MaxVersion:         tls.VersionTLS12,
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
	}
	tlsConn = tls.Client(nc, tlsc)
	tlsConn.SetDeadline(time.Now().Add(time.Second))
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("Handshake error: %v", err)
	}
}
