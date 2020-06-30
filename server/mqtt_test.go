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
	"bufio"
	"crypto/tls"
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
	}
	var err error
	o.MQTT.TLSConfig, err = GenTLSConfig(tc)
	o.MQTT.TLSTimeout = 2.0
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

func TestMQTTTLS(t *testing.T) {
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

	tc := &TLSConfigOpts{
		CertFile: "../test/configs/certs/client-cert.pem",
		KeyFile:  "../test/configs/certs/client-key.pem",
	}
	tlsc, err = GenTLSConfig(tc)
	if err != nil {
		t.Fatalf("Error generating tls config: %v", err)
	}
	tlsc.InsecureSkipVerify = true
	tlsConn = tls.Client(nc, tlsc)
	tlsConn.SetDeadline(time.Now().Add(time.Second))
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("Handshake error: %v", err)
	}
	nc.Close()
	s.Shutdown()

	// Lower TLS timeout so low that we should fail
	o.MQTT.TLSTimeout = 0.001
	s = RunServer(o)
	defer s.Shutdown()

	nc, err = net.Dial("tcp", fmt.Sprintf("%s:%d", o.MQTT.Host, o.MQTT.Port))
	if err != nil {
		t.Fatalf("Unable to create tcp connection to mqtt port: %v", err)
	}
	defer nc.Close()
	time.Sleep(100 * time.Millisecond)
	tlsConn = tls.Client(nc, tlsc)
	tlsConn.SetDeadline(time.Now().Add(time.Second))
	if err := tlsConn.Handshake(); err == nil {
		t.Fatal("Expected failure, did not get one")
	}
}

type mqttConnInfo struct {
	clientID  string
	cleanSess bool
	keepAlive uint16
	will      *mqttWill
	user      string
	pass      string
}

func testMQTTRead(c net.Conn) ([]byte, error) {
	var buf [512]byte
	// Make sure that test does not block
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := c.Read(buf[:])
	if err != nil {
		return nil, err
	}
	c.SetReadDeadline(time.Time{})
	return copyBytes(buf[:n]), nil
}

func testMQTTConnect(t testing.TB, ci *mqttConnInfo, host string, port int) (net.Conn, *mqttReader) {
	t.Helper()

	addr := fmt.Sprintf("%s:%d", host, port)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Error creating mqtt connection: %v", err)
	}

	proto := mqttCreateConnectProto(ci)
	if _, err := c.Write(proto); err != nil {
		t.Fatalf("Error writing connect: %v", err)
	}

	buf, err := testMQTTRead(c)
	if err != nil {
		t.Fatalf("Error reading: %v", err)
	}
	br := &mqttReader{reader: c}
	br.reset(buf)

	return c, br
}

func mqttCreateConnectProto(ci *mqttConnInfo) []byte {
	flags := byte(0)
	if ci.cleanSess {
		flags |= mqttConnFlagCleanSession
	}
	if ci.will != nil {
		flags |= mqttConnFlagWillFlag | (ci.will.qos << 3)
		if ci.will.retain {
			flags |= mqttConnFlagWillRetain
		}
	}
	if ci.user != _EMPTY_ {
		flags |= mqttConnFlagUsernameFlag
	}
	if ci.pass != _EMPTY_ {
		flags |= mqttConnFlagPasswordFlag
	}

	pkLen := 2 + len(mqttProtoName) +
		1 + // proto level
		1 + // flags
		2 + // keepAlive
		2 + len(ci.clientID)

	if ci.will != nil {
		pkLen += 2 + len(ci.will.topic)
		pkLen += 2 + len(ci.will.message)
	}
	if ci.user != _EMPTY_ {
		pkLen += 2 + len(ci.user)
	}
	if ci.pass != _EMPTY_ {
		pkLen += 2 + len(ci.pass)
	}

	w := &mqttWriter{}
	w.WriteByte(mqttPacketConnect)
	w.WriteVarInt(pkLen)
	w.WriteString(string(mqttProtoName))
	w.WriteByte(0x4)
	w.WriteByte(flags)
	w.WriteUint16(ci.keepAlive)
	w.WriteString(ci.clientID)
	if ci.will != nil {
		w.WriteBytes(ci.will.topic)
		w.WriteBytes(ci.will.message)
	}
	if ci.user != _EMPTY_ {
		w.WriteString(ci.user)
	}
	if ci.pass != _EMPTY_ {
		w.WriteBytes([]byte(ci.pass))
	}
	return w.Bytes()
}

func testMQTTCheckConnAck(t testing.TB, r *mqttReader, rc byte, sessionPresent bool) {
	t.Helper()
	r.reader.SetReadDeadline(time.Now().Add(2 * time.Second))
	if err := r.ensurePacketInBuffer(4); err != nil {
		t.Fatalf("Error ensuring packet in buffer: %v", err)
	}
	r.reader.SetReadDeadline(time.Time{})
	b, err := r.readByte("connack packet type")
	if err != nil {
		t.Fatalf("Error reading packet type: %v", err)
	}
	pt := b & mqttPacketMask
	if pt != mqttPacketConnectAck {
		t.Fatalf("Expected ConnAck (%x), got %x", mqttPacketConnectAck, pt)
	}
	pl, err := r.readByte("connack packet len")
	if err != nil {
		t.Fatalf("Error reading packet length: %v", err)
	}
	if pl != 2 {
		t.Fatalf("ConnAck packet length should be 2, got %v", pl)
	}
	caf, err := r.readByte("connack flags")
	if err != nil {
		t.Fatalf("Error reading packet length: %v", err)
	}
	if caf&0xfe != 0 {
		t.Fatalf("ConnAck flag bits 7-1 should all be 0, got %x", caf>>1)
	}
	if sp := caf == 1; sp != sessionPresent {
		t.Fatalf("Expected session present flag=%v got %v", sessionPresent, sp)
	}
	carc, err := r.readByte("connack return code")
	if err != nil {
		t.Fatalf("Error reading returned code: %v", err)
	}
	if carc != rc {
		t.Fatalf("Expected return code to be %v, got %v", rc, carc)
	}
}

func TestMQTTTLSVerifyAndMap(t *testing.T) {
	accName := "MyAccount"
	acc := NewAccount(accName)
	certUserName := "CN=example.com,OU=NATS.io"
	users := []*User{&User{Username: certUserName, Account: acc}}

	for _, test := range []struct {
		name        string
		mqttUsers   bool
		provideCert bool
	}{
		{"no users override, client provides cert", false, true},
		{"no users override, client does not provide cert", false, false},
		{"users override, client provides cert", true, true},
		{"users override, client does not provide cert", true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			o := testMQTTDefaultOptions()
			o.Host = "localhost"
			o.Accounts = []*Account{acc}
			if test.mqttUsers {
				o.MQTT.Users = users
			} else {
				o.Users = users
			}
			tc := &TLSConfigOpts{
				CertFile: "../test/configs/certs/tlsauth/server.pem",
				KeyFile:  "../test/configs/certs/tlsauth/server-key.pem",
				CaFile:   "../test/configs/certs/tlsauth/ca.pem",
				Verify:   true,
			}
			tlsc, err := GenTLSConfig(tc)
			if err != nil {
				t.Fatalf("Error creating tls config: %v", err)
			}
			o.MQTT.TLSConfig = tlsc
			o.MQTT.TLSTimeout = 2.0
			o.MQTT.TLSMap = true
			s := RunServer(o)
			defer s.Shutdown()

			addr := fmt.Sprintf("%s:%d", o.MQTT.Host, o.MQTT.Port)
			mc, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatalf("Error creating ws connection: %v", err)
			}
			defer mc.Close()
			tlscc := &tls.Config{}
			if test.provideCert {
				tc := &TLSConfigOpts{
					CertFile: "../test/configs/certs/tlsauth/client.pem",
					KeyFile:  "../test/configs/certs/tlsauth/client-key.pem",
				}
				var err error
				tlscc, err = GenTLSConfig(tc)
				if err != nil {
					t.Fatalf("Error generating tls config: %v", err)
				}
			}
			tlscc.InsecureSkipVerify = true
			if test.provideCert {
				tlscc.MinVersion = tls.VersionTLS13
			}
			mc = tls.Client(mc, tlscc)
			if err := mc.(*tls.Conn).Handshake(); err != nil {
				t.Fatalf("Error during handshake: %v", err)
			}

			ci := &mqttConnInfo{cleanSess: true}
			proto := mqttCreateConnectProto(ci)
			if _, err := mc.Write(proto); err != nil {
				t.Fatalf("Error sending proto: %v", err)
			}
			buf, err := testMQTTRead(mc)
			if !test.provideCert {
				if err == nil {
					t.Fatal("Expected error, did not get one")
				} else if !strings.Contains(err.Error(), "bad certificate") {
					t.Fatalf("Unexpected error: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Error reading: %v", err)
			}
			r := &mqttReader{reader: mc}
			r.reset(buf)
			testMQTTCheckConnAck(t, r, mqttConnAckRCConnectionAccepted, false)

			var c *client
			s.mu.Lock()
			for _, sc := range s.clients {
				sc.mu.Lock()
				if sc.mqtt != nil {
					c = sc
				}
				sc.mu.Unlock()
				if c != nil {
					break
				}
			}
			s.mu.Unlock()
			if c == nil {
				t.Fatal("Client not found")
			}

			var uname string
			var accname string
			c.mu.Lock()
			uname = c.opts.Username
			if c.acc != nil {
				accname = c.acc.GetName()
			}
			c.mu.Unlock()
			if uname != certUserName {
				t.Fatalf("Expected username %q, got %q", certUserName, uname)
			}
			if accname != accName {
				t.Fatalf("Expected account %q, got %v", accName, accname)
			}
		})
	}
}

func TestMQTTBasicAuth(t *testing.T) {
	for _, test := range []struct {
		name string
		opts func() *Options
		user string
		pass string
		rc   byte
	}{
		{
			"top level auth, no override, wrong u/p",
			func() *Options {
				o := testMQTTDefaultOptions()
				o.Username = "normal"
				o.Password = "client"
				return o
			},
			"mqtt", "client", mqttConnAckRCNotAuthorized,
		},
		{
			"top level auth, no override, correct u/p",
			func() *Options {
				o := testMQTTDefaultOptions()
				o.Username = "normal"
				o.Password = "client"
				return o
			},
			"normal", "client", mqttConnAckRCConnectionAccepted,
		},
		{
			"no top level auth, mqtt auth, wrong u/p",
			func() *Options {
				o := testMQTTDefaultOptions()
				o.MQTT.Username = "mqtt"
				o.MQTT.Password = "client"
				return o
			},
			"normal", "client", mqttConnAckRCNotAuthorized,
		},
		{
			"no top level auth, mqtt auth, correct u/p",
			func() *Options {
				o := testMQTTDefaultOptions()
				o.MQTT.Username = "mqtt"
				o.MQTT.Password = "client"
				return o
			},
			"mqtt", "client", mqttConnAckRCConnectionAccepted,
		},
		{
			"top level auth, mqtt override, wrong u/p",
			func() *Options {
				o := testMQTTDefaultOptions()
				o.Username = "normal"
				o.Password = "client"
				o.MQTT.Username = "mqtt"
				o.MQTT.Password = "client"
				return o
			},
			"normal", "client", mqttConnAckRCNotAuthorized,
		},
		{
			"top level auth, mqtt override, correct u/p",
			func() *Options {
				o := testMQTTDefaultOptions()
				o.Username = "normal"
				o.Password = "client"
				o.MQTT.Username = "mqtt"
				o.MQTT.Password = "client"
				return o
			},
			"mqtt", "client", mqttConnAckRCConnectionAccepted,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			o := test.opts()
			s := RunServer(o)
			defer s.Shutdown()

			ci := &mqttConnInfo{
				cleanSess: true,
				user:      test.user,
				pass:      test.pass,
			}
			mc, r := testMQTTConnect(t, ci, o.MQTT.Host, o.MQTT.Port)
			defer mc.Close()
			testMQTTCheckConnAck(t, r, test.rc, false)
		})
	}
}

func TestMQTTAuthTimeout(t *testing.T) {
	for _, test := range []struct {
		name string
		at   float64
		mat  float64
		ok   bool
	}{
		{"use top-level auth timeout", 10.0, 0.0, true},
		{"use mqtt auth timeout", 10.0, 0.05, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			o := testMQTTDefaultOptions()
			o.AuthTimeout = test.at
			o.MQTT.Username = "mqtt"
			o.MQTT.Password = "client"
			o.MQTT.AuthTimeout = test.mat
			s := RunServer(o)
			defer s.Shutdown()

			mc, err := net.Dial("tcp", fmt.Sprintf("%s:%d", o.MQTT.Host, o.MQTT.Port))
			if err != nil {
				t.Fatalf("Error connecting: %v", err)
			}
			defer mc.Close()

			time.Sleep(100 * time.Millisecond)

			ci := &mqttConnInfo{
				cleanSess: true,
				user:      "mqtt",
				pass:      "client",
			}
			proto := mqttCreateConnectProto(ci)
			if _, err := mc.Write(proto); err != nil {
				if test.ok {
					t.Fatalf("Error sending connect: %v", err)
				}
				// else it is ok since we got disconnected due to auth timeout
				return
			}
			buf, err := testMQTTRead(mc)
			if err != nil {
				if test.ok {
					t.Fatalf("Error reading: %v", err)
				}
				// else it is ok since we got disconnected due to auth timeout
				return
			}
			r := &mqttReader{reader: mc}
			r.reset(buf)
			testMQTTCheckConnAck(t, r, mqttConnAckRCConnectionAccepted, false)
		})
	}
}

func TestMQTTTokenAuth(t *testing.T) {
	for _, test := range []struct {
		name  string
		opts  func() *Options
		token string
		rc    byte
	}{
		{
			"top level auth, no override, wrong token",
			func() *Options {
				o := testMQTTDefaultOptions()
				o.Authorization = "goodtoken"
				return o
			},
			"badtoken", mqttConnAckRCNotAuthorized,
		},
		{
			"top level auth, no override, correct token",
			func() *Options {
				o := testMQTTDefaultOptions()
				o.Authorization = "goodtoken"
				return o
			},
			"goodtoken", mqttConnAckRCConnectionAccepted,
		},
		{
			"no top level auth, mqtt auth, wrong token",
			func() *Options {
				o := testMQTTDefaultOptions()
				o.MQTT.Token = "goodtoken"
				return o
			},
			"badtoken", mqttConnAckRCNotAuthorized,
		},
		{
			"no top level auth, mqtt auth, correct token",
			func() *Options {
				o := testMQTTDefaultOptions()
				o.MQTT.Token = "goodtoken"
				return o
			},
			"goodtoken", mqttConnAckRCConnectionAccepted,
		},
		{
			"top level auth, mqtt override, wrong token",
			func() *Options {
				o := testMQTTDefaultOptions()
				o.Authorization = "clienttoken"
				o.MQTT.Token = "mqtttoken"
				return o
			},
			"clienttoken", mqttConnAckRCNotAuthorized,
		},
		{
			"top level auth, mqtt override, correct token",
			func() *Options {
				o := testMQTTDefaultOptions()
				o.Authorization = "clienttoken"
				o.MQTT.Token = "mqtttoken"
				return o
			},
			"mqtttoken", mqttConnAckRCConnectionAccepted,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			o := test.opts()
			s := RunServer(o)
			defer s.Shutdown()

			ci := &mqttConnInfo{
				cleanSess: true,
				user:      "ignore_use_token",
				pass:      test.token,
			}
			mc, r := testMQTTConnect(t, ci, o.MQTT.Host, o.MQTT.Port)
			defer mc.Close()
			testMQTTCheckConnAck(t, r, test.rc, false)
		})
	}
}

func TestMQTTUsersAuth(t *testing.T) {
	for _, test := range []struct {
		name string
		opts func() *Options
		user string
		pass string
		rc   byte
	}{
		{
			"top level auth, no override, wrong user",
			func() *Options {
				o := testMQTTDefaultOptions()
				o.Users = []*User{
					&User{Username: "normal1", Password: "client1"},
					&User{Username: "normal2", Password: "client2"},
				}
				return o
			},
			"mqtt", "client", mqttConnAckRCNotAuthorized,
		},
		{
			"top level auth, no override, correct user",
			func() *Options {
				o := testMQTTDefaultOptions()
				o.Users = []*User{
					&User{Username: "normal1", Password: "client1"},
					&User{Username: "normal2", Password: "client2"},
				}
				return o
			},
			"normal2", "client2", mqttConnAckRCConnectionAccepted,
		},
		{
			"no top level auth, mqtt auth, wrong user",
			func() *Options {
				o := testMQTTDefaultOptions()
				o.MQTT.Users = []*User{
					&User{Username: "mqtt1", Password: "client1"},
					&User{Username: "mqtt2", Password: "client2"},
				}
				return o
			},
			"mqtt", "client", mqttConnAckRCNotAuthorized,
		},
		{
			"no top level auth, mqtt auth, correct token",
			func() *Options {
				o := testMQTTDefaultOptions()
				o.MQTT.Users = []*User{
					&User{Username: "mqtt1", Password: "client1"},
					&User{Username: "mqtt2", Password: "client2"},
				}
				return o
			},
			"mqtt1", "client1", mqttConnAckRCConnectionAccepted,
		},
		{
			"top level auth, mqtt override, wrong user",
			func() *Options {
				o := testMQTTDefaultOptions()
				o.Users = []*User{
					&User{Username: "normal1", Password: "client1"},
					&User{Username: "normal2", Password: "client2"},
				}
				o.MQTT.Users = []*User{
					&User{Username: "mqtt1", Password: "client1"},
					&User{Username: "mqtt2", Password: "client2"},
				}
				return o
			},
			"normal2", "client2", mqttConnAckRCNotAuthorized,
		},
		{
			"top level auth, mqtt override, correct token",
			func() *Options {
				o := testMQTTDefaultOptions()
				o.Users = []*User{
					&User{Username: "normal1", Password: "client1"},
					&User{Username: "normal2", Password: "client2"},
				}
				o.MQTT.Users = []*User{
					&User{Username: "mqtt1", Password: "client1"},
					&User{Username: "mqtt2", Password: "client2"},
				}
				return o
			},
			"mqtt2", "client2", mqttConnAckRCConnectionAccepted,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			o := test.opts()
			s := RunServer(o)
			defer s.Shutdown()

			ci := &mqttConnInfo{
				cleanSess: true,
				user:      test.user,
				pass:      test.pass,
			}
			mc, r := testMQTTConnect(t, ci, o.MQTT.Host, o.MQTT.Port)
			defer mc.Close()
			testMQTTCheckConnAck(t, r, test.rc, false)
		})
	}
}

func TestMQTTNoAuthUserValidation(t *testing.T) {
	// It is illegal to configure a mqtt's NoAuthUser if mqtt's
	// auth config does not have a matching User.
	// Create regular clients's User to make sure that we fail even if
	// the mqtt's NoAuthUser is found in opts.Users.
	o := testMQTTDefaultOptions()
	o.Users = []*User{&User{Username: "user", Password: "pwd"}}
	o.MQTT.NoAuthUser = "user"
	if _, err := NewServer(o); err == nil || !strings.Contains(err.Error(), "users are not") {
		t.Fatalf("Expected error saying that users are not configured, got %v", err)
	}

	o.MQTT.Users = []*User{&User{Username: "msuser", Password: "pwd"}}
	o.MQTT.NoAuthUser = "notfound"
	if _, err := NewServer(o); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("Expected error saying no auth user not found, got %v", err)
	}
}

func TestMQTTNoAuthUser(t *testing.T) {
	for _, test := range []struct {
		name            string
		createMQTTUsers bool
		useAuth         bool
		expectedUser    string
		expectedAcc     string
	}{
		{"no override, no user provided", false, false, "noauth", "normal"},
		{"no override, user povided", false, true, "user", "normal"},
		{"override, no user provided", true, false, "mqttnoauth", "mqtt"},
		{"override, user provided", true, true, "mqttuser", "mqtt"},
	} {
		t.Run(test.name, func(t *testing.T) {
			o := testMQTTDefaultOptions()
			normalAcc := NewAccount("normal")
			mqttAcc := NewAccount("mqtt")
			o.Accounts = []*Account{normalAcc, mqttAcc}
			o.Users = []*User{
				&User{Username: "noauth", Password: "pwd", Account: normalAcc},
				&User{Username: "user", Password: "pwd", Account: normalAcc},
			}
			o.NoAuthUser = "noauth"
			if test.createMQTTUsers {
				o.MQTT.Users = []*User{
					&User{Username: "mqttnoauth", Password: "pwd", Account: mqttAcc},
					&User{Username: "mqttuser", Password: "pwd", Account: mqttAcc},
				}
				o.MQTT.NoAuthUser = "mqttnoauth"
			}
			s := RunServer(o)
			defer s.Shutdown()

			ci := &mqttConnInfo{cleanSess: true}
			if test.useAuth {
				ci.user = test.expectedUser
				ci.pass = "pwd"
			}
			mc, r := testMQTTConnect(t, ci, o.MQTT.Host, o.MQTT.Port)
			defer mc.Close()
			testMQTTCheckConnAck(t, r, mqttConnAckRCConnectionAccepted, false)

			var c *client
			s.mu.Lock()
			for _, sc := range s.clients {
				sc.mu.Lock()
				if sc.mqtt != nil {
					c = sc
				}
				sc.mu.Unlock()
				if c != nil {
					break
				}
			}
			s.mu.Unlock()
			if c == nil {
				t.Fatal("Client not found")
			}
			c.mu.Lock()
			uname := c.opts.Username
			aname := c.acc.GetName()
			c.mu.Unlock()
			if uname != test.expectedUser {
				t.Fatalf("Expected selected user to be %q, got %q", test.expectedUser, uname)
			}
			if aname != test.expectedAcc {
				t.Fatalf("Expected selected account to be %q, got %q", test.expectedAcc, aname)
			}
		})
	}
}

func TestMQTTPubMQTTSubNATS(t *testing.T) {
	o := testMQTTDefaultOptions()
	s := RunServer(o)
	defer s.Shutdown()

	nc := natsConnect(t, s.ClientURL())
	defer nc.Close()

	sub := natsSubSync(t, nc, ">")
	natsFlush(t, nc)

	mc, r := testMQTTConnect(t, &mqttConnInfo{cleanSess: true}, o.MQTT.Host, o.MQTT.Port)
	defer mc.Close()
	testMQTTCheckConnAck(t, r, mqttConnAckRCConnectionAccepted, false)

	for _, test := range []struct {
		name        string
		mqttTopic   string
		natsSubject string
	}{
		{"single level", "foo", "foo"},
		{"dot is slash", "foo.bar", "foo/bar"},
		{"slash is dot", "foo/bar", "foo.bar"},
		{"single slash remains slash", "/", "/"},
		{"slash first is slash dot", "/foo", "/.foo"},
		{"slash first is slash dot with several sep ", "/foo/bar", "/.foo.bar"},
		{"slash last is dot slash", "foo/", "foo./"},
		{"slash last is dot slash with several sep", "foo/bar/", "foo.bar./"},
		{"slash is first and last", "/foo/bar/baz/", "/.foo.bar.baz./"},
	} {
		t.Run(test.name, func(t *testing.T) {
			w := &mqttWriter{}
			mqttWritePublish(w, 0, false, false, test.mqttTopic, 0, []byte("hello"))
			if _, err := mc.Write(w.Bytes()); err != nil {
				t.Fatalf("Error publishing: %v", err)
			}
			msg := natsNexMsg(t, sub, time.Second)
			if msg.Subject != test.natsSubject {
				t.Fatalf("MQTT published on %q, expected NATS subject to be %q, got %q",
					test.mqttTopic, test.natsSubject, msg.Subject)
			}
		})
	}
}

// Benchmarks

func mqttBenchPub(b *testing.B, subject, payload string) {
	b.StopTimer()
	o := testMQTTDefaultOptions()
	s := RunServer(o)
	defer s.Shutdown()

	ci := &mqttConnInfo{cleanSess: true}
	c, br := testMQTTConnect(b, ci, o.MQTT.Host, o.MQTT.Port)
	testMQTTCheckConnAck(b, br, mqttConnAckRCConnectionAccepted, false)
	w := &mqttWriter{}
	mqttWritePublish(w, 0, false, false, subject, 0, []byte(payload))

	bw := bufio.NewWriterSize(c, 32768)
	sendOp := w.Bytes()
	b.SetBytes(int64(len(sendOp)))
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		bw.Write(sendOp)
	}
	w.Reset()
	w.WriteByte(mqttPacketPing)
	w.WriteByte(0)
	bw.Write(w.Bytes())
	bw.Flush()
	br.ensurePacketInBuffer(2)
	ab, err := br.readByte("pingresp")
	if err != nil {
		b.Fatalf("Error reading ping response: %v", err)
	}
	if pt := ab & mqttPacketMask; pt != mqttPacketPingResp {
		b.Fatalf("Expected ping response got %x", pt)
	}
	b.StopTimer()
	c.Close()
	s.Shutdown()
}

var mqttPubSubj = "a"

func BenchmarkMQTT_QoS0_____Pub0b_Payload(b *testing.B) {
	mqttBenchPub(b, mqttPubSubj, "")
}

func BenchmarkMQTT_QoS0_____Pub8b_Payload(b *testing.B) {
	mqttBenchPub(b, mqttPubSubj, sizedString(8))
}

func BenchmarkMQTT_QoS0____Pub32b_Payload(b *testing.B) {
	mqttBenchPub(b, mqttPubSubj, sizedString(32))
}

func BenchmarkMQTT_QoS0___Pub128b_Payload(b *testing.B) {
	mqttBenchPub(b, mqttPubSubj, sizedString(128))
}

func BenchmarkMQTT_QoS0___Pub256b_Payload(b *testing.B) {
	mqttBenchPub(b, mqttPubSubj, sizedString(256))
}

func BenchmarkMQTT_QoS1_____Pub1K_Payload(b *testing.B) {
	mqttBenchPub(b, mqttPubSubj, sizedString(1024))
}
