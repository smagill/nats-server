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
	"net"
	"strconv"
	"sync"
)

type srvMQTT struct {
	mu       sync.RWMutex
	listener net.Listener
	tls      bool
}

func (s *Server) startMQTT() {
	sopts := s.getOpts()
	o := &sopts.MQTT

	var hl net.Listener
	var err error

	port := o.Port
	if port == -1 {
		port = 0
	}
	hp := net.JoinHostPort(o.Host, strconv.Itoa(port))

	if o.TLSConfig != nil {
		config := o.TLSConfig.Clone()
		hl, err = tls.Listen("tcp", hp, config)
	} else {
		hl, err = net.Listen("tcp", hp)
	}
	if err != nil {
		s.Fatalf("Unable to listen for MQTT connections: %v", err)
		return
	}
	s.Noticef("Listening for MQTT clients on %s:%d", o.Host, port)

	s.mu.Lock()
	s.mqtt.tls = o.TLSConfig != nil
	if port == 0 {
		o.Port = hl.Addr().(*net.TCPAddr).Port
	}
	s.mqtt.listener = hl
	s.mu.Unlock()

	s.startGoRoutine(func() {
		defer s.grWG.Done()

		tmpDelay := ACCEPT_MIN_SLEEP

		for s.isRunning() {
			conn, err := hl.Accept()
			if err != nil {
				tmpDelay = s.acceptError("MQTT", err, tmpDelay)
				continue
			}
			tmpDelay = ACCEPT_MIN_SLEEP
			s.startGoRoutine(func() {
				s.createMQTTClient(conn)
				s.grWG.Done()
			})
		}
		s.Debugf("MQTT accept loop exiting..")
		s.done <- true
	})
}

func (s *Server) createMQTTClient(nc net.Conn) {
	s.mqtt.mu.RLock()
	tlsReq := s.mqtt.tls
	s.mqtt.mu.RUnlock()

	if tlsReq {
		if err := nc.(*tls.Conn).Handshake(); err != nil {
			s.Errorf("TLS handshake error: %v", err)
			nc.Close()
			return
		}
	}
	nc.Close()
}
