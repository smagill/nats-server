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
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/nats-io/nuid"
	"io"
	"net"
	"strconv"
	"time"
	"unicode/utf8"
)

// References to "spec" here is from https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.pdf

const (
	mqttPacketConnect    = byte(0x10)
	mqttPacketConnectAck = byte(0x20)
	mqttPacketPub        = byte(0x30)
	mqttPacketPubAck     = byte(0x40)
	mqttPacketPubRec     = byte(0x50)
	mqttPacketPubRel     = byte(0x60)
	mqttPacketPubComp    = byte(0x70)
	mqttPacketSub        = byte(0x80)
	mqttPacketSubAck     = byte(0x90)
	mqttPacketUnsub      = byte(0xa0)
	mqttPacketUnsubAck   = byte(0xb0)
	mqttPacketPing       = byte(0xc0)
	mqttPacketPingResp   = byte(0xd0)
	mqttPacketDisconnect = byte(0xe0)
	mqttPacketMask       = byte(0xf0)
	mqttPacketFlagMask   = byte(0x0f)

	mqttProtoLevel = byte(0x4)

	// Connect flags
	mqttConnFlagReserved     = byte(0x0)
	mqttConnFlagCleanSession = byte(0x2)
	mqttConnFlagWillFlag     = byte(0x04)
	mqttConnFlagWillQoS      = byte(0x18)
	mqttConnFlagWillRetain   = byte(0x20)
	mqttConnFlagPasswordFlag = byte(0x40)
	mqttConnFlagUsernameFlag = byte(0x80)

	// Publish flags
	mqttPubFlagRetain = byte(0x01)
	mqttPubFlagQoS    = byte(0x06)
	mqttPubFlagDup    = byte(0x08)

	// Subscribe flags
	mqttSubscribeFlags = byte(0x2)

	// ConnAck returned codes
	mqttConnAckRCConnectionAccepted          = byte(0x0)
	mqttConnAckRCUnacceptableProtocolVersion = byte(0x1)
	mqttConnAckRCIdentifierRejected          = byte(0x2)
	mqttConnAckRCServerUnavailable           = byte(0x3)
	mqttConnAckRCBadUserOrPassword           = byte(0x4)
	mqttConnAckRCNotAuthorized               = byte(0x5)

	// Topic/Filter characters
	mqttTopicLevelSep = '/'
	mqttSingleLevelWC = '+'
	mqttMultiLevelWC  = '#'
)

var (
	mqttPingResponse = []byte{mqttPacketPingResp, 0x0}
	mqttProtoName    = []byte("MQTT")
	mqttOldProtoName = []byte("MQIsdp")
)

type srvMQTT struct {
	listener     net.Listener
	authOverride bool
	nkeys        map[string]*NkeyUser
	users        map[string]*User
}

type mqtt struct {
	r     *mqttReader
	cp    *mqttConnectProto
	sessp bool // session present
}

type mqttConnectProto struct {
	clientID string
	rd       time.Duration
	will     *mqttWill
	flags    byte
}

type mqttReader struct {
	reader io.Reader
	buf    []byte
	pos    int
}

type mqttWriter struct {
	bytes.Buffer
}

type mqttWill struct {
	topic   []byte
	message []byte
	qos     byte
	retain  bool
}

type mqttFilter struct {
	filter []byte
	copied bool
	qos    byte
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
	s.mu.Lock()
	if s.shutdown {
		s.mu.Unlock()
		return
	}
	hl, err = net.Listen("tcp", hp)
	if err != nil {
		s.mu.Unlock()
		s.Fatalf("Unable to listen for MQTT connections: %v", err)
		return
	}
	if port == 0 {
		o.Port = hl.Addr().(*net.TCPAddr).Port
	}
	s.mqtt.listener = hl
	scheme := "mqtt"
	if o.TLSConfig != nil {
		scheme = "tls"
	}
	s.Noticef("Listening for MQTT clients on %s://%s:%d", scheme, o.Host, o.Port)
	go s.acceptConnections(hl, "MQTT", func(conn net.Conn) { s.createClient(conn, nil, &mqtt{}) }, nil)
	s.mu.Unlock()
}

// Given the mqtt options, we check if any auth configuration
// has been provided. If so, possibly create users/nkey users and
// store them in s.mqtt.users/nkeys.
// Also update a boolean that indicates if auth is required for
// mqtt clients.
// Server lock is held on entry.
func (s *Server) mqttConfigAuth(opts *MQTTOpts) {
	mqtt := &s.mqtt
	if len(opts.Users) > 0 {
		_, mqtt.users = s.buildNkeysAndUsersFromOptions(nil, opts.Users)
		mqtt.authOverride = true
	} else if opts.Username != "" || opts.Token != "" {
		mqtt.authOverride = true
	} else {
		mqtt.users = nil
		mqtt.nkeys = nil
		mqtt.authOverride = false
	}
}

// Validate the mqtt related options.
func validateMQTTOptions(o *Options) error {
	mo := &o.MQTT
	// If no port is defined, we don't care about other options
	if mo.Port == 0 {
		return nil
	}
	// If there is a NoAuthUser, we need to have Users defined and
	// the user to be present.
	if mo.NoAuthUser != _EMPTY_ {
		if mo.Users == nil {
			return fmt.Errorf("mqtt no_auth_user %q configured, but users are not", mo.NoAuthUser)
		}
		for _, u := range mo.Users {
			if u.Username == mo.NoAuthUser {
				return nil
			}
		}
		return fmt.Errorf("mqtt no_auth_user %q not found in users configuration", mo.NoAuthUser)
	}
	return nil
}

// Parse protocols inside the given buffer.
// This is invoked from the readLoop.
func (c *client) mqttParse(buf []byte) error {
	c.mu.Lock()
	s := c.srv
	trace := c.trace
	connected := c.flags.isSet(connectReceived)
	mqtt := c.mqtt
	r := mqtt.r
	var rd time.Duration
	if mqtt.cp != nil {
		rd = mqtt.cp.rd
		if rd > 0 {
			if nc, ok := r.reader.(net.Conn); ok {
				nc.SetReadDeadline(time.Time{})
			}
		}
	}
	c.mu.Unlock()

	r.reset(buf)

	var err error
	var b byte
	var pl int

	for err == nil && r.hasMore() {

		// Read packet type and flags
		if b, err = r.readByte("packet type"); err != nil {
			break
		}

		// Packet type
		pt := b & mqttPacketMask

		// If client was not connected yet, the first packet must be
		// a mqttPacketConnect otherwise we fail the connection.
		if !connected && pt != mqttPacketConnect {
			err = errors.New("not connected")
			break
		}

		if pl, err = r.readPacketLen(); err != nil {
			break
		}

		switch pt {
		case mqttPacketPub:
			var pi uint16
			var pqos byte
			pi, pqos, err = c.mqttParsePub(r, b, pl)
			if trace {
				c.traceInOp("PUB", errOrTrace(err, c.mqttPubTrace(pi, pqos)))
				if err == nil {
					c.traceMsg(c.msgBuf)
				}
			}
			if err == nil {
				c.mqttProcessPub(pi, pqos)
			}
		case mqttPacketPubAck:
			// if p, err = pkg.ParsePubAck(r, b, rl); err == nil {
			// 	c.Debug("received", p)
			// 	id := p.(pkg.PubAck).ID()
			// 	c.session.ClientAckReceived(id, c.natsConn)
			// 	c.server.ReleasePacketID(id)
			// }
		case mqttPacketSub:
			var pi uint16 // packet identifier
			var filters []*mqttFilter
			pi, filters, err = c.mqttParseSubs(r, b, pl)
			if trace {
				c.traceInOp("SUB", errOrTrace(err, mqttSubscribeTrace(filters)))
			}
			if err == nil {
				err = c.mqttProcessSubs(pi, filters)
			}
		// case mqttPacketUnsub:
		// if p, err = pkg.ParseUnsubscribe(r, b, rl); err == nil {
		// 	c.Debug("received", p)
		// 	c.natsUnsubscribe(p.(*pkg.Unsubscribe))
		// }
		case mqttPacketPing:
			if trace {
				c.traceInOp("PING", nil)
			}
			c.mqttEnqueuePingResp()
			if trace {
				c.traceOutOp("PONG", nil)
			}
		case mqttPacketConnect:
			// It is an error to receive a second connect packet
			if connected {
				err = errors.New("second connect packet")
				break
			}
			var rc byte
			var cp *mqttConnectProto
			rc, cp, err = c.mqttParseConnect(r, pl)
			if trace {
				c.traceInOp("CONNECT", errOrTrace(err, c.mqttConnectTrace(cp)))
			}
			if err == nil {
				rc, rd, err = s.mqttProcessConnect(c, cp)
				if err == nil {
					connected = true
				}
			}
			// We need to send a ConnAck on success or if we are given a return code.
			if err == nil || rc != 0 {
				c.mqttEnqueueConnAck(rc)
			}
			// The readLoop will not call closeConnection for this error...
			if err == ErrAuthentication {
				c.closeConnection(AuthenticationViolation)
			}
		case mqttPacketDisconnect:
			// Normal disconnect, we need to discard the will.
			// Spec [MQTT-3.1.2-8]
			c.mu.Lock()
			if c.mqtt.cp != nil {
				c.mqtt.cp.will = nil
			}
			c.mu.Unlock()
			c.closeConnection(ClientClosed)
			return nil
		case mqttPacketPubRec:
			fallthrough
		case mqttPacketPubRel:
			fallthrough
		case mqttPacketPubComp:
			err = fmt.Errorf("protocol %d not supported", pt>>4)
		default:
			err = fmt.Errorf("received unknown packet type %d", pt>>4)
		}
	}
	if err == nil && rd > 0 {
		if nc, ok := r.reader.(net.Conn); ok {
			nc.SetReadDeadline(time.Now().Add(rd))
		}
	}
	return err
}

//////////////////////////////////////////////////////////////////////////////
//
// CONNECT protocol related functions
//
//////////////////////////////////////////////////////////////////////////////

// Parse the MQTT connect protocol
func (c *client) mqttParseConnect(r *mqttReader, pl int) (byte, *mqttConnectProto, error) {

	// Make sure that we have the expected length in the buffer,
	// and if not, this will read it from the underlying reader.
	if err := r.ensurePacketInBuffer(pl); err != nil {
		return 0, nil, err
	}

	// Protocol name
	proto, err := r.readBytes("protocol name", false)
	if err != nil {
		return 0, nil, err
	}

	// Spec [MQTT-3.1.2-1]
	if !bytes.Equal(proto, mqttProtoName) {
		// Check proto name against v3.1 to report better error
		if bytes.Equal(proto, mqttOldProtoName) {
			return 0, nil, fmt.Errorf("older protocol %q not supported", proto)
		}
		return 0, nil, fmt.Errorf("expected connect packet with protocol name %q, got %q", mqttProtoName, proto)
	}

	// Protocol level
	level, err := r.readByte("protocol level")
	if err != nil {
		return 0, nil, nil
	}
	// Spec [MQTT-3.1.2-2]
	if level != mqttProtoLevel {
		return mqttConnAckRCUnacceptableProtocolVersion, nil, fmt.Errorf("unacceptable protocol version of %v", level)
	}

	cp := &mqttConnectProto{}
	// Connect flags
	cp.flags, err = r.readByte("flags")
	if err != nil {
		return 0, nil, err
	}

	// Spec [MQTT-3.1.2-3]
	if cp.flags&mqttConnFlagReserved != 0 {
		return 0, nil, fmt.Errorf("connect flags reserved bit not set to 0")
	}

	var hasWill bool
	wqos := (cp.flags & mqttConnFlagWillQoS) >> 3
	wretain := cp.flags&mqttConnFlagWillRetain != 0
	// Spec [MQTT-3.1.2-11]
	if cp.flags&mqttConnFlagWillFlag == 0 {
		// Spec [MQTT-3.1.2-13]
		if wqos != 0 {
			return 0, nil, fmt.Errorf("if Will flag is set to 0, Will QoS must be 0 too, got %v", wqos)
		}
		// Spec [MQTT-3.1.2-15]
		if wretain {
			return 0, nil, fmt.Errorf("if Will flag is set to 0, Will Retain flag must be 0 too")
		}
	} else {
		// Spec [MQTT-3.1.2-14]
		if wqos == 3 {
			return 0, nil, fmt.Errorf("if Will flag is set to 1, Will QoS can be 0, 1 or 2, got %v", wqos)
		}
		hasWill = true
	}

	// Spec [MQTT-3.1.2-19]
	hasUser := cp.flags&mqttConnFlagUsernameFlag != 0
	// Spec [MQTT-3.1.2-21]
	hasPassword := cp.flags&mqttConnFlagPasswordFlag != 0
	// Spec [MQTT-3.1.2-22]
	if !hasUser && hasPassword {
		return 0, nil, fmt.Errorf("password flag set but username flag is not")
	}

	// Keep alive
	var ka uint16
	ka, err = r.readUint16("keep alive")
	if err != nil {
		return 0, nil, err
	}
	// Spec [MQTT-3.1.2-24]
	if ka > 0 {
		cp.rd = time.Duration(float64(ka)*1.5) * time.Second
	}

	// Payload starts here and order is mandated by:
	// Spec [MQTT-3.1.3-1]: client ID, will topic, will message, username, password

	// Client ID
	cp.clientID, err = r.readString("client ID")
	if err != nil {
		return 0, nil, err
	}
	// Spec [MQTT-3.1.3-7]
	if cp.clientID == _EMPTY_ {
		if cp.flags&mqttConnFlagCleanSession == 0 {
			return mqttConnAckRCIdentifierRejected, nil, fmt.Errorf("when client ID is empty, clean session flag must be set to 1")
		}
		// Spec [MQTT-3.1.3-6]
		cp.clientID = nuid.Next()
	}
	// Spec [MQTT-3.1.3-4] and [MQTT-3.1.3-9]
	if !utf8.ValidString(cp.clientID) {
		return mqttConnAckRCIdentifierRejected, nil, fmt.Errorf("invalid utf8 for client ID: %q", cp.clientID)
	}

	if hasWill {
		cp.will = &mqttWill{
			qos:    wqos,
			retain: wretain,
		}
		var topic []byte
		topic, err = r.readBytes("Will topic", false)
		if err != nil {
			return 0, nil, err
		}
		if len(topic) == 0 {
			return 0, nil, fmt.Errorf("empty Will topic not allowed")
		}
		if !utf8.Valid(topic) {
			return 0, nil, fmt.Errorf("invalide utf8 for Will topic %q", topic)
		}
		// Convert MQTT topic to NATS subject
		_, topic, err = mqttTopicToNATSPubSubject(topic, true)
		if err != nil {
			return 0, nil, err
		}
		cp.will.topic = topic
		// Now will message
		cp.will.message, err = r.readBytes("Will message", true)
		if err != nil {
			return 0, nil, err
		}
	}

	if hasUser {
		c.opts.Username, err = r.readString("user name")
		if err != nil {
			return 0, nil, err
		}
		// Spec [MQTT-3.1.3-11]
		if !utf8.ValidString(c.opts.Username) {
			return mqttConnAckRCBadUserOrPassword, nil, fmt.Errorf("invalid utf8 for username %q", c.opts.Username)
		}
	}

	if hasPassword {
		c.opts.Password, err = r.readString("password")
		if err != nil {
			return 0, nil, err
		}
		c.opts.Token = c.opts.Password
	}
	return 0, cp, nil
}

func (c *client) mqttConnectTrace(cp *mqttConnectProto) string {
	trace := fmt.Sprintf("clientID=%s", cp.clientID)
	if cp.rd > 0 {
		trace += fmt.Sprintf(" keepAlive=%v", cp.rd)
	}
	if cp.will != nil {
		trace += fmt.Sprintf(" will=(topic=%s QoS=%v retain=%v)",
			cp.will.topic, cp.will.qos, cp.will.retain)
	}
	if c.opts.Username != _EMPTY_ {
		trace += fmt.Sprintf(" username=%s", c.opts.Username)
	}
	if c.opts.Password != _EMPTY_ {
		trace += " password=****"
	}
	return trace
}

func (s *Server) mqttProcessConnect(c *client, cp *mqttConnectProto) (byte, time.Duration, error) {
	if !s.isClientAuthorized(c) {
		return mqttConnAckRCNotAuthorized, 0, ErrAuthentication
	}
	c.mu.Lock()
	c.flags.set(connectReceived)
	c.mqtt.cp = cp
	rd := c.mqtt.cp.rd
	c.mu.Unlock()
	return mqttConnAckRCConnectionAccepted, rd, nil
}

func (c *client) mqttEnqueueConnAck(rc byte) {
	proto := [4]byte{mqttPacketConnectAck, 2, 0, rc}
	c.mu.Lock()
	if c.mqtt.sessp {
		proto[2] = 1
	}
	c.queueOutbound(proto[:])
	c.flushSignal()
	c.mu.Unlock()
}

//////////////////////////////////////////////////////////////////////////////
//
// PUBLISH protocol related functions
//
//////////////////////////////////////////////////////////////////////////////

func (c *client) mqttParsePub(r *mqttReader, flags byte, pl int) (uint16, byte, error) {
	flags = flags & mqttPacketFlagMask
	qos := (flags & mqttPubFlagQoS) >> 1
	if qos > 1 {
		return 0, 0, fmt.Errorf("publish QoS=%v not supported", qos)
	}
	if err := r.ensurePacketInBuffer(pl); err != nil {
		return 0, 0, err
	}
	// Keep track of where we are when starting to read the variable header
	start := r.pos

	var topic []byte
	var err error
	topic, err = r.readBytes("topic", false)
	if err != nil {
		return 0, 0, err
	}
	// We don't ask for a copy since after processing of the publish,
	// we don't need the subject anymore. However, the conversion may
	// still return a copy if had to expand the subject due to the
	// MQTT specific topic name rules.
	_, topic, err = mqttTopicToNATSPubSubject(topic, false)
	if err != nil {
		return 0, 0, err
	}
	c.pa.subject = topic
	c.pa.hdr = -1

	var id uint16
	if qos > 0 {
		id, err = r.readUint16("QoS")
		if err != nil {
			return 0, 0, err
		}
	}

	c.msgBuf = nil
	// The message payload will be the total packet length minus
	// what we have consumed for the variable header
	c.pa.size = pl - (r.pos - start)
	c.msgBuf = make([]byte, 0, c.pa.size+2)
	if c.pa.size > 0 {
		start = r.pos
		r.pos += c.pa.size
		c.msgBuf = append(c.msgBuf, r.buf[start:r.pos]...)
	}
	c.pa.szb = []byte(strconv.FormatInt(int64(c.pa.size), 10))
	c.msgBuf = append(c.msgBuf, _CRLF_...)
	return id, qos, nil
}

func (c *client) mqttPubTrace(pi uint16, qos byte) string {
	trace := fmt.Sprintf("%s", c.pa.subject)
	if pi > 0 {
		trace += fmt.Sprintf(" pid=%v", pi)
	}
	trace += fmt.Sprintf(" %v", len(c.msgBuf)-LEN_CR_LF)
	return trace
}

func (c *client) mqttProcessPub(pi uint16, qos byte) {
	c.processInboundClientMsg(c.msgBuf)
	c.msgBuf, c.pa.subject, c.pa.hdr, c.pa.size, c.pa.szb = nil, nil, -1, 0, nil
}

func mqttWritePublish(w *mqttWriter, qos byte, dup, retain bool, subject string, pid uint16, payload []byte) {
	flags := qos << 1
	if dup {
		flags |= mqttPubFlagDup
	}
	if retain {
		flags |= mqttPubFlagRetain
	}
	w.WriteByte(mqttPacketPub | flags)
	pkLen := 2 + len(subject) + len(payload)
	if qos > 0 {
		pkLen += 2
	}
	w.WriteVarInt(pkLen)
	w.WriteString(subject)
	if qos > 0 {
		w.WriteUint16(pid)
	}
	w.Write([]byte(payload))
}

//////////////////////////////////////////////////////////////////////////////
//
// SUBSCRIBE related functions
//
//////////////////////////////////////////////////////////////////////////////

func (c *client) mqttParseSubs(r *mqttReader, b byte, pl int) (uint16, []*mqttFilter, error) {
	// Spec [MQTT-3.8.1-1]
	if rf := b & 0xf; rf != mqttSubscribeFlags {
		return 0, nil, fmt.Errorf("wrong subscribe reserved flags: %x", rf)
	}
	if err := r.ensurePacketInBuffer(pl); err != nil {
		return 0, nil, err
	}
	start := r.pos
	pi, err := r.readUint16("packet identifier")
	if err != nil {
		return 0, nil, fmt.Errorf("reading packet identifier: %v", err)
	}
	end := start + (pl - 2)
	var filters []*mqttFilter
	for r.pos < end {
		// Don't make a copy now because the conversion function will.
		filter, err := r.readBytes("topic filter", false)
		if err != nil {
			return 0, nil, err
		}
		// Spec [MQTT-3.8.3-1]
		if !utf8.Valid(filter) {
			return 0, nil, fmt.Errorf("invalid utf8 for topic filter %q", filter)
		}
		var cp bool
		cp, filter, err = mqttFilterToNATSSubject(filter, false)
		if err != nil {
			return 0, nil, err
		}
		qos, err := r.readByte("QoS")
		if err != nil {
			return 0, nil, err
		}
		// Spec [MQTT-3-8.3-4].
		if qos > 2 {
			return 0, nil, fmt.Errorf("subscribe QoS value must be 0, 1 or 2, got %v", qos)
		}
		filters = append(filters, &mqttFilter{filter, cp, qos})
	}
	// Spec [MQTT-3.8.3-3]
	if len(filters) == 0 {
		return 0, nil, fmt.Errorf("subscribe protocol must contain at least 1 topic filter")
	}
	return pi, filters, nil
}

func mqttSubscribeTrace(filters []*mqttFilter) string {
	var sep string
	trace := "["
	for i, f := range filters {
		trace += sep + fmt.Sprintf("%s QoS=%v", f.filter, f.qos)
		if i == 0 {
			sep = ", "
		}
	}
	trace += "]"
	return trace
}

func (c *client) mqttProcessSubs(pi uint16, filters []*mqttFilter) error {
	return nil
}

//////////////////////////////////////////////////////////////////////////////
//
// PINGREQ/PINGRESP related functions
//
//////////////////////////////////////////////////////////////////////////////

func (c *client) mqttEnqueuePingResp() {
	c.mu.Lock()
	c.queueOutbound(mqttPingResponse)
	c.flushSignal()
	c.mu.Unlock()
}

//////////////////////////////////////////////////////////////////////////////
//
// Trace functions
//
//////////////////////////////////////////////////////////////////////////////

func errOrTrace(err error, trace string) []byte {
	if err != nil {
		return []byte(err.Error())
	}
	return []byte(trace)
}

//////////////////////////////////////////////////////////////////////////////
//
// Subject/Topic conversion functions
//
//////////////////////////////////////////////////////////////////////////////

// Converts an MQTT Topic Name to a NATS Subject (used by PUBLISH)
// See mqttToNATSSubjectConversion() for details.
func mqttTopicToNATSPubSubject(mt []byte, cp bool) (bool, []byte, error) {
	return mqttToNATSSubjectConversion(mt, cp, false)
}

// Converts an MQTT Topic Filter to a NATS Subject (used by SUBSCRIBE)
// See mqttToNATSSubjectConversion() for details.
//
// Differences with NATS: in MQTT, subscribing to "foo/#" is not entirely
// equivalent to "foo.>" because in MQTT, foo/bar matches "foo/#", but so
// does "foo/" or "foo".
func mqttFilterToNATSSubject(filter []byte, cp bool) (bool, []byte, error) {
	return mqttToNATSSubjectConversion(filter, cp, true)
}

// Converts an MQTT Topic Name or Filter to a NATS Subject
// In MQTT:
// - a Topic Name does not have wildcard (PUBLISH uses only topic names).
// - a Topic Filter can include wildcards (SUBSCRIBE uses those).
// - '+' and '#' are wildcard characters (single and multiple levels respectively)
// - '/' is the topic level separator.
//
// Conversion that occurs:
// - '/' is replaced with '/.' is it is the first but not only character in mt
// - '/' is replaced with './' is it is the last but not only character in mt
// - '/' is left intact if it is the first and only character in mt
// - '/' is replaced with '.' for all other conditions
// - '.' is replaced with '/'
//
// If `cp` is true, a copy is returned. If not, the returned slice
// may still be a copy of `mt` due to the rules described above. In that
// case the first returned field indicates if the result is a copy or not.
func mqttToNATSSubjectConversion(mt []byte, cp, wcOk bool) (bool, []byte, error) {
	if len(mt) == 1 {
		if mt[0] == btsep {
			mt[0] = mqttTopicLevelSep
		}
		if cp {
			return true, copyBytes(mt), nil
		}
		return false, mt, nil
	}
	var res = mt
	var resSize = len(mt)
	var newSlice bool
	if mt[0] == mqttTopicLevelSep {
		resSize++
		newSlice = true
	}
	if mt[len(mt)-1] == mqttTopicLevelSep {
		resSize++
		newSlice = true
	}
	if newSlice {
		res = make([]byte, resSize)
	}
	for i, j := 0, 0; i < len(mt); i++ {
		switch mt[i] {
		case btsep:
			res[j] = mqttTopicLevelSep
		case mqttTopicLevelSep:
			// If the MQTT topic starts with '/'
			if i == 0 {
				// Replace with '/.'
				res[0] = mqttTopicLevelSep
				res[1] = btsep
				j = 1 // it will be bumped outside the switch statement.
			} else {
				res[j] = btsep
				if i == len(mt)-1 {
					j++
					res[j] = mqttTopicLevelSep
				}
			}
		case '+', '#':
			if !wcOk {
				// Spec [MQTT-3.3.2-2] and [MQTT-4.7.1-1]
				// The wildcard characters can be used in Topic Filters, but MUST NOT be used within a Topic Name
				return false, nil, fmt.Errorf("wildcards not allowed in publish's topic: %q", mt)
			}
			if mt[i] == mqttSingleLevelWC {
				res[j] = pwc
			} else {
				res[j] = fwc
			}
		default:
			res[j] = mt[i]
		}
		j++
	}
	// Not asked to copy, return res and indicate if this is actually a copy
	if !cp {
		return newSlice, res, nil
	}
	// If we are asked to copy but we had to create a new slice, it
	// is already copied, so return 'res'
	if newSlice {
		return true, res, nil
	}
	// Return a copy of res (which is same than mt).
	return true, copyBytes(res), nil
}

//////////////////////////////////////////////////////////////////////////////
//
// MQTT Reader functions
//
//////////////////////////////////////////////////////////////////////////////

func copyBytes(b []byte) []byte {
	cbuf := make([]byte, len(b))
	copy(cbuf, b)
	return cbuf
}

func (r *mqttReader) reset(buf []byte) {
	r.buf = buf
	r.pos = 0
}

func (r *mqttReader) hasMore() bool {
	return r.pos != len(r.buf)
}

func (r *mqttReader) readByte(field string) (byte, error) {
	if r.pos == len(r.buf) {
		return 0, fmt.Errorf("error reading %s: %v", field, io.EOF)
	}
	b := r.buf[r.pos]
	r.pos++
	return b, nil
}

func (r *mqttReader) readPacketLen() (int, error) {
	m := 1
	v := 0
	for {
		var b byte
		if r.pos != len(r.buf) {
			b = r.buf[r.pos]
			r.pos++
		} else {
			var buf [1]byte
			if _, err := r.reader.Read(buf[:1]); err != nil {
				if err == io.EOF {
					return 0, io.ErrUnexpectedEOF
				}
				return 0, fmt.Errorf("error reading packet length: %v", err)
			}
			b = buf[0]
		}
		v += int(b&0x7f) * m
		if (b & 0x80) == 0 {
			return v, nil
		}
		m *= 0x80
		if m > 0x200000 {
			return 0, errors.New("malformed variable int")
		}
	}
}

func (r *mqttReader) ensurePacketInBuffer(pl int) error {
	rem := len(r.buf) - r.pos
	if rem >= pl {
		return nil
	}
	b := make([]byte, pl)
	start := copy(b, r.buf[r.pos:])
	for start != pl {
		n, err := r.reader.Read(b[start:cap(b)])
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return fmt.Errorf("error ensuring protocol is loaded: %v", err)
		}
		start += n
	}
	r.reset(b)
	return nil
}

func (r *mqttReader) readString(field string) (string, error) {
	var s string
	bs, err := r.readBytes(field, false)
	if err == nil {
		s = string(bs)
	}
	return s, err
}

func (r *mqttReader) readBytes(field string, cp bool) ([]byte, error) {
	luint, err := r.readUint16(field)
	if err != nil {
		return nil, err
	}
	l := int(luint)
	if l == 0 {
		return nil, nil
	}
	start := r.pos
	if start+l > len(r.buf) {
		return nil, fmt.Errorf("error reading %s: %v", field, io.ErrUnexpectedEOF)
	}
	r.pos += l
	b := r.buf[start:r.pos]
	if cp {
		b = copyBytes(b)
	}
	return b, nil
}

func (r *mqttReader) readUint16(field string) (uint16, error) {
	if len(r.buf)-r.pos < 2 {
		return 0, fmt.Errorf("error reading %s: %v", field, io.ErrUnexpectedEOF)
	}
	start := r.pos
	r.pos += 2
	return binary.BigEndian.Uint16(r.buf[start:r.pos]), nil
}

//////////////////////////////////////////////////////////////////////////////
//
// MQTT Writer functions
//
//////////////////////////////////////////////////////////////////////////////

func (w *mqttWriter) WriteUint16(i uint16) {
	w.WriteByte(byte(i >> 8))
	w.WriteByte(byte(i))
}

func (w *mqttWriter) WriteString(s string) {
	w.WriteBytes([]byte(s))
}

func (w *mqttWriter) WriteBytes(bs []byte) {
	w.WriteUint16(uint16(len(bs)))
	w.Write(bs)
}

func (w *mqttWriter) WriteVarInt(value int) {
	for {
		b := byte(value & 0x7f)
		value >>= 7
		if value > 0 {
			b |= 0x80
		}
		w.WriteByte(b)
		if value == 0 {
			break
		}
	}
}
