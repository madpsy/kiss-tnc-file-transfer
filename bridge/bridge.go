// bridge.go
package main

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.bug.st/serial"
)

// -----------------------------------------------------------------------------
// Global Pass‑Through Variables (for non‑loop mode)
// -----------------------------------------------------------------------------

var (
	// Pass‑through clients for TNC1
	ptTNC1Conns []net.Conn
	ptTNC1Lock  sync.Mutex

	// Pass‑through clients for TNC2
	ptTNC2Conns []net.Conn
	ptTNC2Lock  sync.Mutex
)

// broadcastToClients sends the given data to every client in the list.
func broadcastToClients(data []byte, lock *sync.Mutex, conns *[]net.Conn) {
	lock.Lock()
	defer lock.Unlock()
	// Iterate in reverse so that removals don’t disturb indices.
	for i := len(*conns) - 1; i >= 0; i-- {
		conn := (*conns)[i]
		if conn != nil {
			_, err := conn.Write(data)
			if err != nil {
				log.Printf("Error writing to pass‑through client %v: %v. Dropping client.", conn.RemoteAddr(), err)
				conn.Close()
				*conns = append((*conns)[:i], (*conns)[i+1:]...)
			}
		}
	}
}

// -----------------------------------------------------------------------------
// KISS / AX.25 Constants and Helper Functions
// -----------------------------------------------------------------------------

const (
	KISS_FLAG     = 0xC0
	KISS_CMD_DATA = 0x00
)

func escapeData(data []byte) []byte {
	var out bytes.Buffer
	for _, b := range data {
		if b == KISS_FLAG {
			out.Write([]byte{0xDB, 0xDC})
		} else if b == 0xDB {
			out.Write([]byte{0xDB, 0xDD})
		} else {
			out.WriteByte(b)
		}
	}
	return out.Bytes()
}

func unescapeData(data []byte) []byte {
	var out bytes.Buffer
	for i := 0; i < len(data); {
		b := data[i]
		if b == 0xDB && i+1 < len(data) {
			nxt := data[i+1]
			if nxt == 0xDC {
				out.WriteByte(KISS_FLAG)
				i += 2
				continue
			} else if nxt == 0xDD {
				out.WriteByte(0xDB)
				i += 2
				continue
			}
		}
		out.WriteByte(b)
		i++
	}
	return out.Bytes()
}

func buildKISSFrame(packet []byte) []byte {
	escaped := escapeData(packet)
	frame := []byte{KISS_FLAG, KISS_CMD_DATA}
	frame = append(frame, escaped...)
	frame = append(frame, KISS_FLAG)
	return frame
}

func extractKISSFrames(data []byte) ([][]byte, []byte) {
	var frames [][]byte
	for {
		start := bytes.IndexByte(data, KISS_FLAG)
		if start == -1 {
			break
		}
		end := bytes.IndexByte(data[start+1:], KISS_FLAG)
		if end == -1 {
			break
		}
		end = start + 1 + end
		frame := data[start : end+1]
		frames = append(frames, frame)
		data = data[end+1:]
	}
	return frames, data
}

func padCallsign(cs string) string {
	return fmt.Sprintf("%-9s", strings.ToUpper(cs))
}

func generateFileID() string {
	chars := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	return string([]byte{chars[rand.Intn(len(chars))], chars[rand.Intn(len(chars))]})
}

func encodeAX25Address(callsign string, isLast bool) []byte {
	parts := strings.Split(strings.ToUpper(callsign), "-")
	call := parts[0]
	if len(call) < 6 {
		call = call + strings.Repeat(" ", 6-len(call))
	} else if len(call) > 6 {
		call = call[:6]
	}
	addr := make([]byte, 7)
	for i := 0; i < 6; i++ {
		addr[i] = call[i] << 1
	}
	addr[6] = 0x60
	if isLast {
		addr[6] |= 0x01
	}
	return addr
}

func buildAX25Header(sender, receiver string) []byte {
	dest := encodeAX25Address(receiver, false)
	src := encodeAX25Address(sender, true)
	header := append(dest, src...)
	header = append(header, 0x03, 0xF0)
	return header
}

func canonicalKey(sender, receiver, fileID string) string {
	s := strings.ToUpper(strings.TrimSpace(sender))
	r := strings.ToUpper(strings.TrimSpace(receiver))
	fid := strings.TrimSpace(fileID)
	if s < r {
		return fmt.Sprintf("%s|%s|%s", s, r, fid)
	}
	return fmt.Sprintf("%s|%s|%s", r, s, fid)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// -----------------------------------------------------------------------------
// Packet Parsing: Structures and Functions
// -----------------------------------------------------------------------------

type Packet struct {
	Type           string // "data" or "ack"
	Sender         string
	Receiver       string
	FileID         string
	Seq            int
	BurstTo        int
	Total          int    // For header packets (seq==1), total number of packets.
	Payload        []byte // The inner payload.
	RawInfo        string // The decoded info field.
	Ack            string // For ACK packets.
	EncodingMethod byte   // new: 0=binary, 1=base64
}


func parsePacket(packet []byte) *Packet {
	// Require at least 16 bytes for the AX.25 header.
	if len(packet) < 16 {
		return nil
	}
	// Always decode sender and receiver from the AX.25 header.
	sender := decodeAX25Address(packet[7:14])
	receiver := decodeAX25Address(packet[0:7])
	// Get everything past the 16-byte header.
	infoAndPayload := packet[16:]
	if len(infoAndPayload) == 0 {
		return nil
	}

	// First, check for CMD/RSP packets.
	if len(packet) >= 80 {
		rspInfo := packet[16:80]
		strInfo := string(rspInfo)
		if strings.HasPrefix(strInfo, "CMD:") || strings.HasPrefix(strInfo, "RSP:") {
			return &Packet{
				Type:     "cmdrsp",
				Sender:   sender,
				Receiver: receiver,
				RawInfo:  strInfo,
			}
		}
	}

	// Next, check for ACK packets.
	// New ACK format is: "fileID:ACK:ackValue:" (fields separated by colons)
	if strings.Contains(string(infoAndPayload), "ACK:") {
		fields := strings.Split(string(infoAndPayload), ":")
		if len(fields) >= 3 {
			fileID := strings.TrimSpace(fields[0])
			ackVal := strings.TrimSpace(fields[2])
			return &Packet{
				Type:     "ack",
				Sender:   sender,
				Receiver: receiver,
				FileID:   fileID,
				Ack:      ackVal,
				RawInfo:  string(infoAndPayload),
			}
		}
		// Fallback if the format isn’t as expected.
		ackVal := ""
		parts := strings.Split(string(infoAndPayload), "ACK:")
		if len(parts) >= 2 {
			ackVal = strings.Trim(strings.Trim(parts[1], ":"), " ")
		}
		return &Packet{
			Type:     "ack",
			Sender:   sender,
			Receiver: receiver,
			Ack:      ackVal,
			RawInfo:  string(infoAndPayload),
		}
	}

	// Otherwise, assume it is a data packet.
	var infoField, payload []byte
	// Determine if this is the header packet (seq == 1) or a regular data packet.
	// Header packets have a 17-byte info field where positions 3–7 equal "0001".
	if len(infoAndPayload) >= 17 && string(infoAndPayload[3:7]) == "0001" {
		infoField = infoAndPayload[:17]
		payload = infoAndPayload[17:]
	} else if len(infoAndPayload) >= 12 {
		infoField = infoAndPayload[:12]
		payload = infoAndPayload[12:]
	} else {
		return nil
	}

	infoStr := string(infoField)
	fields := strings.Split(infoStr, ":")
	if len(fields) < 2 {
		return nil
	}
	fileID := strings.TrimSpace(fields[0])
	var seq, burstTo, total int
	// For header packet: info field length is 17 bytes, format: fileID:0001XXXX/YYYY:
	if len(infoField) == 17 {
		seq = 1
		if len(fields[1]) < 9 {
			return nil
		}
		// BurstTo is in characters 4 to 8 of fields[1].
		burstPart := fields[1][4:8]
		b, err := strconv.ParseInt(burstPart, 16, 32)
		if err != nil {
			return nil
		}
		burstTo = int(b)
		// Total is after the "/" in fields[1].
		parts := strings.Split(fields[1], "/")
		if len(parts) < 2 {
			return nil
		}
		totalVal, err := strconv.ParseInt(parts[1], 16, 32)
		if err != nil {
			return nil
		}
		total = int(totalVal)
	} else if len(infoField) == 12 {
		// Data packet: format: fileID:SSSSBBBB:
		if len(fields[1]) < 8 {
			return nil
		}
		seqPart := fields[1][:4]
		burstPart := fields[1][4:8]
		s, err1 := strconv.ParseInt(seqPart, 16, 32)
		b, err2 := strconv.ParseInt(burstPart, 16, 32)
		if err1 != nil || err2 != nil {
			return nil
		}
		seq = int(s)
		burstTo = int(b)
	} else {
		return nil
	}

	// Optionally, for header packets, determine the encoding method from the file header payload.
	var encodingMethod byte = 0
	if seq == 1 {
		headerFields := strings.Split(string(payload), "|")
		if len(headerFields) >= 8 {
			if val, err := strconv.Atoi(headerFields[7]); err == nil {
				encodingMethod = byte(val)
			}
		}
	}

	return &Packet{
		Type:           "data",
		Sender:         sender,
		Receiver:       receiver,
		FileID:         fileID,
		Seq:            seq,
		BurstTo:        burstTo,
		Total:          total,
		Payload:        payload,
		RawInfo:        infoStr,
		EncodingMethod: encodingMethod,
	}
}




// -----------------------------------------------------------------------------
// KISSConnection Interface and Implementations (TCP and Serial)
// -----------------------------------------------------------------------------

// Modified KISSConnection now includes SendFrameExcluding.
type KISSConnection interface {
	SendFrame(frame []byte) error
	SendFrameExcluding(frame []byte, exclude net.Conn) error
	RecvData(timeout time.Duration) ([]byte, error)
	Close() error
}

type connHolder struct {
	conn net.Conn
}

type TCPKISSConnection struct {
	conn       net.Conn
	listener   net.Listener
	atomicConn atomic.Value // stores *connHolder (never nil)
	isServer   bool
	lock       sync.Mutex
}

func newTCPKISSConnection(host string, port int, isServer bool) (*TCPKISSConnection, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	tnc := &TCPKISSConnection{isServer: isServer}
	if isServer {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return nil, err
		}
		tnc.listener = ln
		tnc.atomicConn.Store(&connHolder{conn: nil})
		log.Printf("[TCP Server] Listening on %s", addr)
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					log.Printf("Error accepting new connection on %s: %v", addr, err)
					time.Sleep(500 * time.Millisecond)
					continue
				}
				oldHolder := tnc.atomicConn.Load().(*connHolder)
				if oldHolder.conn != nil {
					oldHolder.conn.Close()
				}
				tnc.atomicConn.Store(&connHolder{conn: conn})
				log.Printf("[TCP Server] Accepted connection on %s from %s", addr, conn.RemoteAddr().String())
			}
		}()
	} else {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			return nil, err
		}
		tnc.conn = conn
		log.Printf("[TCP Client] Connected to %s", addr)
	}
	return tnc, nil
}

func (t *TCPKISSConnection) SendFrame(frame []byte) error {
	return t.SendFrameExcluding(frame, nil)
}

func (t *TCPKISSConnection) SendFrameExcluding(frame []byte, exclude net.Conn) error {
	// For client mode or non-server, simply write the frame.
	if !t.isServer {
		t.lock.Lock()
		defer t.lock.Unlock()
		_, err := t.conn.Write(frame)
		return err
	}
	// For server mode, loop until a connection is available.
	for {
		holderInterface := t.atomicConn.Load()
		holder := holderInterface.(*connHolder)
		if holder.conn == nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		t.lock.Lock()
		holderInterface = t.atomicConn.Load()
		holder = holderInterface.(*connHolder)
		if holder.conn == nil {
			t.lock.Unlock()
			continue
		}
		_, err := holder.conn.Write(frame)
		t.lock.Unlock()
		return err
	}
}

func (t *TCPKISSConnection) RecvData(timeout time.Duration) ([]byte, error) {
	if !t.isServer {
		t.conn.SetReadDeadline(time.Now().Add(timeout))
		buf := make([]byte, 1024)
		n, err := t.conn.Read(buf)
		if err != nil {
			if err == io.EOF {
				return []byte{}, err
			}
			if nErr, ok := err.(net.Error); ok && nErr.Timeout() {
				return []byte{}, nil
			}
			return nil, err
		}
		return buf[:n], nil
	}
	start := time.Now()
	for {
		holderInterface := t.atomicConn.Load()
		holder := holderInterface.(*connHolder)
		if holder.conn == nil {
			if time.Since(start) > timeout {
				return []byte{}, nil
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		holder.conn.SetReadDeadline(time.Now().Add(timeout))
		buf := make([]byte, 1024)
		n, err := holder.conn.Read(buf)
		if err != nil {
			if err == io.EOF {
				t.atomicConn.Store(&connHolder{conn: nil})
				continue
			}
			if nErr, ok := err.(net.Error); ok && nErr.Timeout() {
				return []byte{}, nil
			}
			return nil, err
		}
		return buf[:n], nil
	}
}

func (t *TCPKISSConnection) Close() error {
	if t.conn != nil {
		t.conn.Close()
	}
	if t.listener != nil {
		t.listener.Close()
	}
	holderInterface := t.atomicConn.Load()
	holder := holderInterface.(*connHolder)
	if holder.conn != nil {
		holder.conn.Close()
	}
	return nil
}

type SerialKISSConnection struct {
	ser  serial.Port
	lock sync.Mutex
}

func newSerialKISSConnection(portName string, baud int) (*SerialKISSConnection, error) {
	mode := &serial.Mode{
		BaudRate: baud,
	}
	ser, err := serial.Open(portName, mode)
	if err != nil {
		return nil, err
	}
	log.Printf("[Serial] Opened serial port %s at %d baud", portName, baud)
	return &SerialKISSConnection{ser: ser}, nil
}

func (s *SerialKISSConnection) SendFrame(frame []byte) error {
	return s.SendFrameExcluding(frame, nil)
}

func (s *SerialKISSConnection) SendFrameExcluding(frame []byte, exclude net.Conn) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	_, err := s.ser.Write(frame)
	return err
}

func (s *SerialKISSConnection) RecvData(timeout time.Duration) ([]byte, error) {
	buf := make([]byte, 1024)
	n, err := s.ser.Read(buf)
	if err != nil {
		if err == io.EOF {
			return []byte{}, nil
		}
		return nil, err
	}
	return buf[:n], nil
}

func (s *SerialKISSConnection) Close() error {
	return s.ser.Close()
}

// -----------------------------------------------------------------------------
// FrameReader: Reads raw data and extracts KISS frames
// -----------------------------------------------------------------------------

type FrameReader struct {
	conn    KISSConnection
	outChan chan []byte
	errChan chan error
	running bool
	buffer  []byte
	name    string
}

func NewFrameReader(conn KISSConnection, outChan chan []byte, name string) *FrameReader {
	return &FrameReader{
		conn:    conn,
		outChan: outChan,
		errChan: make(chan error, 1),
		running: true,
		buffer:  []byte{},
		name:    name,
	}
}

func (fr *FrameReader) Run() {
	for fr.running {
		data, err := fr.conn.RecvData(100 * time.Millisecond)
		if err != nil {
			// If error is not a timeout, signal and exit.
			if nErr, ok := err.(net.Error); !ok || !nErr.Timeout() {
				log.Printf("[%s] Fatal receive error: %v", fr.name, err)
				fr.errChan <- err
				return
			}
		}
		if len(data) > 0 {
			// Update independent inactivity timestamps.
			if fr.name == "TNC1" {
				lastDataTimeTNC1 = time.Now()
			} else if fr.name == "TNC2" {
				lastDataTimeTNC2 = time.Now()
			}
			fr.buffer = append(fr.buffer, data...)
			frames, remaining := extractKISSFrames(fr.buffer)
			fr.buffer = remaining
			for _, f := range frames {
				if len(f) >= 2 && f[0] == KISS_FLAG && f[len(f)-1] == KISS_FLAG {
					if len(f) < 4 {
						continue
					}
					inner := f[2 : len(f)-1]
					unesc := unescapeData(inner)
					fr.outChan <- unesc
					// In non‑loop mode, broadcast to pass‑through clients.
					if !*loop {
						frameToBroadcast := buildKISSFrame(unesc)
						if fr.name == "TNC1" {
							broadcastToClients(frameToBroadcast, &ptTNC1Lock, &ptTNC1Conns)
						} else if fr.name == "TNC2" {
							broadcastToClients(frameToBroadcast, &ptTNC2Lock, &ptTNC2Conns)
						}
					}
				}
			}
		} else {
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func (fr *FrameReader) Stop() {
	fr.running = false
}

// -----------------------------------------------------------------------------
// Pass‑Through Listener Functions for TNC1 and TNC2
// -----------------------------------------------------------------------------

func startTNC1PassthroughListener(port int) {
	addr := fmt.Sprintf("0.0.0.0:%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Error starting TNC1 pass‑through listener on %s: %v", addr, err)
	}
	log.Printf("TNC1 pass‑through listener started on %s", addr)
	for {
		client, err := ln.Accept()
		if err != nil {
			log.Printf("Error accepting TNC1 pass‑through client on %s: %v", addr, err)
			continue
		}
		log.Printf("TNC1 pass‑through client connected from %s", client.RemoteAddr().String())
		ptTNC1Lock.Lock()
		ptTNC1Conns = append(ptTNC1Conns, client)
		ptTNC1Lock.Unlock()
		go handleTNC1PassThroughRead(client)
	}
}

func startTNC2PassthroughListener(port int) {
	addr := fmt.Sprintf("0.0.0.0:%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Error starting TNC2 pass‑through listener on %s: %v", addr, err)
	}
	log.Printf("TNC2 pass‑through listener started on %s", addr)
	for {
		client, err := ln.Accept()
		if err != nil {
			log.Printf("Error accepting TNC2 pass‑through client on %s: %v", addr, err)
			continue
		}
		log.Printf("TNC2 pass‑through client connected from %s", client.RemoteAddr().String())
		ptTNC2Lock.Lock()
		ptTNC2Conns = append(ptTNC2Conns, client)
		ptTNC2Lock.Unlock()
		go handleTNC2PassThroughRead(client)
	}
}

func handleTNC1PassThroughRead(client net.Conn) {
	defer client.Close()
	buf := make([]byte, 1024)
	for {
		n, err := client.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Printf("Error reading from TNC1 pass‑through client %s: %v", client.RemoteAddr(), err)
			}
			return
		}
		if n > 0 {
			currentTNC1Lock.RLock()
			conn := currentTNC1
			currentTNC1Lock.RUnlock()
			if conn == nil {
				log.Printf("No TNC1 connection available; dropping pass‑through data from %s", client.RemoteAddr())
				continue
			}
			if err := conn.SendFrameExcluding(buf[:n], client); err != nil {
				log.Printf("Error sending data from TNC1 pass‑through client %s: %v", client.RemoteAddr(), err)
				return
			}
		}
	}
}

func handleTNC2PassThroughRead(client net.Conn) {
	defer client.Close()
	buf := make([]byte, 1024)
	for {
		n, err := client.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Printf("Error reading from TNC2 pass‑through client %s: %v", client.RemoteAddr(), err)
			}
			return
		}
		if n > 0 {
			currentTNC2Lock.RLock()
			conn := currentTNC2
			currentTNC2Lock.RUnlock()
			if conn == nil {
				log.Printf("No TNC2 connection available; dropping pass‑through data from %s", client.RemoteAddr())
				continue
			}
			if err := conn.SendFrameExcluding(buf[:n], client); err != nil {
				log.Printf("Error sending data from TNC2 pass‑through client %s: %v", client.RemoteAddr(), err)
				return
			}
		}
	}
}

// -----------------------------------------------------------------------------
// Transfer Tracking Structures
// -----------------------------------------------------------------------------

type Transfer struct {
	Sender         string
	Receiver       string
	FileID         string
	Filename       string
	TotalPackets   int
	LastSeq        int
	StartTime      time.Time
	TimeoutSeconds int
	FinAckTime     time.Time
	PacketData     map[int][]byte
	EncodingMethod byte
	Compress       bool
	FileSaved      bool
}

var (
	transfers        = make(map[string]*Transfer)
	transfersLock    sync.Mutex
	allowedCallsigns []string
)

// -----------------------------------------------------------------------------
// Global Command‑Line Options
// -----------------------------------------------------------------------------

var (
	callsignsFlag       = flag.String("callsigns", "", "Comma delimited list of valid sender/receiver callsigns (optional; supports wildcards)")
	tnc1ConnType        = flag.String("tnc1-connection-type", "tcp", "Connection type for TNC1: tcp or serial")
	tnc1Host            = flag.String("tnc1-host", "127.0.0.1", "TCP host for TNC1")
	tnc1Port            = flag.Int("tnc1-port", 9001, "TCP port for TNC1")
	tnc1SerialPort      = flag.String("tnc1-serial-port", "", "Serial port for TNC1 (e.g., COM3 or /dev/ttyUSB0)")
	tnc1Baud            = flag.Int("tnc1-baud", 115200, "Baud rate for TNC1 serial connection")
	tnc2ConnType        = flag.String("tnc2-connection-type", "tcp", "Connection type for TNC2: tcp or serial")
	tnc2Host            = flag.String("tnc2-host", "127.0.0.1", "TCP host for TNC2")
	tnc2Port            = flag.Int("tnc2-port", 9002, "TCP port for TNC2")
	tnc2SerialPort      = flag.String("tnc2-serial-port", "", "Serial port for TNC2")
	tnc2Baud            = flag.Int("tnc2-baud", 115200, "Baud rate for TNC2 serial connection")
	tnc1PassthroughPort = flag.Int("tnc1-passthrough-port", 5010, "TCP port for TNC1 pass‑through")
	tnc2PassthroughPort = flag.Int("tnc2-passthrough-port", 5011, "TCP port for TNC2 pass‑through")
	tcpReadDeadline     = flag.Int("tcp-read-deadline", 600, "Time (in seconds) without data before triggering reconnect")
	debug               = flag.Bool("debug", false, "Enable debug logging")
	saveFiles           = flag.Bool("save-files", false, "Save all files seen by the proxy (prepending <SENDER>_<RECEIVER>_ to filename)")
	loop                = flag.Bool("loop", false, "Enable loopback mode. In this mode, TNC1 listens on the pass‑through port and TNC2 on the corresponding port. Mutually exclusive with TNC1/TNC2 options.")
)

// -----------------------------------------------------------------------------
// Global Variables for Independent Monitoring and Connection Sharing
// -----------------------------------------------------------------------------

var (
	currentTNC1     KISSConnection
	currentTNC2     KISSConnection
	currentTNC1Lock sync.RWMutex
	currentTNC2Lock sync.RWMutex

	tnc1FrameChan = make(chan []byte, 100)
	tnc2FrameChan = make(chan []byte, 100)

	lastDataTimeTNC1 time.Time
	lastDataTimeTNC2 time.Time
)

// -----------------------------------------------------------------------------
// Wildcard Matching for Callsigns
// -----------------------------------------------------------------------------

func callsignAllowed(callsign string) bool {
	cs := strings.ToUpper(strings.TrimSpace(callsign))
	for _, pattern := range allowedCallsigns {
		if match, err := filepath.Match(pattern, cs); err == nil && match {
			return true
		}
	}
	return false
}

// decodeAX25Address decodes a 7‑byte AX.25 address into a callsign.
// Each of the first 6 bytes is right‐shifted by one to recover the ASCII characters,
// and the 7th byte holds the SSID (in its lower 4 bits). Extra spaces are trimmed.
func decodeAX25Address(addr []byte) string {
	b := make([]byte, 6)
	for i := 0; i < 6; i++ {
		b[i] = addr[i] >> 1
	}
	cs := strings.TrimSpace(string(b))
	ssid := (addr[6] >> 1) & 0x0F
	if ssid > 0 {
		cs = fmt.Sprintf("%s-%d", cs, ssid)
	}
	return cs
}

// processAndForwardPacket processes a raw packet (already unescaped from KISS framing)
// and then forwards it appropriately based on its type (CMD/RSP, ACK, header, or data).
func processAndForwardPacket(pkt []byte, dstConn KISSConnection, direction string) {
	packet := parsePacket(pkt)
	if packet == nil {
		if *debug {
			log.Printf("[%s] [FileID: <unknown>] [From: <unknown> To: <unknown>] Could not parse packet.", direction)
		}
		return
	}

	// For all non-ACK packets, enforce allowed callsigns if specified.
	// For CMD/RSP packets, if the sender or receiver is empty, try to decode them from the raw packet header.
	if packet.Type != "ack" && len(allowedCallsigns) > 0 {
		if packet.Type == "cmdrsp" && (strings.TrimSpace(packet.Sender) == "" || strings.TrimSpace(packet.Receiver) == "") {
			// Ensure we have enough bytes (at least 14) in the raw packet to decode addresses.
			if len(pkt) >= 14 {
				packet.Receiver = decodeAX25Address(pkt[0:7])
				packet.Sender = decodeAX25Address(pkt[7:14])
			}
		}
		if !callsignAllowed(packet.Sender) || !callsignAllowed(packet.Receiver) {
			log.Printf("[%s] [FileID: %s] [From: %s To: %s] Dropping packet: callsign not allowed",
				direction, packet.FileID, packet.Sender, packet.Receiver)
			return
		}
	}

	// Special-case: CMD/RSP packets are forwarded immediately.
	if packet.Type == "cmdrsp" {
		log.Printf("[%s] [FileID: %s] [From: %s To: %s] CMD/RSP packet received; forwarding without header check.",
			direction, packet.FileID, packet.Sender, packet.Receiver)
		frame := buildKISSFrame(pkt)
		if err := dstConn.SendFrame(frame); err != nil {
			log.Printf("[%s] [FileID: %s] [From: %s To: %s] Error forwarding CMD/RSP packet: %v",
				direction, packet.FileID, packet.Sender, packet.Receiver, err)
		}
		return
	}

	// Process ACK packets.
	if packet.Type == "ack" {
		transfersLock.Lock()
		transfer, exists := transfers[canonicalKey(packet.Sender, packet.Receiver, packet.FileID)]
		if exists {
			if strings.Contains(packet.Ack, "FIN-ACK") {
				if transfer.FinAckTime.IsZero() {
					transfer.FinAckTime = time.Now()
					log.Printf("[%s] [FileID: %s] [From: %s To: %s] Received FIN-ACK for file %s. Transfer complete. Continuing for timeout period (%d sec).",
						direction, packet.FileID, packet.Sender, packet.Receiver, transfer.Filename, transfer.TimeoutSeconds)
				} else {
					log.Printf("[%s] [FileID: %s] [From: %s To: %s] Re‑received FIN-ACK for file %s.",
						direction, packet.FileID, packet.Sender, packet.Receiver, transfer.Filename)
				}
			} else {
				if !transfer.FinAckTime.IsZero() && time.Since(transfer.FinAckTime) > time.Duration(transfer.TimeoutSeconds)*time.Second {
					log.Printf("[%s] [FileID: %s] [From: %s To: %s] Transfer timeout expired. Dropping ACK packet.",
						direction, packet.FileID, packet.Sender, packet.Receiver)
					delete(transfers, canonicalKey(packet.Sender, packet.Receiver, packet.FileID))
					transfersLock.Unlock()
					return
				}
			}
			transfersLock.Unlock()
		} else {
			transfersLock.Unlock()
			log.Printf("[%s] [FileID: %s] [From: %s To: %s] Dropping ACK packet: header not seen yet",
				direction, packet.FileID, packet.Sender, packet.Receiver)
			return
		}
		log.Printf("[%s] [FileID: %s] [From: %s To: %s] Forwarding ACK packet: %s",
			direction, packet.FileID, packet.Sender, packet.Receiver, packet.Ack)
		frame := buildKISSFrame(pkt)
		if err := dstConn.SendFrame(frame); err != nil {
			log.Printf("[%s] [FileID: %s] [From: %s To: %s] Error forwarding ACK packet: %v",
				direction, packet.FileID, packet.Sender, packet.Receiver, err)
		}
		return
	}

	// Process header packets (data packets with sequence number 1).
	if packet.Seq == 1 {
		headerStr := string(packet.Payload)
		fields := strings.Split(headerStr, "|")
		if len(fields) < 10 {
			log.Printf("[%s] [FileID: %s] [From: %s To: %s] Dropping header packet: invalid header (not enough fields)",
				direction, packet.FileID, packet.Sender, packet.Receiver)
			return
		}
		timeoutSec, err := strconv.Atoi(fields[0])
		if err != nil {
			log.Printf("[%s] [FileID: %s] [From: %s To: %s] Invalid timeout seconds in header: %v",
				direction, packet.FileID, packet.Sender, packet.Receiver, err)
			return
		}
		timeoutRetries, err := strconv.Atoi(fields[1])
		if err != nil {
			log.Printf("[%s] [FileID: %s] [From: %s To: %s] Invalid timeout retries in header: %v",
				direction, packet.FileID, packet.Sender, packet.Receiver, err)
			return
		}
		filename := fields[2]
		origSize, err := strconv.Atoi(fields[3])
		if err != nil {
			log.Printf("[%s] [FileID: %s] [From: %s To: %s] Invalid original size in header: %v",
				direction, packet.FileID, packet.Sender, packet.Receiver, err)
			return
		}
		compSize, err := strconv.Atoi(fields[4])
		if err != nil {
			log.Printf("[%s] [FileID: %s] [From: %s To: %s] Invalid compressed size in header: %v",
				direction, packet.FileID, packet.Sender, packet.Receiver, err)
			return
		}
		md5Hash := fields[5]
		encodingMethodVal, err := strconv.Atoi(fields[7])
		if err != nil {
			log.Printf("[%s] [FileID: %s] [From: %s To: %s] Invalid encoding method in header: %v",
				direction, packet.FileID, packet.Sender, packet.Receiver, err)
			return
		}
		compFlag := fields[8]
		totalPackets, err := strconv.Atoi(fields[9])
		if err != nil {
			log.Printf("[%s] [FileID: %s] [From: %s To: %s] Invalid total packets in header: %v",
				direction, packet.FileID, packet.Sender, packet.Receiver, err)
			return
		}
		compress := compFlag == "1"
		encStr := "binary"
		if encodingMethodVal == 1 {
			encStr = "base64"
		}
		log.Printf("[%s] [FileID: %s] [From: %s To: %s] Received HEADER packet:",
			direction, packet.FileID, packet.Sender, packet.Receiver)
		log.Printf("           Filename       : %s", filename)
		log.Printf("           Timeout Secs   : %d", timeoutSec)
		log.Printf("           Timeout Retries: %d", timeoutRetries)
		log.Printf("           Orig Size      : %d", origSize)
		log.Printf("           Comp Size      : %d", compSize)
		log.Printf("           MD5            : %s", md5Hash)
		log.Printf("           Compression    : %v", compress)
		log.Printf("           Total Packets  : %d", totalPackets)
		log.Printf("           Encoding Method: %s", encStr)
		transfersLock.Lock()
		transfers[canonicalKey(packet.Sender, packet.Receiver, packet.FileID)] = &Transfer{
			Sender:         packet.Sender,
			Receiver:       packet.Receiver,
			FileID:         packet.FileID,
			Filename:       filename,
			TotalPackets:   totalPackets,
			LastSeq:        1,
			StartTime:      time.Now(),
			TimeoutSeconds: timeoutSec,
			FinAckTime:     time.Time{},
			PacketData:     make(map[int][]byte),
			EncodingMethod: byte(encodingMethodVal),
			Compress:       compress,
			FileSaved:      false,
		}
		transfersLock.Unlock()
		log.Printf("[%s] [FileID: %s] [From: %s To: %s] Forwarding HEADER packet for file %s",
			direction, packet.FileID, packet.Sender, packet.Receiver, filename)
		frame := buildKISSFrame(pkt)
		if err := dstConn.SendFrame(frame); err != nil {
			log.Printf("[%s] [FileID: %s] [From: %s To: %s] Error forwarding HEADER packet: %v",
				direction, packet.FileID, packet.Sender, packet.Receiver, err)
		}
		return
	}

	// Process remaining data packets.
	transfersLock.Lock()
	transfer, exists := transfers[canonicalKey(packet.Sender, packet.Receiver, packet.FileID)]
	transfersLock.Unlock()
	if !exists {
		log.Printf("[%s] [FileID: %s] [From: %s To: %s] Dropping data packet seq %d: header not seen",
			direction, packet.FileID, packet.Sender, packet.Receiver, packet.Seq)
		return
	}
	if !transfer.FinAckTime.IsZero() {
		if time.Since(transfer.FinAckTime) > time.Duration(transfer.TimeoutSeconds)*time.Second {
			log.Printf("[%s] [FileID: %s] [From: %s To: %s] Transfer timeout expired. Dropping data packet seq %d.",
				direction, packet.FileID, packet.Sender, packet.Receiver, packet.Seq)
			transfersLock.Lock()
			delete(transfers, canonicalKey(packet.Sender, packet.Receiver, packet.FileID))
			transfersLock.Unlock()
			return
		}
	}
	if packet.Seq > transfer.LastSeq {
		transfer.LastSeq = packet.Seq
		progress := float64(packet.Seq-1) / float64(transfer.TotalPackets-1) * 100.0
		log.Printf("[%s] [FileID: %s] [From: %s To: %s] Transfer progress for file %s: packet %d of %d (%.1f%%)",
			direction, packet.FileID, packet.Sender, packet.Receiver, transfer.Filename, packet.Seq, transfer.TotalPackets, progress)
		if packet.Seq == transfer.TotalPackets {
			log.Printf("[%s] [FileID: %s] [From: %s To: %s] All data packets received for file %s; waiting for FIN-ACK.",
				direction, packet.FileID, packet.Sender, packet.Receiver, transfer.Filename)
		}
	}

	if *saveFiles {
		transfersLock.Lock()
		if transfer.PacketData == nil {
			transfer.PacketData = make(map[int][]byte)
		}
		if _, exists := transfer.PacketData[packet.Seq]; !exists {
			transfer.PacketData[packet.Seq] = append([]byte(nil), packet.Payload...)
		}
		complete := (len(transfer.PacketData) == (transfer.TotalPackets - 1))
		alreadySaved := transfer.FileSaved
		transfersLock.Unlock()
		if complete && !alreadySaved {
			var buf bytes.Buffer
			for i := 2; i <= transfer.TotalPackets; i++ {
				data, ok := transfer.PacketData[i]
				if !ok {
					log.Printf("[%s] [FileID: %s] Missing packet seq %d; cannot reassemble file.",
						direction, packet.FileID, i)
					goto ForwardPacket
				}
				if transfer.EncodingMethod == 1 {
					decoded, err := ioutil.ReadAll(base64.NewDecoder(base64.StdEncoding, bytes.NewReader(data)))
					if err != nil {
						log.Printf("[%s] [FileID: %s] Error decoding base64 on packet seq %d: %v",
							direction, packet.FileID, i, err)
						goto ForwardPacket
					}
					buf.Write(decoded)
				} else {
					buf.Write(data)
				}
			}
			fileData := buf.Bytes()
			if transfer.Compress {
				b := bytes.NewReader(fileData)
				zr, err := zlib.NewReader(b)
				if err != nil {
					log.Printf("[%s] [FileID: %s] Error decompressing file: %v", direction, packet.FileID, err)
					goto ForwardPacket
				}
				decompressed, err := ioutil.ReadAll(zr)
				zr.Close()
				if err != nil {
					log.Printf("[%s] [FileID: %s] Error reading decompressed data: %v", direction, packet.FileID, err)
					goto ForwardPacket
				}
				fileData = decompressed
			}
			newFilename := fmt.Sprintf("%s_%s_%s_%s", strings.ToUpper(transfer.Sender), strings.ToUpper(transfer.Receiver), transfer.FileID, transfer.Filename)
			finalFilename := newFilename
			if _, err := os.Stat(finalFilename); err == nil {
				extIndex := strings.LastIndex(newFilename, ".")
				var base, ext string
				if extIndex != -1 {
					base = newFilename[:extIndex]
					ext = newFilename[extIndex:]
				} else {
					base = newFilename
					ext = ""
				}
				for i := 1; ; i++ {
					candidate := fmt.Sprintf("%s_%d%s", base, i, ext)
					if _, err := os.Stat(candidate); os.IsNotExist(err) {
						finalFilename = candidate
						break
					}
				}
			}
			err := ioutil.WriteFile(finalFilename, fileData, 0644)
			if err != nil {
				log.Printf("[%s] [FileID: %s] Error saving file %s: %v", direction, packet.FileID, finalFilename, err)
			} else {
				log.Printf("[%s] [FileID: %s] Saved file as %s", direction, packet.FileID, finalFilename)
			}
			transfersLock.Lock()
			transfer.FileSaved = true
			transfersLock.Unlock()
		}
	}

ForwardPacket:
	log.Printf("[%s] [FileID: %s] [From: %s To: %s] Forwarding data packet seq %d",
		direction, packet.FileID, packet.Sender, packet.Receiver, packet.Seq)
	frame := buildKISSFrame(pkt)
	if err := dstConn.SendFrame(frame); err != nil {
		log.Printf("[%s] [FileID: %s] [From: %s To: %s] Error forwarding data packet: %v",
			direction, packet.FileID, packet.Sender, packet.Receiver, err)
	}
}




// -----------------------------------------------------------------------------
// Independent Auto‑Reconnect Loops for TNC1 and TNC2
// -----------------------------------------------------------------------------

func manageTNC1() {
	for {
		var conn KISSConnection
		var err error

		if *loop {
			// In loop mode, listen on the TNC1 passthrough port.
			conn, err = newTCPKISSConnection("0.0.0.0", *tnc1PassthroughPort, true)
			if err != nil {
				log.Printf("TNC1 (Loop Mode): Error creating TCP listener on port %d: %v", *tnc1PassthroughPort, err)
				time.Sleep(5 * time.Second)
				continue
			}
		} else {
			switch strings.ToLower(*tnc1ConnType) {
			case "tcp":
				conn, err = newTCPKISSConnection(*tnc1Host, *tnc1Port, false)
				if err != nil {
					log.Printf("TNC1: Error creating TCP connection: %v", err)
					time.Sleep(5 * time.Second)
					continue
				}
			case "serial":
				if *tnc1SerialPort == "" {
					log.Fatalf("TNC1: Serial port must be specified for serial connection.")
				}
				conn, err = newSerialKISSConnection(*tnc1SerialPort, *tnc1Baud)
				if err != nil {
					log.Printf("TNC1: Error creating serial connection: %v", err)
					time.Sleep(5 * time.Second)
					continue
				}
			default:
				log.Fatalf("TNC1: Invalid connection type: %s", *tnc1ConnType)
			}
		}

		currentTNC1Lock.Lock()
		currentTNC1 = conn
		currentTNC1Lock.Unlock()
		lastDataTimeTNC1 = time.Now()

		fr := NewFrameReader(conn, tnc1FrameChan, "TNC1")
		go fr.Run()

		// Inactivity monitor for TNC1
		done := make(chan struct{})
		go func() {
			deadline := time.Duration(*tcpReadDeadline) * time.Second
			for {
				select {
				case <-done:
					return
				default:
				}
				time.Sleep(1 * time.Second)
				if time.Since(lastDataTimeTNC1) > deadline {
					log.Printf("TNC1: No data received for %v. Reconnecting...", deadline)
					conn.Close()
					return
				}
			}
		}()

		// Wait for a fatal error from the frame reader.
		err = <-fr.errChan
		log.Printf("TNC1: Connection error detected: %v. Reconnecting...", err)
		fr.Stop()
		currentTNC1Lock.Lock()
		currentTNC1 = nil
		currentTNC1Lock.Unlock()
		close(done)
		time.Sleep(5 * time.Second)
	}
}

func manageTNC2() {
	for {
		var conn KISSConnection
		var err error

		if *loop {
			// In loop mode, listen on the TNC2 passthrough port.
			conn, err = newTCPKISSConnection("0.0.0.0", *tnc2PassthroughPort, true)
			if err != nil {
				log.Printf("TNC2 (Loop Mode): Error creating TCP listener on port %d: %v", *tnc2PassthroughPort, err)
				time.Sleep(5 * time.Second)
				continue
			}
		} else {
			switch strings.ToLower(*tnc2ConnType) {
			case "tcp":
				conn, err = newTCPKISSConnection(*tnc2Host, *tnc2Port, false)
				if err != nil {
					log.Printf("TNC2: Error creating TCP connection: %v", err)
					time.Sleep(5 * time.Second)
					continue
				}
			case "serial":
				if *tnc2SerialPort == "" {
					log.Fatalf("TNC2: Serial port must be specified for serial connection.")
				}
				conn, err = newSerialKISSConnection(*tnc2SerialPort, *tnc2Baud)
				if err != nil {
					log.Printf("TNC2: Error creating serial connection: %v", err)
					time.Sleep(5 * time.Second)
					continue
				}
			default:
				log.Fatalf("TNC2: Invalid connection type: %s", *tnc2ConnType)
			}
		}

		currentTNC2Lock.Lock()
		currentTNC2 = conn
		currentTNC2Lock.Unlock()
		lastDataTimeTNC2 = time.Now()

		fr := NewFrameReader(conn, tnc2FrameChan, "TNC2")
		go fr.Run()

		// Inactivity monitor for TNC2
		done := make(chan struct{})
		go func() {
			deadline := time.Duration(*tcpReadDeadline) * time.Second
			for {
				select {
				case <-done:
					return
				default:
				}
				time.Sleep(1 * time.Second)
				if time.Since(lastDataTimeTNC2) > deadline {
					log.Printf("TNC2: No data received for %v. Reconnecting...", deadline)
					conn.Close()
					return
				}
			}
		}()

		// Wait for a fatal error from the frame reader.
		err = <-fr.errChan
		log.Printf("TNC2: Connection error detected: %v. Reconnecting...", err)
		fr.Stop()
		currentTNC2Lock.Lock()
		currentTNC2 = nil
		currentTNC2Lock.Unlock()
		close(done)
		time.Sleep(5 * time.Second)
	}
}

// -----------------------------------------------------------------------------
// Forwarding Routines: Forward frames between TNC1 and TNC2
// -----------------------------------------------------------------------------

func forwardTNC1toTNC2() {
    for frame := range tnc1FrameChan {
        currentTNC2Lock.RLock()
       	dstConn := currentTNC2
        currentTNC2Lock.RUnlock()
        if dstConn != nil {
            // Process the frame, which will log file transfer details if applicable,
            // and then forward it to TNC2.
            processAndForwardPacket(frame, dstConn, "TNC1->TNC2")
        }
    }
}

func forwardTNC2toTNC1() {
    for frame := range tnc2FrameChan {
        currentTNC1Lock.RLock()
        dstConn := currentTNC1
        currentTNC1Lock.RUnlock()
        if dstConn != nil {
            // Process the frame and forward it to TNC1.
            processAndForwardPacket(frame, dstConn, "TNC2->TNC1")
        }
    }
}


// -----------------------------------------------------------------------------
// Main: Initialization and Launching of Independent Loops
// -----------------------------------------------------------------------------

func main() {
	flag.Parse()

	// Build allowed callsign patterns from the provided comma‑delimited list.
	if *callsignsFlag != "" {
		for _, s := range strings.Split(*callsignsFlag, ",") {
			s = strings.ToUpper(strings.TrimSpace(s))
			if s != "" {
				allowedCallsigns = append(allowedCallsigns, s)
			}
		}
		log.Printf("Allowed callsign patterns: %v", allowedCallsigns)
	} else {
		log.Printf("--callsigns not set, allowing any callsigns.")
	}

	if *loop {
		var conflict bool
		flag.Visit(func(f *flag.Flag) {
			if strings.HasPrefix(f.Name, "tnc1-") || strings.HasPrefix(f.Name, "tnc2-") {
				conflict = true
			}
		})
		if conflict {
			log.Fatal("--loop is mutually exclusive with TNC1/TNC2 options. Remove TNC1/TNC2 flags when using --loop.")
		}
	}

	// Only start pass‑through listeners if loop mode is disabled.
	if !*loop {
		go startTNC1PassthroughListener(*tnc1PassthroughPort)
		go startTNC2PassthroughListener(*tnc2PassthroughPort)
	}

	// Launch independent auto‑reconnect loops.
	go manageTNC1()
	go manageTNC2()

	// Launch forwarding routines.
	go forwardTNC1toTNC2()
	go forwardTNC2toTNC1()

	// Block forever.
	select {}
}
