// repeater.go
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
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.bug.st/serial"
)

//
// Command‑line Flags for TNC Connection, Pass‑Through, Allowed Callsigns,
// and saving files.
//
var (
	tncConnType     = flag.String("tnc-connection-type", "tcp", "Connection type for TNC: tcp or serial")
	tncHost         = flag.String("tnc-host", "127.0.0.1", "TCP host for TNC")
	tncPort         = flag.Int("tnc-port", 9000, "TCP port for TNC")
	tncSerialPort   = flag.String("tnc-serial-port", "", "Serial port for TNC (e.g. COM3 or /dev/ttyUSB0)")
	tncBaud         = flag.Int("tnc-baud", 115200, "Baud rate for TNC serial connection")
	passthroughPort = flag.Int("passthrough-port", 5010, "TCP port for pass‑through clients")
	callsigns       = flag.String("callsigns", "", "Comma delimited list of valid sender/receiver callsigns (optional; supports wildcards, e.g. MM5NDH-*,*-15)")
	debug           = flag.Bool("debug", false, "Enable extra debug logging")
	// New flag to save files locally.
	saveFiles = flag.Bool("save-files", false, "Save received files locally (reassemble from data packets)")
	// New flag for send delay (in milliseconds)
	sendDelay = flag.Int("send-delay", 0, "Minimum delay in milliseconds after the TNC last sent us a frame before sending a frame to the TNC")
	// NEW: tcp-read-deadline flag (only for TCP TNC)
	tcpReadDeadline = flag.Int("tcp-read-deadline", 600, "Time (in seconds) without data from TNC before triggering reconnect (only for TCP TNC)")
)

// Global variable to hold the current TNC connection (updated on reconnect)
var (
	globalTNCConn      KISSConnection
	globalTNCConnMutex sync.RWMutex
)

// getGlobalTNCConn returns the current TNC connection.
func getGlobalTNCConn() KISSConnection {
	globalTNCConnMutex.RLock()
	defer globalTNCConnMutex.RUnlock()
	return globalTNCConn
}

//
// Instead of a map for allowed callsigns, we now use a slice of patterns.
var allowedCallsigns []string

// Global variables to track when the TNC last sent us a frame.
var (
	lastTNCRecvTime  time.Time
	lastTNCRecvMutex sync.Mutex
)

func updateLastTNCRecvTime() {
	lastTNCRecvMutex.Lock()
	lastTNCRecvTime = time.Now()
	lastTNCRecvMutex.Unlock()
}

func waitForSendDelay() {
	if *sendDelay <= 0 {
		return
	}
	lastTNCRecvMutex.Lock()
	t := lastTNCRecvTime
	lastTNCRecvMutex.Unlock()
	// If no frame has been received yet, send immediately.
	if t.IsZero() {
		return
	}
	delayDuration := time.Millisecond * time.Duration(*sendDelay)
	elapsed := time.Since(t)
	if elapsed < delayDuration {
		time.Sleep(delayDuration - elapsed)
	}
}

func debugf(format string, v ...interface{}) {
	if *debug {
		log.Printf("[DEBUG] "+format, v...)
	}
}

//
// KISS / AX.25 Constants and Helper Functions
//
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
		debugf("Extracted frame: % X", frame)
		data = data[end+1:]
	}
	return frames, data
}

//
// Packet Parsing: Structures and Functions
//
// We now add a RawFrame field to preserve the original TNC frame.
type Packet struct {
	Type           string // "data" or "ack"
	Sender         string
	Receiver       string
	FileID         string
	Seq            int    // sequence number
	BurstTo        int    // expected highest sequence number for the burst
	Payload        []byte // inner payload (after unescaping)
	RawInfo        string // raw info field (for logging)
	Ack            string // for ACK packets
	EncodingMethod byte   // parsed for completeness (not used here)
	RawFrame       []byte // the original raw frame (with KISS framing)
}

//
// parsePacket now expects the full raw frame, strips the first two and last byte,
// unescapes the inner data, and uses that for parsing. It also saves the raw frame.
func parsePacket(rawFrame []byte) *Packet {
	// Basic sanity check: frame should start and end with KISS_FLAG and have at least 4 bytes.
	if len(rawFrame) < 4 || rawFrame[0] != KISS_FLAG || rawFrame[len(rawFrame)-1] != KISS_FLAG {
		debugf("Invalid frame format")
		return nil
	}
	// Remove the first 2 bytes (KISS_FLAG and command) and the last KISS_FLAG.
	inner := rawFrame[2 : len(rawFrame)-1]
	unesc := unescapeData(inner)
	// Now, unesc is the same as what was previously passed to parsePacket.
	if len(unesc) < 16 {
		debugf("Packet too short: %d bytes", len(unesc))
		return nil
	}
	infoAndPayload := unesc[16:]
	if len(infoAndPayload) == 0 {
		debugf("No info/payload found")
		return nil
	}
	prefix := string(infoAndPayload[:min(50, len(infoAndPayload))])
	// Check for ACK packet.
	if strings.Contains(prefix, "ACK:") {
		fields := strings.Split(string(infoAndPayload), ":")
		if len(fields) >= 4 {
			srParts := strings.Split(fields[0], ">")
			if len(srParts) != 2 {
				return &Packet{
					Type:     "ack",
					Ack:      strings.TrimSpace(fields[len(fields)-1]),
					RawInfo:  string(infoAndPayload),
					RawFrame: rawFrame,
				}
			}
			sender := strings.TrimSpace(srParts[0])
			receiver := strings.TrimSpace(srParts[1])
			fileID := strings.TrimSpace(fields[1])
			ackVal := strings.TrimSpace(fields[3])
			debugf("Parsed ACK: sender=%s, receiver=%s, fileID=%s, ack=%s", sender, receiver, fileID, ackVal)
			return &Packet{
				Type:     "ack",
				Sender:   sender,
				Receiver: receiver,
				FileID:   fileID,
				Ack:      ackVal,
				RawInfo:  string(infoAndPayload),
				RawFrame: rawFrame,
			}
		}
		ackVal := ""
		parts := strings.Split(string(infoAndPayload), "ACK:")
		if len(parts) >= 2 {
			ackVal = strings.Trim(strings.Trim(parts[1], ":"), " ")
		}
		return &Packet{
			Type:     "ack",
			Ack:      ackVal,
			RawInfo:  string(infoAndPayload),
			RawFrame: rawFrame,
		}
	}

	// Otherwise, it's a data packet.
	var infoField, payload []byte
	if len(infoAndPayload) >= 27 && string(infoAndPayload[23:27]) == "0001" {
		idx := bytes.IndexByte(infoAndPayload[27:], ':')
		if idx == -1 {
			return nil
		}
		endIdx := 27 + idx + 1
		infoField = infoAndPayload[:endIdx]
		payload = infoAndPayload[endIdx:]
		debugf("Detected header packet via marker. InfoField: %s", string(infoField))
	} else {
		if len(infoAndPayload) < 32 {
			return nil
		}
		infoField = infoAndPayload[:32]
		payload = infoAndPayload[32:]
		debugf("Using fixed-length split. InfoField: %s", string(infoField))
	}

	var encodingMethod byte = 0
	infoStr := string(infoField)
	parts := strings.Split(infoStr, ":")
	if len(parts) < 4 {
		debugf("Insufficient parts in info field: %s", infoStr)
		return nil
	}
	srParts := strings.Split(parts[0], ">")
	if len(srParts) != 2 {
		debugf("Invalid sender/receiver field: %s", parts[0])
		return nil
	}
	sender := strings.TrimSpace(srParts[0])
	receiver := strings.TrimSpace(srParts[1])
	fileID := strings.TrimSpace(parts[1])
	seqBurst := strings.TrimSpace(parts[2])
	var seq int
	var burstTo int
	if strings.Contains(seqBurst, "/") {
		seq = 1 // header always seq 1
		if len(seqBurst) >= 8 {
			burstPart := seqBurst[4:8]
			b, err := strconv.ParseInt(burstPart, 16, 32)
			if err != nil {
				return nil
			}
			burstTo = int(b)
		}
	} else {
		if len(seqBurst) != 8 {
			return nil
		}
		seqInt, err1 := strconv.ParseInt(seqBurst[:4], 16, 32)
		burstInt, err2 := strconv.ParseInt(seqBurst[4:], 16, 32)
		if err1 != nil || err2 != nil {
			return nil
		}
		seq = int(seqInt)
		burstTo = int(burstInt)
	}
	debugf("Parsed DATA packet: sender=%s, receiver=%s, fileID=%s, seq=%d, burstTo %d",
		sender, receiver, fileID, seq, burstTo)
	return &Packet{
		Type:           "data",
		Sender:         sender,
		Receiver:       receiver,
		FileID:         fileID,
		Seq:            seq,
		BurstTo:        burstTo,
		Payload:        payload,
		RawInfo:        infoStr,
		EncodingMethod: encodingMethod,
		RawFrame:       rawFrame,
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

//
// Header Logging Helper
//
func logHeaderDetails(payload []byte, fileID, sender, receiver string) {
	headerStr := string(payload)
	fields := strings.Split(headerStr, "|")
	if len(fields) < 10 {
		log.Printf("[Repeater] HEADER for fileID %s from %s->%s: insufficient header fields: %s", fileID, sender, receiver, headerStr)
		return
	}
	timeoutSec := fields[0]
	timeoutRetries := fields[1]
	filename := fields[2]
	origSize := fields[3]
	compSize := fields[4]
	md5Hash := fields[5]
	encodingMethod := fields[7]
	compFlag := fields[8]
	totalPackets := fields[9]

	encodingStr := encodingMethod
	if encodingMethod == "0" {
		encodingStr = "binary"
	} else if encodingMethod == "1" {
		encodingStr = "base64"
	}

	log.Printf("[Repeater] HEADER for fileID %s:", fileID)
	log.Printf("           Filename       : %s", filename)
	log.Printf("           Timeout Secs   : %s", timeoutSec)
	log.Printf("           Timeout Retries: %s", timeoutRetries)
	log.Printf("           Orig Size      : %s", origSize)
	log.Printf("           Comp Size      : %s", compSize)
	log.Printf("           MD5            : %s", md5Hash)
	log.Printf("           Compression    : %s", compFlag)
	log.Printf("           Total Packets  : %s", totalPackets)
	log.Printf("           Encoding Method: %s", encodingStr)
}

//
// Pass‑Through Support (Two‑Way)
//
var (
	ptConns []net.Conn
	ptLock  sync.Mutex
)

// broadcastToClients now accepts an "exclude" connection. If non‑nil, that client
// will not receive the data.
func broadcastToClients(data []byte, lock *sync.Mutex, conns *[]net.Conn, exclude net.Conn) {
	lock.Lock()
	defer lock.Unlock()
	for i := len(*conns) - 1; i >= 0; i-- {
		conn := (*conns)[i]
		if exclude != nil && conn == exclude {
			continue
		}
		_, err := conn.Write(data)
		if err != nil {
			log.Printf("Error writing to pass‑through client %v: %v. Dropping client.", conn.RemoteAddr(), err)
			conn.Close()
			*conns = append((*conns)[:i], (*conns)[i+1:]...)
		}
	}
}

// When a pass‑through client sends data, we want to forward it to the TNC
// but exclude that client from the broadcast.
func handlePassThroughRead(client net.Conn) {
	defer client.Close()
	buf := make([]byte, 1024)
	for {
		n, err := client.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Printf("Pass‑through read error from %s: %v", client.RemoteAddr(), err)
			}
			return
		}
		if n > 0 {
			debugf("Pass‑through received %d bytes from %s: % X", n, client.RemoteAddr(), buf[:n])
			// Retrieve the current TNC connection.
			tncConn := getGlobalTNCConn()
			if tncConn == nil {
				log.Printf("No TNC connection available; dropping pass‑through data from %s", client.RemoteAddr())
				continue
			}
			// Send to the TNC; note that we no longer broadcast here.
			if err := tncConn.SendFrameExcluding(buf[:n], client); err != nil {
				log.Printf("Error sending data from pass‑through client to TNC: %v", err)
				return
			}
		}
	}
}

// startPassThroughListener is modified to start the listener once.
// It no longer takes a tncConn parameter.
func startPassThroughListener(port int) {
	addr := fmt.Sprintf("0.0.0.0:%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Error starting pass‑through listener on %s: %v", addr, err)
	}
	log.Printf("Pass‑through listener started on %s", addr)
	for {
		client, err := ln.Accept()
		if err != nil {
			log.Printf("Error accepting pass‑through client on %s: %v", addr, err)
			continue
		}
		log.Printf("Pass‑through client connected from %s", client.RemoteAddr().String())
		ptLock.Lock()
		ptConns = append(ptConns, client)
		ptLock.Unlock()
		go handlePassThroughRead(client)
	}
}

//
// KISSConnection Interface and Implementations
//
// We add SendFrameExcluding as before.
type KISSConnection interface {
	SendFrame(frame []byte) error
	SendFrameExcluding(frame []byte, exclude net.Conn) error
	RecvData(timeout time.Duration) ([]byte, error)
	Close() error
}

//
// --- TCP Connection Implementation ---
//
type tcpKISSConnection struct {
	conn       net.Conn
	isServer   bool
	listener   net.Listener
	atomicConn atomic.Value // stores *connHolder
	lock       sync.Mutex
}

type connHolder struct {
	conn net.Conn
}

func newTCPKISSConnectionClient(host string, port int) (*tcpKISSConnection, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	log.Printf("[TCP Client] Connected to %s", addr)
	return &tcpKISSConnection{
		conn:     conn,
		isServer: false,
	}, nil
}

func (t *tcpKISSConnection) SendFrameExcluding(frame []byte, exclude net.Conn) error {
	t.lock.Lock()
	defer t.lock.Unlock()
	// Wait if necessary before sending.
	waitForSendDelay()
	_, err := t.conn.Write(frame)
	debugf("Sent frame: % X", frame)
	// Removed broadcasting to pass‑through clients from here.
	// broadcastToClients(frame, &ptLock, &ptConns, exclude)
	return err
}

func (t *tcpKISSConnection) SendFrame(frame []byte) error {
	return t.SendFrameExcluding(frame, nil)
}

func (t *tcpKISSConnection) RecvData(timeout time.Duration) ([]byte, error) {
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
	debugf("Received %d bytes from TCP client", n)
	return buf[:n], nil
}

func (t *tcpKISSConnection) Close() error {
	return t.conn.Close()
}

//
// --- Serial Connection Implementation ---
//
type serialKISSConnection struct {
	ser  serial.Port
	lock sync.Mutex
}

func newSerialKISSConnection(portName string, baud int) (*serialKISSConnection, error) {
	mode := &serial.Mode{
		BaudRate: baud,
	}
	ser, err := serial.Open(portName, mode)
	if err != nil {
		return nil, err
	}
	log.Printf("[Serial] Opened serial port %s at %d baud", portName, baud)
	return &serialKISSConnection{ser: ser}, nil
}

func (s *serialKISSConnection) SendFrameExcluding(frame []byte, exclude net.Conn) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	// Wait if necessary before sending.
	waitForSendDelay()
	// Flush the serial port's output buffer before sending
	if err := s.ser.ResetOutputBuffer(); err != nil {
		log.Printf("Error flushing serial port: %v", err)
	}
	// Loop until all bytes are written to handle partial writes.
	totalWritten := 0
	for totalWritten < len(frame) {
		n, err := s.ser.Write(frame[totalWritten:])
		if err != nil {
			return err
		}
		totalWritten += n
	}
	debugf("Sent frame over serial: % X", frame)
	return nil
}

func (s *serialKISSConnection) SendFrame(frame []byte) error {
	return s.SendFrameExcluding(frame, nil)
}

func (s *serialKISSConnection) RecvData(timeout time.Duration) ([]byte, error) {
	buf := make([]byte, 1024)
	s.ser.SetReadTimeout(timeout)
	n, err := s.ser.Read(buf)
	if err != nil {
		if err == io.EOF {
			return []byte{}, err
		}
		return nil, err
	}
	debugf("Received %d bytes over serial", n)
	return buf[:n], nil
}

func (s *serialKISSConnection) Close() error {
	return s.ser.Close()
}

//
// FrameReader: Reads raw data from the TNC and extracts KISS frames.
// We now push the full raw frame to the out channel (so that we can forward it unchanged).
//
type FrameReader struct {
	conn    KISSConnection
	outChan chan []byte
	errChan chan error // error channel to signal connection loss
	running bool
	buffer  []byte
}

func NewFrameReader(conn KISSConnection, outChan chan []byte) *FrameReader {
	return &FrameReader{
		conn:    conn,
		outChan: outChan,
		errChan: make(chan error, 1),
		running: true,
		buffer:  []byte{},
	}
}

func (fr *FrameReader) Run() {
	for fr.running {
		data, err := fr.conn.RecvData(100 * time.Millisecond)
		if err != nil {
			if nErr, ok := err.(net.Error); !ok || !nErr.Timeout() {
				log.Printf("Fatal receive error: %v", err)
				fr.errChan <- err
				return
			}
		}
		if len(data) > 0 {
			debugf("FrameReader received %d bytes: % X", len(data), data)
			updateLastTNCRecvTime()
			fr.buffer = append(fr.buffer, data...)
			frames, remaining := extractKISSFrames(fr.buffer)
			fr.buffer = remaining
			for _, f := range frames {
				// Immediately broadcast the raw frame from the TNC to all pass‑through clients.
				broadcastToClients(f, &ptLock, &ptConns, nil)
				// Also push the raw frame for state‑machine processing.
				fr.outChan <- f
			}
		} else {
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func (fr *FrameReader) Stop() {
	fr.running = false
}

//
// Transfer State Machine
//
type TransferState int

const (
	WaitHeaderAck TransferState = iota
	WaitBurst
	WaitBurstAck
	Finished
)

// Transfer holds the state and buffers for one file transfer session.
type Transfer struct {
	Sender        string
	Receiver      string
	FileID        string
	HeaderPacket  []byte         // The header packet from the sender.
	BurstBuffer   map[int][]byte // Buffers data packets keyed by sequence.
	ExpectedBurst int            // Expected highest seq number for the burst.
	LastSeq       int            // Highest sequence number seen.
	State         TransferState
	// --- Fields for file saving ---
	Filename       string
	TotalPackets   int            // Total packet count (header included)
	EncodingMethod byte           // 0 = binary, 1 = base64
	Compress       bool           // true if file is compressed
	PacketData     map[int][]byte // Data packets (seq > 1) keyed by sequence
	FileSaved      bool
	sync.Mutex
}

var (
	transfers     = make(map[string]*Transfer)
	transfersLock sync.Mutex
)

func canonicalKey(sender, receiver, fileID string) string {
	s := strings.ToUpper(strings.TrimSpace(sender))
	r := strings.ToUpper(strings.TrimSpace(receiver))
	fid := strings.TrimSpace(fileID)
	if s < r {
		return fmt.Sprintf("%s|%s|%s", s, r, fid)
	}
	return fmt.Sprintf("%s|%s|%s", r, s, fid)
}

func forwardBurst(tr *Transfer, conn KISSConnection) {
	var seqs []int
	for seq := range tr.BurstBuffer {
		seqs = append(seqs, seq)
	}
	sort.Ints(seqs)
	for _, seq := range seqs {
		// Forward using the original raw frame from the buffered packet.
		frame := tr.BurstBuffer[seq]
		if err := conn.SendFrame(frame); err != nil {
			log.Printf("[Repeater] Error sending data packet seq %d: %v", seq, err)
		} else {
			log.Printf("[Repeater] Forwarded data packet seq %d for fileID %s.", seq, tr.FileID)
		}
	}
	tr.BurstBuffer = make(map[int][]byte)
	tr.LastSeq = 1
}

// processPacket is the main state machine. It buffers packets and forwards duplicates immediately.
func processPacket(rawFrame []byte, conn KISSConnection) {
	packet := parsePacket(rawFrame)
	if packet == nil {
		log.Printf("[Repeater] Could not parse packet.")
		return
	}

	// --- Logging improvements ---
	if packet.Type == "ack" {
		log.Printf("[Repeater] ACK packet from %s -> %s for fileID %s: %s",
			packet.Sender, packet.Receiver, packet.FileID, packet.RawInfo)
	} else {
		log.Printf("[Repeater] Data packet from %s -> %s for fileID %s, seq %d, burstTo %d",
			packet.Sender, packet.Receiver, packet.FileID, packet.Seq, packet.BurstTo)
	}
	// --- End logging improvements ---

	// If callsigns filtering is enabled, check against allowed patterns.
	if *callsigns != "" {
		if !callsignAllowed(packet.Sender) || !callsignAllowed(packet.Receiver) {
			log.Printf("[Repeater] Dropping packet for fileID %s from %s -> %s: callsign not allowed",
				packet.FileID, packet.Sender, packet.Receiver)
			return
		}
	}

	key := canonicalKey(packet.Sender, packet.Receiver, packet.FileID)
	transfersLock.Lock()
	tr, exists := transfers[key]
	if !exists {
		if packet.Type == "data" && packet.Seq == 1 {
			tr = &Transfer{
				Sender:        packet.Sender,
				Receiver:      packet.Receiver,
				FileID:        packet.FileID,
				HeaderPacket:  rawFrame, // store the original raw header frame
				BurstBuffer:   make(map[int][]byte),
				ExpectedBurst: packet.BurstTo,
				State:         WaitHeaderAck,
				LastSeq:       1,
			}
			// If saving files is enabled, parse header info.
			if *saveFiles {
				headerParts := strings.Split(string(packet.Payload), "|")
				if len(headerParts) >= 10 {
					tr.Filename = headerParts[2]
					if tot, err := strconv.Atoi(headerParts[9]); err == nil {
						tr.TotalPackets = tot
					} else {
						log.Printf("[Repeater] Error parsing total packets from header for fileID %s: %v", packet.FileID, err)
					}
					if enc, err := strconv.Atoi(headerParts[7]); err == nil {
						tr.EncodingMethod = byte(enc)
					}
					tr.Compress = headerParts[8] == "1"
				}
				tr.PacketData = make(map[int][]byte)
			}
			transfers[key] = tr
			log.Printf("[Repeater] Received HEADER from %s -> %s for fileID %s. Forwarding header to receiver.",
				packet.Sender, packet.Receiver, packet.FileID)
			logHeaderDetails(packet.Payload, packet.FileID, packet.Sender, packet.Receiver)
			// Forward the header using the original raw frame.
			if err := conn.SendFrame(rawFrame); err != nil {
				log.Printf("[Repeater] Error sending HEADER: %v", err)
			}
		} else {
			transfersLock.Unlock()
			log.Printf("[Repeater] Dropping packet for unknown transfer (fileID %s).", packet.FileID)
			return
		}
	}
	transfersLock.Unlock()

	tr.Lock()
	defer tr.Unlock()

	isFromSender := (packet.Sender == tr.Sender)
	isFromReceiver := (packet.Sender == tr.Receiver)
	debugf("Processing packet in state %d from %s", tr.State, packet.Sender)

	switch tr.State {
	case WaitHeaderAck:
		if isFromSender && packet.Type == "data" && packet.Seq == 1 {
			log.Printf("[Repeater] Resent HEADER from sender for fileID %s. Forwarding header to receiver.", tr.FileID)
			conn.SendFrame(rawFrame)
		} else if packet.Type == "ack" && (isFromReceiver || strings.ToUpper(packet.Ack) == "FIN-ACK") {
			log.Printf("[Repeater] Received header ACK (%s) for fileID %s. Forwarding header ACK to sender.", packet.Ack, tr.FileID)
			conn.SendFrame(rawFrame)
			tr.State = WaitBurst
			debugf("State changed to WaitBurst")
		} else {
			log.Printf("[Repeater] In WaitHeaderAck state; forwarding packet from %s.", packet.Sender)
			conn.SendFrame(rawFrame)
		}
	case WaitBurst:
		if isFromSender && packet.Type == "data" && packet.Seq > 1 {
			if _, exists := tr.BurstBuffer[packet.Seq]; exists {
				log.Printf("[Repeater] Duplicate data packet seq %d for fileID %s. Forwarding immediately.", packet.Seq, tr.FileID)
				conn.SendFrame(rawFrame)
			} else {
				tr.BurstBuffer[packet.Seq] = rawFrame
				if packet.Seq > tr.LastSeq {
					tr.LastSeq = packet.Seq
				}
				log.Printf("[Repeater] Buffered data packet seq %d for fileID %s.", packet.Seq, tr.FileID)
			}
			if tr.LastSeq >= packet.BurstTo {
				log.Printf("[Repeater] Burst complete for fileID %s. Forwarding burst to receiver.", tr.FileID)
				forwardBurst(tr, conn)
				tr.State = WaitBurstAck
				debugf("State changed to WaitBurstAck")
			}
		} else if packet.Type == "ack" && (isFromReceiver || strings.ToUpper(packet.Ack) == "FIN-ACK") {
			log.Printf("[Repeater] Received ACK (%s) in WaitBurst state for fileID %s. Forwarding ACK to sender.", packet.Ack, tr.FileID)
			conn.SendFrame(rawFrame)
		} else {
			log.Printf("[Repeater] In WaitBurst state; forwarding packet from %s.", packet.Sender)
			conn.SendFrame(rawFrame)
		}
	case WaitBurstAck:
		if packet.Type == "ack" && (isFromReceiver || strings.ToUpper(packet.Ack) == "FIN-ACK") {
			log.Printf("[Repeater] Received burst ACK (%s) for fileID %s. Forwarding burst ACK to sender.", packet.Ack, tr.FileID)
			conn.SendFrame(rawFrame)
			tr.State = WaitBurst
			debugf("State changed to WaitBurst")
		} else if isFromSender && packet.Type == "data" && packet.Seq > 1 {
			log.Printf("[Repeater] Resent data packet seq %d for fileID %s in WaitBurstAck state. Forwarding immediately.", packet.Seq, tr.FileID)
			conn.SendFrame(rawFrame)
			tr.BurstBuffer[packet.Seq] = rawFrame
			if packet.Seq > tr.LastSeq {
				tr.LastSeq = packet.Seq
			}
		} else {
			log.Printf("[Repeater] In WaitBurstAck state; forwarding packet from %s.", packet.Sender)
			conn.SendFrame(rawFrame)
		}
	case Finished:
		log.Printf("[Repeater] Transfer finished for fileID %s; forwarding packet from %s.", tr.FileID, packet.Sender)
		conn.SendFrame(rawFrame)
	}

	// --- File-saving logic (unchanged) ---
	if *saveFiles && isFromSender && packet.Type == "data" && packet.Seq > 1 {
		if tr.PacketData == nil {
			tr.PacketData = make(map[int][]byte)
		}
		if _, exists := tr.PacketData[packet.Seq]; !exists {
			tr.PacketData[packet.Seq] = packet.Payload
		}
		if tr.TotalPackets > 0 && !tr.FileSaved && len(tr.PacketData) == (tr.TotalPackets-1) {
			var buf bytes.Buffer
			complete := true
			for i := 2; i <= tr.TotalPackets; i++ {
				data, ok := tr.PacketData[i]
				if !ok {
					complete = false
					log.Printf("[Repeater] Missing packet seq %d for fileID %s; cannot reassemble file.", i, tr.FileID)
					break
				}
				if tr.EncodingMethod == 1 {
					decoded, err := ioutil.ReadAll(base64.NewDecoder(base64.StdEncoding, bytes.NewReader(data)))
					if err != nil {
						log.Printf("[Repeater] Error decoding base64 on packet seq %d for fileID %s: %v", i, tr.FileID, err)
						complete = false
						break
					}
					buf.Write(decoded)
				} else {
					buf.Write(data)
				}
			}
			if complete {
				fileData := buf.Bytes()
				if tr.Compress {
					b := bytes.NewReader(fileData)
					zr, err := zlib.NewReader(b)
					if err != nil {
						log.Printf("[Repeater] Error decompressing file for fileID %s: %v", tr.FileID, err)
						complete = false
					} else {
						decompressed, err := ioutil.ReadAll(zr)
						zr.Close()
						if err != nil {
							log.Printf("[Repeater] Error reading decompressed data for fileID %s: %v", tr.FileID, err)
							complete = false
						} else {
							fileData = decompressed
						}
					}
				}
				if complete {
					newFilename := fmt.Sprintf("%s_%s_%s_%s", strings.ToUpper(tr.Sender), strings.ToUpper(tr.Receiver), tr.FileID, tr.Filename)
					finalFilename := newFilename
					for i := 1; ; i++ {
						if _, err := os.Stat(finalFilename); os.IsNotExist(err) {
							break
						}
						finalFilename = fmt.Sprintf("%s_%d", newFilename, i)
					}
					err := ioutil.WriteFile(finalFilename, fileData, 0644)
					if err != nil {
						log.Printf("[Repeater] Error saving file %s: %v", finalFilename, err)
					} else {
						log.Printf("[Repeater] Saved file as %s", finalFilename)
					}
					tr.FileSaved = true
				}
			}
		}
	}
}

//
// callsignAllowed returns true if the given callsign matches any of the allowed patterns.
// The matching is case‑insensitive.
func callsignAllowed(callsign string) bool {
	cs := strings.ToUpper(strings.TrimSpace(callsign))
	for _, pattern := range allowedCallsigns {
		if match, err := filepath.Match(pattern, cs); err == nil && match {
			return true
		}
	}
	return false
}

//
// Main: TNC Connection Setup, Pass‑Through Listener, and Processing Loop with Auto‑Reconnect
//
func main() {
	flag.Parse()

	// Build allowed callsign patterns from the provided comma‑delimited list.
	if *callsigns != "" {
		for _, cs := range strings.Split(*callsigns, ",") {
			cs = strings.ToUpper(strings.TrimSpace(cs))
			if cs != "" {
				allowedCallsigns = append(allowedCallsigns, cs)
			}
		}
		log.Printf("Allowed callsign patterns: %v", allowedCallsigns)
	} else {
		log.Printf("--callsigns not set; allowing any callsign.")
	}

	// Start the pass‑through listener once in a separate goroutine.
	go startPassThroughListener(*passthroughPort)

	for {
		tncConn, err := createTNCConnection()
		if err != nil {
			log.Printf("Error creating TNC connection: %v. Retrying in 5 seconds...", err)
			time.Sleep(5 * time.Second)
			continue
		}

		// Update the global TNC connection.
		globalTNCConnMutex.Lock()
		globalTNCConn = tncConn
		globalTNCConnMutex.Unlock()

		frameChan := make(chan []byte, 100)
		fr := NewFrameReader(tncConn, frameChan)
		go fr.Run()

		// NEW: Only for TCP TNC connections, start an inactivity monitor.
		if strings.ToLower(*tncConnType) == "tcp" {
			go func(conn KISSConnection) {
				deadline := time.Duration(*tcpReadDeadline) * time.Second
				for {
					time.Sleep(1 * time.Second)
					lastTNCRecvMutex.Lock()
					last := lastTNCRecvTime
					lastTNCRecvMutex.Unlock()
					// If we've received data before and the inactivity period is exceeded…
					if !last.IsZero() && time.Since(last) > deadline {
						log.Printf("No data received from TNC for %d seconds; triggering reconnect", *tcpReadDeadline)
						conn.Close() // Force the FrameReader to error out and break the inner loop.
						return
					}
				}
			}(tncConn)
		}

		log.Printf("Repeater running. Waiting for packets...")
		reconnect := false

		for {
			select {
			case pkt := <-frameChan:
				debugf("Main loop received raw packet: % X", pkt)
				processPacket(pkt, tncConn)
			case err := <-fr.errChan:
				log.Printf("TNC connection lost: %v", err)
				reconnect = true
			}
			if reconnect {
				break
			}
		}

		fr.Stop()
		tncConn.Close()
		log.Printf("Attempting to reconnect in 5 seconds...")
		time.Sleep(5 * time.Second)
	}
}

func createTNCConnection() (KISSConnection, error) {
	switch strings.ToLower(*tncConnType) {
	case "tcp":
		conn, err := newTCPKISSConnectionClient(*tncHost, *tncPort)
		if err != nil {
			return nil, err
		}
		return conn, nil
	case "serial":
		if *tncSerialPort == "" {
			return nil, fmt.Errorf("Serial port must be specified for serial connection")
		}
		conn, err := newSerialKISSConnection(*tncSerialPort, *tncBaud)
		if err != nil {
			return nil, err
		}
		return conn, nil
	default:
		return nil, fmt.Errorf("Invalid TNC connection type: %s", *tncConnType)
	}
}
