// repeater.go
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.bug.st/serial"
)

// -----------------------------------------------------------------------------
// Command-line Flags for TNC Connection, Pass‑Through, and Allowed Callsigns
// -----------------------------------------------------------------------------

var (
	tncConnType   = flag.String("tnc-connection-type", "tcp", "Connection type for TNC: tcp or serial")
	tncHost       = flag.String("tnc-host", "127.0.0.1", "TCP host for TNC")
	tncPort       = flag.Int("tnc-port", 9000, "TCP port for TNC")
	tncSerialPort = flag.String("tnc-serial-port", "", "Serial port for TNC (e.g. COM3 or /dev/ttyUSB0)")
	tncBaud       = flag.Int("tnc-baud", 115200, "Baud rate for TNC serial connection")
	passthroughPort = flag.Int("passthrough-port", 5010, "TCP port for pass‑through clients")
	callsigns     = flag.String("callsigns", "", "Comma delimited list of valid sender/receiver callsigns (optional)")
	debug         = flag.Bool("debug", false, "Enable extra debug logging")
)

// allowedCalls is a global map of allowed callsigns (uppercase).
var allowedCalls map[string]bool

// debugf logs debug messages when debug is enabled.
func debugf(format string, v ...interface{}) {
	if *debug {
		log.Printf("[DEBUG] "+format, v...)
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
		debugf("Extracted frame: % X", frame)
		data = data[end+1:]
	}
	return frames, data
}

// -----------------------------------------------------------------------------
// Packet Parsing: Structures and Functions
// -----------------------------------------------------------------------------

// Packet represents a parsed packet.
type Packet struct {
	Type           string // "data" or "ack"
	Sender         string
	Receiver       string
	FileID         string
	Seq            int    // sequence number (first 4 hex digits)
	BurstTo        int    // expected highest sequence number for the burst (last 4 hex digits)
	Payload        []byte // inner payload (could be header info, data, or FIN marker)
	RawInfo        string // raw info field (for logging)
	Ack            string // for ACK packets
	EncodingMethod byte   // parsed for completeness (not used here)
}

// parsePacket extracts a packet from raw (unescaped) bytes.
func parsePacket(packet []byte) *Packet {
	debugf("Parsing packet: % X", packet)
	if len(packet) < 16 {
		debugf("Packet too short: %d bytes", len(packet))
		return nil
	}
	infoAndPayload := packet[16:]
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
					Type:    "ack",
					Ack:     strings.TrimSpace(fields[len(fields)-1]),
					RawInfo: string(infoAndPayload),
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
			}
		}
		ackVal := ""
		parts := strings.Split(string(infoAndPayload), "ACK:")
		if len(parts) >= 2 {
			ackVal = strings.Trim(strings.Trim(parts[1], ":"), " ")
		}
		return &Packet{
			Type:    "ack",
			Ack:     ackVal,
			RawInfo: string(infoAndPayload),
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
	debugf("Parsed DATA packet: sender=%s, receiver=%s, fileID=%s, seq=%d, burstTo=%d",
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
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// -----------------------------------------------------------------------------
// Header Logging Helper
// -----------------------------------------------------------------------------

// logHeaderDetails parses the header payload (assumed to be pipe-delimited)
// and logs the header details, translating the encoding method (0=binary, 1=base64).
func logHeaderDetails(payload []byte, fileID, sender, receiver string) {
	headerStr := string(payload)
	fields := strings.Split(headerStr, "|")
	if len(fields) < 10 {
		log.Printf("[Repeater] HEADER for fileID %s from %s->%s: insufficient header fields: %s", fileID, sender, receiver, headerStr)
		return
	}

	// Example parsing—adjust field indices as needed.
	timeoutSec := fields[0]
	timeoutRetries := fields[1]
	filename := fields[2]
	origSize := fields[3]
	compSize := fields[4]
	md5Hash := fields[5]
	// Field 6 is unused.
	encodingMethod := fields[7]
	compFlag := fields[8]
	totalPackets := fields[9]

	// Translate encodingMethod: 0 = binary, 1 = base64.
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

// -----------------------------------------------------------------------------
// Pass‑Through Support
// -----------------------------------------------------------------------------

var (
	ptConns []net.Conn
	ptLock  sync.Mutex
)

// broadcastToClients sends data to all connected pass‑through clients.
func broadcastToClients(data []byte, lock *sync.Mutex, conns *[]net.Conn) {
	lock.Lock()
	defer lock.Unlock()
	// Iterate in reverse order so removals don't affect indices.
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

// startPassThroughListener starts a TCP listener for pass‑through clients.
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
	}
}

// -----------------------------------------------------------------------------
// KISSConnection Interface and Implementations
// -----------------------------------------------------------------------------

// KISSConnection abstracts a connection that can send/receive KISS frames.
type KISSConnection interface {
	SendFrame(frame []byte) error
	RecvData(timeout time.Duration) ([]byte, error)
	Close() error
}

// --- TCP Connection Implementation ---

type tcpKISSConnection struct {
	conn     net.Conn
	isServer bool

	// For server mode.
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

func (t *tcpKISSConnection) SendFrame(frame []byte) error {
	if !t.isServer {
		t.lock.Lock()
		defer t.lock.Unlock()
		_, err := t.conn.Write(frame)
		debugf("Sent frame: % X", frame)
		broadcastToClients(frame, &ptLock, &ptConns)
		return err
	}
	// Server mode.
	for {
		holder := t.atomicConn.Load().(*connHolder)
		if holder.conn == nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		t.lock.Lock()
		holder = t.atomicConn.Load().(*connHolder)
		if holder.conn == nil {
			t.lock.Unlock()
			continue
		}
		_, err := holder.conn.Write(frame)
		t.lock.Unlock()
		debugf("Sent frame (server mode): % X", frame)
		broadcastToClients(frame, &ptLock, &ptConns)
		return err
	}
}

func (t *tcpKISSConnection) RecvData(timeout time.Duration) ([]byte, error) {
	if !t.isServer {
		t.conn.SetReadDeadline(time.Now().Add(timeout))
		buf := make([]byte, 1024)
		n, err := t.conn.Read(buf)
		if err != nil {
			if err == io.EOF {
				return []byte{}, nil
			}
			if nErr, ok := err.(net.Error); ok && nErr.Timeout() {
				return []byte{}, nil
			}
			return nil, err
		}
		debugf("Received %d bytes from TCP client", n)
		return buf[:n], nil
	}
	// Server mode.
	start := time.Now()
	for {
		holder := t.atomicConn.Load().(*connHolder)
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
		debugf("Received %d bytes from TCP server", n)
		return buf[:n], nil
	}
}

func (t *tcpKISSConnection) Close() error {
	if !t.isServer {
		return t.conn.Close()
	}
	holder := t.atomicConn.Load().(*connHolder)
	if holder.conn != nil {
		holder.conn.Close()
	}
	if t.listener != nil {
		t.listener.Close()
	}
	return nil
}

// --- Serial Connection Implementation ---

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

func (s *serialKISSConnection) SendFrame(frame []byte) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	_, err := s.ser.Write(frame)
	debugf("Sent frame over serial: % X", frame)
	broadcastToClients(frame, &ptLock, &ptConns)
	return err
}

func (s *serialKISSConnection) RecvData(timeout time.Duration) ([]byte, error) {
	buf := make([]byte, 1024)
	s.ser.SetReadTimeout(timeout)
	n, err := s.ser.Read(buf)
	if err != nil {
		if err == io.EOF {
			return []byte{}, nil
		}
		return nil, err
	}
	debugf("Received %d bytes over serial", n)
	return buf[:n], nil
}

func (s *serialKISSConnection) Close() error {
	return s.ser.Close()
}

// -----------------------------------------------------------------------------
// FrameReader: Reads raw data and extracts KISS frames
// -----------------------------------------------------------------------------

type FrameReader struct {
	conn    KISSConnection
	outChan chan []byte
	running bool
	buffer  []byte
}

func NewFrameReader(conn KISSConnection, outChan chan []byte) *FrameReader {
	return &FrameReader{
		conn:    conn,
		outChan: outChan,
		running: true,
		buffer:  []byte{},
	}
}

func (fr *FrameReader) Run() {
	for fr.running {
		data, err := fr.conn.RecvData(100 * time.Millisecond)
		if err != nil {
			log.Printf("Receive error: %v", err)
			continue
		}
		if len(data) > 0 {
			debugf("FrameReader received %d bytes: % X", len(data), data)
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
					debugf("FrameReader pushing packet: % X", unesc)
					fr.outChan <- unesc
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
// Transfer State Machine
// -----------------------------------------------------------------------------

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

// forwardBurst immediately forwards the buffered burst in order.
func forwardBurst(tr *Transfer, conn KISSConnection) {
	var seqs []int
	for seq := range tr.BurstBuffer {
		seqs = append(seqs, seq)
	}
	sort.Ints(seqs)
	for _, seq := range seqs {
		frame := buildKISSFrame(tr.BurstBuffer[seq])
		if err := conn.SendFrame(frame); err != nil {
			log.Printf("[Repeater] Error sending data packet seq %d: %v", seq, err)
		} else {
			log.Printf("[Repeater] Forwarded data packet seq %d for fileID %s.", seq, tr.FileID)
		}
	}
	// Clear the buffer and reset counter.
	tr.BurstBuffer = make(map[int][]byte)
	tr.LastSeq = 1
}

// processPacket is the main state machine.
// It buffers packets and forwards duplicates immediately.
func processPacket(pkt []byte, conn KISSConnection) {
	packet := parsePacket(pkt)
	if packet == nil {
		log.Printf("[Repeater] Could not parse packet.")
		return
	}

	// If allowed callsigns are configured, drop packets with unauthorized callsigns.
	if *callsigns != "" {
		srcAllowed := allowedCalls[strings.ToUpper(strings.TrimSpace(packet.Sender))]
		dstAllowed := allowedCalls[strings.ToUpper(strings.TrimSpace(packet.Receiver))]
		if !srcAllowed || !dstAllowed {
			log.Printf("[Repeater] Dropping packet for fileID %s from %s->%s: callsign not allowed", packet.FileID, packet.Sender, packet.Receiver)
			return
		}
	}

	key := canonicalKey(packet.Sender, packet.Receiver, packet.FileID)
	transfersLock.Lock()
	tr, exists := transfers[key]
	if !exists {
		// Create a new transfer if this is a header packet from the sender.
		if packet.Type == "data" && packet.Seq == 1 {
			tr = &Transfer{
				Sender:        packet.Sender,
				Receiver:      packet.Receiver,
				FileID:        packet.FileID,
				HeaderPacket:  pkt,
				BurstBuffer:   make(map[int][]byte),
				ExpectedBurst: packet.BurstTo,
				State:         WaitHeaderAck,
				LastSeq:       1,
			}
			transfers[key] = tr
			log.Printf("[Repeater] Received HEADER from %s (fileID %s). Forwarding header to receiver.", packet.Sender, packet.FileID)
			// Log header details.
			logHeaderDetails(packet.Payload, packet.FileID, packet.Sender, packet.Receiver)
			if err := conn.SendFrame(buildKISSFrame(pkt)); err != nil {
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

	// Determine packet direction.
	isFromSender := (packet.Sender == tr.Sender)
	isFromReceiver := (packet.Sender == tr.Receiver)
	debugf("Processing packet in state %d from %s", tr.State, packet.Sender)

	switch tr.State {
	case WaitHeaderAck:
		// In this state, forward header packets from sender and ACKs from receiver.
		if isFromSender && packet.Type == "data" && packet.Seq == 1 {
			log.Printf("[Repeater] Resent HEADER from sender for fileID %s. Forwarding header to receiver.", tr.FileID)
			conn.SendFrame(buildKISSFrame(pkt))
		} else if isFromReceiver && packet.Type == "ack" {
			log.Printf("[Repeater] Received header ACK from receiver for fileID %s. Forwarding header ACK to sender.", tr.FileID)
			conn.SendFrame(buildKISSFrame(pkt))
			tr.State = WaitBurst
			debugf("State changed to WaitBurst")
		} else {
			log.Printf("[Repeater] In WaitHeaderAck state; forwarding packet from %s.", packet.Sender)
			conn.SendFrame(buildKISSFrame(pkt))
		}
	case WaitBurst:
		// Buffer data packets; forward duplicates immediately.
		if isFromSender && packet.Type == "data" && packet.Seq > 1 {
			if _, exists := tr.BurstBuffer[packet.Seq]; exists {
				log.Printf("[Repeater] Duplicate data packet seq %d for fileID %s. Forwarding immediately.", packet.Seq, tr.FileID)
				conn.SendFrame(buildKISSFrame(pkt))
			} else {
				tr.BurstBuffer[packet.Seq] = pkt
				if packet.Seq > tr.LastSeq {
					tr.LastSeq = packet.Seq
				}
				log.Printf("[Repeater] Buffered data packet seq %d for fileID %s.", packet.Seq, tr.FileID)
			}
			// If the burst is complete, immediately forward it.
			if tr.LastSeq >= packet.BurstTo {
				log.Printf("[Repeater] Burst complete for fileID %s. Forwarding burst to receiver.", tr.FileID)
				forwardBurst(tr, conn)
				tr.State = WaitBurstAck
				debugf("State changed to WaitBurstAck")
			}
		} else if isFromReceiver && packet.Type == "ack" {
			log.Printf("[Repeater] Received ACK in WaitBurst state from receiver. Forwarding ACK to sender.")
			conn.SendFrame(buildKISSFrame(pkt))
		} else {
			log.Printf("[Repeater] In WaitBurst state; forwarding packet from %s.", packet.Sender)
			conn.SendFrame(buildKISSFrame(pkt))
		}
	case WaitBurstAck:
		// In WaitBurstAck, if receiver sends an ACK, forward it and return to WaitBurst.
		if isFromReceiver && packet.Type == "ack" {
			log.Printf("[Repeater] Received burst ACK from receiver for fileID %s. Forwarding burst ACK to sender.", tr.FileID)
			conn.SendFrame(buildKISSFrame(pkt))
			tr.State = WaitBurst
			debugf("State changed to WaitBurst")
		} else if isFromSender && packet.Type == "data" && packet.Seq > 1 {
			log.Printf("[Repeater] Resent data packet seq %d for fileID %s in WaitBurstAck state. Forwarding immediately.", packet.Seq, tr.FileID)
			conn.SendFrame(buildKISSFrame(pkt))
			tr.BurstBuffer[packet.Seq] = pkt
			if packet.Seq > tr.LastSeq {
				tr.LastSeq = packet.Seq
			}
		} else {
			log.Printf("[Repeater] In WaitBurstAck state; forwarding packet from %s.", packet.Sender)
			conn.SendFrame(buildKISSFrame(pkt))
		}
	case Finished:
		log.Printf("[Repeater] Transfer finished for fileID %s; forwarding packet from %s.", tr.FileID, packet.Sender)
		conn.SendFrame(buildKISSFrame(pkt))
	}
}

// -----------------------------------------------------------------------------
// Main: TNC Connection Setup, Pass‑Through Listener, and Processing Loop
// -----------------------------------------------------------------------------

func main() {
	flag.Parse()

	// If callsigns flag is provided, create the allowedCalls map.
	allowedCalls = make(map[string]bool)
	if *callsigns != "" {
		for _, cs := range strings.Split(*callsigns, ",") {
			cs = strings.ToUpper(strings.TrimSpace(cs))
			if cs != "" {
				allowedCalls[cs] = true
			}
		}
		log.Printf("Allowed callsigns: %v", allowedCalls)
	} else {
		log.Printf("--callsigns not set; allowing any callsign.")
	}

	// Start pass‑through listener.
	go startPassThroughListener(*passthroughPort)

	var tncConn KISSConnection
	var err error

	switch strings.ToLower(*tncConnType) {
	case "tcp":
		tncConn, err = newTCPKISSConnectionClient(*tncHost, *tncPort)
		if err != nil {
			log.Fatalf("Error creating TCP connection: %v", err)
		}
	case "serial":
		if *tncSerialPort == "" {
			log.Fatalf("Serial port must be specified for serial connection.")
		}
		tncConn, err = newSerialKISSConnection(*tncSerialPort, *tncBaud)
		if err != nil {
			log.Fatalf("Error creating serial connection: %v", err)
		}
	default:
		log.Fatalf("Invalid TNC connection type: %s", *tncConnType)
	}
	defer tncConn.Close()

	frameChan := make(chan []byte, 100)
	fr := NewFrameReader(tncConn, frameChan)
	go fr.Run()

	log.Printf("Repeater running. Waiting for packets...")
	for {
		select {
		case pkt := <-frameChan:
			debugf("Main loop received raw packet: % X", pkt)
			processPacket(pkt, tncConn)
		}
	}
}
