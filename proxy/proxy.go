// proxy.go
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

// handlePassThroughRead handles data coming from a pass‑through client
// and writes it directly to the associated TNC connection (bypassing file‑transfer logic).
func handlePassThroughRead(client net.Conn, tncConn KISSConnection, name string) {
	defer client.Close()
	buf := make([]byte, 1024)
	for {
		n, err := client.Read(buf)
		if err != nil {
			log.Printf("[Pass‑Through %s] Read error: %v", name, err)
			return
		}
		if n > 0 {
			err := tncConn.SendFrame(buf[:n])
			if err != nil {
				log.Printf("[Pass‑Through %s] Error sending to TNC: %v", name, err)
				return
			}
		}
	}
}

// startPassThroughListener starts a TCP listener on the given port.
func startPassThroughListener(port int, tncConn KISSConnection, ptConns *[]net.Conn, ptLock *sync.Mutex, name string) {
	addr := fmt.Sprintf("0.0.0.0:%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Error starting pass‑through listener on %s: %v", addr, err)
	}
	log.Printf("Pass‑through listener for %s started on %s", name, addr)
	for {
		client, err := ln.Accept()
		if err != nil {
			log.Printf("Error accepting pass‑through client on %s: %v", addr, err)
			continue
		}
		log.Printf("Pass‑through client connected for %s from %s", name, client.RemoteAddr().String())
		ptLock.Lock()
		*ptConns = append(*ptConns, client)
		ptLock.Unlock()
		go handlePassThroughRead(client, tncConn, name)
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
	if len(packet) < 16 {
		return nil
	}
	infoAndPayload := packet[16:]
	if len(infoAndPayload) == 0 {
		return nil
	}
	prefix := string(infoAndPayload[:min(50, len(infoAndPayload))])
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

	var infoField, payload []byte
	if len(infoAndPayload) >= 27 && string(infoAndPayload[23:27]) == "0001" {
		idx := bytes.IndexByte(infoAndPayload[27:], ':')
		if idx == -1 {
			return nil
		}
		endIdx := 27 + idx + 1
		infoField = infoAndPayload[:endIdx]
		payload = infoAndPayload[endIdx:]
	} else {
		if len(infoAndPayload) < 32 {
			return nil
		}
		infoField = infoAndPayload[:32]
		payload = infoAndPayload[32:]
	}

	var encodingMethod byte = 0
	infoStr := string(infoField)
	parts := strings.Split(infoStr, ":")
	if len(parts) < 4 {
		return nil
	}
	srParts := strings.Split(parts[0], ">")
	if len(srParts) != 2 {
		return nil
	}
	sender := strings.TrimSpace(srParts[0])
	receiver := strings.TrimSpace(srParts[1])
	fileID := strings.TrimSpace(parts[1])
	seqBurst := strings.TrimSpace(parts[2])
	var seq int
	var burstTo int
	total := 0
	if strings.Contains(seqBurst, "/") {
		seq = 1
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
	if seq == 1 {
		headerFields := strings.Split(string(payload), "|")
		if len(headerFields) >= 10 {
			if val, err := strconv.Atoi(headerFields[7]); err == nil {
				encodingMethod = byte(val)
			}
			if tot, err := strconv.Atoi(headerFields[9]); err == nil {
				total = tot
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

type KISSConnection interface {
	SendFrame(frame []byte) error
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
	if !t.isServer {
		t.lock.Lock()
		defer t.lock.Unlock()
		_, err := t.conn.Write(frame)
		return err
	}
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
	transfers     = make(map[string]*Transfer)
	transfersLock sync.Mutex
	allowedCalls  = make(map[string]bool)
)

// -----------------------------------------------------------------------------
// Global Command‑Line Options
// -----------------------------------------------------------------------------

var (
	tnc1ConnType   = flag.String("tnc1-connection-type", "tcp", "Connection type for TNC1: tcp or serial")
	tnc1Host       = flag.String("tnc1-host", "127.0.0.1", "TCP host for TNC1")
	tnc1Port       = flag.Int("tnc1-port", 9001, "TCP port for TNC1")
	tnc1SerialPort = flag.String("tnc1-serial-port", "", "Serial port for TNC1 (e.g., COM3 or /dev/ttyUSB0)")
	tnc1Baud       = flag.Int("tnc1-baud", 115200, "Baud rate for TNC1 serial connection")
	tnc2ConnType   = flag.String("tnc2-connection-type", "tcp", "Connection type for TNC2: tcp or serial")
	tnc2Host       = flag.String("tnc2-host", "127.0.0.1", "TCP host for TNC2")
	tnc2Port       = flag.Int("tnc2-port", 9002, "TCP port for TNC2")
	tnc2SerialPort = flag.String("tnc2-serial-port", "", "Serial port for TNC2")
	tnc2Baud       = flag.Int("tnc2-baud", 115200, "Baud rate for TNC2 serial connection")
	tnc1PassthroughPort = flag.Int("tnc1-passthrough-port", 5010, "TCP port for TNC1 pass‑through")
	tnc2PassthroughPort = flag.Int("tnc2-passthrough-port", 5011, "TCP port for TNC2 pass‑through")
)

var (
	callsigns = flag.String("callsigns", "", "Comma delimited list of valid sender/receiver callsigns (optional)")
	debug     = flag.Bool("debug", false, "Enable debug logging")
	saveFiles = flag.Bool("save-files", false, "Save all files seen by the proxy (prepending <SENDER>_<RECEIVER>_ to filename)")
	loop      = flag.Bool("loop", false, "Enable loopback mode. In this mode, TNC1 listens on the pass‑through port and TNC2 on the corresponding port. Mutually exclusive with TNC1/TNC2 options.")
)

// -----------------------------------------------------------------------------
// Packet Processing and Forwarding Logic
// -----------------------------------------------------------------------------

func processAndForwardPacket(pkt []byte, dstConn KISSConnection, direction string) {
	packet := parsePacket(pkt)
	if packet == nil {
		if *debug {
			log.Printf("[%s] [FileID: <unknown>] [From: <unknown> To: <unknown>] Could not parse packet.", direction)
		}
		return
	}

	key := canonicalKey(packet.Sender, packet.Receiver, packet.FileID)
	if packet.Type != "ack" && len(allowedCalls) > 0 {
		srcAllowed := allowedCalls[strings.ToUpper(strings.TrimSpace(packet.Sender))]
		dstAllowed := allowedCalls[strings.ToUpper(strings.TrimSpace(packet.Receiver))]
		if !srcAllowed || !dstAllowed {
			log.Printf("[%s] [FileID: %s] [From: %s To: %s] Dropping packet: callsign not allowed",
				direction, packet.FileID, packet.Sender, packet.Receiver)
			return
		}
	}

	transfersLock.Lock()
	transfer, exists := transfers[key]
	if exists && !transfer.FinAckTime.IsZero() {
		if time.Since(transfer.FinAckTime) > time.Duration(transfer.TimeoutSeconds)*time.Second {
			log.Printf("[%s] [FileID: %s] [From: %s To: %s] Transfer timeout expired. Dropping packet.",
				direction, packet.FileID, packet.Sender, packet.Receiver)
			delete(transfers, key)
			transfersLock.Unlock()
			return
		}
	}
	transfersLock.Unlock()

	if packet.Type == "ack" {
		transfersLock.Lock()
		transfer, exists := transfers[key]
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
					delete(transfers, key)
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
		var encStr string = "binary"
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
		transfers[key] = &Transfer{
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

	transfersLock.Lock()
	transfer, exists = transfers[key]
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
			delete(transfers, key)
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
// Main: Connection Setup and Forwarding Loop with Auto-Reconnect
// -----------------------------------------------------------------------------

func main() {
	flag.Parse()

	if *callsigns != "" {
		for _, s := range strings.Split(*callsigns, ",") {
			s = strings.ToUpper(strings.TrimSpace(s))
			if s != "" {
				allowedCalls[s] = true
			}
		}
		log.Printf("Allowed callsigns: %v", allowedCalls)
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

	// Auto-reconnect loop for non-loop (client) mode.
	for {
		var tnc1Conn, tnc2Conn KISSConnection
		var err error

		if *loop {
			log.Printf("Loopback mode enabled. Listening on TCP port %d for TNC1 and %d for TNC2.", *tnc1PassthroughPort, *tnc2PassthroughPort)
			tnc1Conn, err = newTCPKISSConnection("0.0.0.0", *tnc1PassthroughPort, true)
			if err != nil {
				log.Fatalf("Error setting up TNC1 listener: %v", err)
			}
			tnc2Conn, err = newTCPKISSConnection("0.0.0.0", *tnc2PassthroughPort, true)
			if err != nil {
				log.Fatalf("Error setting up TNC2 listener: %v", err)
			}
		} else {
			switch strings.ToLower(*tnc1ConnType) {
			case "tcp":
				tnc1Conn, err = newTCPKISSConnection(*tnc1Host, *tnc1Port, false)
				if err != nil {
					log.Printf("Error creating TNC1 TCP connection: %v", err)
					time.Sleep(5 * time.Second)
					continue
				}
			case "serial":
				if *tnc1SerialPort == "" {
					log.Fatalf("TNC1 serial port must be specified for serial connection.")
				}
				tnc1Conn, err = newSerialKISSConnection(*tnc1SerialPort, *tnc1Baud)
				if err != nil {
					log.Printf("Error creating TNC1 serial connection: %v", err)
					time.Sleep(5 * time.Second)
					continue
				}
			default:
				log.Fatalf("Invalid TNC1 connection type: %s", *tnc1ConnType)
			}

			switch strings.ToLower(*tnc2ConnType) {
			case "tcp":
				tnc2Conn, err = newTCPKISSConnection(*tnc2Host, *tnc2Port, false)
				if err != nil {
					log.Printf("Error creating TNC2 TCP connection: %v", err)
					tnc1Conn.Close()
					time.Sleep(5 * time.Second)
					continue
				}
			case "serial":
				if *tnc2SerialPort == "" {
					log.Fatalf("TNC2 serial port must be specified for serial connection.")
				}
				tnc2Conn, err = newSerialKISSConnection(*tnc2SerialPort, *tnc2Baud)
				if err != nil {
					log.Printf("Error creating TNC2 serial connection: %v", err)
					tnc1Conn.Close()
					time.Sleep(5 * time.Second)
					continue
				}
			default:
				log.Fatalf("Invalid TNC2 connection type: %s", *tnc2ConnType)
			}

			// Start pass‑through listeners.
			go startPassThroughListener(*tnc1PassthroughPort, tnc1Conn, &ptTNC1Conns, &ptTNC1Lock, "TNC1")
			go startPassThroughListener(*tnc2PassthroughPort, tnc2Conn, &ptTNC2Conns, &ptTNC2Lock, "TNC2")
		}

		tnc1Chan := make(chan []byte, 100)
		tnc2Chan := make(chan []byte, 100)

		// Create FrameReaders with error channels.
		fr1 := NewFrameReader(tnc1Conn, tnc1Chan, "TNC1")
		fr2 := NewFrameReader(tnc2Conn, tnc2Chan, "TNC2")
		go fr1.Run()
		go fr2.Run()

		// Start packet processing goroutines.
		go func() {
			for pkt := range tnc1Chan {
				processAndForwardPacket(pkt, tnc2Conn, "TNC1->TNC2")
			}
		}()
		go func() {
			for pkt := range tnc2Chan {
				processAndForwardPacket(pkt, tnc1Conn, "TNC2->TNC1")
			}
		}()

		log.Printf("Proxy running. Waiting for packets...")
		// Wait for a reconnect event from either FrameReader.
		select {
		case err := <-fr1.errChan:
			log.Printf("TNC1 connection error detected: %v", err)
		case err := <-fr2.errChan:
			log.Printf("TNC2 connection error detected: %v", err)
		}

		// Cleanup: stop frame readers and close connections.
		fr1.Stop()
		fr2.Stop()
		tnc1Conn.Close()
		tnc2Conn.Close()
		log.Printf("Attempting to reconnect in 5 seconds...")
		time.Sleep(5 * time.Second)
	}
}
