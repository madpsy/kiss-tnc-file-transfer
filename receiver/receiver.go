// receiver.go
package main

import (
	"bytes"
	"compress/zlib"
	"crypto/md5"
	"encoding/base64" // remains for Base64 decoding
	"encoding/hex"
	"flag"
	"fmt"
	"go.bug.st/serial" // run: go get go.bug.st/serial
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------------------
// Global Variables for TCP Inactivity Monitoring
// ---------------------

// lastDataTime holds the timestamp of the most recent data received.
// It is updated by the FrameReader and read by the TCP monitor.
var (
	lastDataTime  time.Time
	lastDataMutex sync.Mutex
)

// updateLastDataTime safely updates the lastDataTime to now.
func updateLastDataTime() {
	lastDataMutex.Lock()
	lastDataTime = time.Now()
	lastDataMutex.Unlock()
}

// setLastDataTime sets the lastDataTime to a given time.
func setLastDataTime(t time.Time) {
	lastDataMutex.Lock()
	lastDataTime = t
	lastDataMutex.Unlock()
}

// ---------------------
// Global Constants
// ---------------------

const (
	KISS_FLAG     = 0xC0
	KISS_CMD_DATA = 0x00
	CHUNK_SIZE    = 205
)

var allowedCallsigns []string

// ---------------------
// Helper Functions
// ---------------------

func callsignAllowed(callsign string) bool {
	cs := strings.ToUpper(strings.TrimSpace(callsign))
	for _, pattern := range allowedCallsigns {
		if match, err := filepath.Match(pattern, cs); err == nil && match {
			return true
		}
	}
	return false
}

// ---------------------
// KISS / AX.25 Utility Functions
// ---------------------

// escapeData escapes any KISS special bytes so that framing is preserved.
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

// unescapeData reverses the KISS escaping.
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

// buildKISSFrame builds a KISS frame from raw packet bytes.
func buildKISSFrame(packet []byte) []byte {
	escaped := escapeData(packet)
	frame := []byte{KISS_FLAG, KISS_CMD_DATA}
	frame = append(frame, escaped...)
	frame = append(frame, KISS_FLAG)
	return frame
}

// extractKISSFrames extracts complete KISS frames from the given buffer.
// Returns a slice of complete frames and any remaining bytes.
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

// --- Updated Callsign Encoding/Decoding ---

// encodeAX25Address encodes an AX.25 address field for the given callsign.
func encodeAX25Address(callsign string, isLast bool) []byte {
	// Split the callsign on "-" to separate the base and SSID.
	parts := strings.Split(callsign, "-")
	call := strings.ToUpper(parts[0])
	if len(call) < 6 {
		call = call + strings.Repeat(" ", 6-len(call))
	} else if len(call) > 6 {
		call = call[:6]
	}
	ssid := 0
	if len(parts) > 1 {
		var err error
		ssid, err = strconv.Atoi(parts[1])
		if err != nil {
			ssid = 0
		}
	}
	addr := make([]byte, 7)
	for i := 0; i < 6; i++ {
		addr[i] = call[i] << 1
	}
	// The 7th byte: bits 1-4 store the SSID (shifted left by 1) and bits 5-7 are set (0x60).
	addr[6] = byte(((ssid & 0x0F) << 1) | 0x60)
	if isLast {
		addr[6] |= 0x01
	}
	return addr
}

// decodeAX25Address decodes a 7‑byte AX.25 address into its full callsign,
// including the SSID if non‑zero.
func decodeAX25Address(addr []byte) string {
	if len(addr) < 7 {
		return ""
	}
	var call string
	for i := 0; i < 6; i++ {
		// Each character is stored shifted left by 1; shift right to decode.
		call += string(addr[i] >> 1)
	}
	call = strings.TrimSpace(call)
	// Decode SSID from bits 1-4 of the 7th byte.
	ssid := (addr[6] >> 1) & 0x0F
	if ssid != 0 {
		call = fmt.Sprintf("%s-%d", call, ssid)
	}
	return call
}

// buildAX25Header builds an AX.25 header using the source and destination callsigns.
func buildAX25Header(source, destination string) []byte {
	dest := encodeAX25Address(destination, false)
	src := encodeAX25Address(source, true)
	header := append(dest, src...)
	header = append(header, 0x03, 0xF0)
	return header
}

// ---------------------
// Packet Parsing
// ---------------------

// Packet represents a parsed data or ACK packet.
type Packet struct {
	Type           string // "data" or "ack"
	Sender         string
	Receiver       string
	FileID         string
	Seq            int
	BurstTo        int
	Total          int    // For header packets (seq==1), total number of data packets.
	Payload        []byte // Binary payload.
	RawInfo        string // The decoded info field.
	Ack            string // For ACK packets.
	EncodingMethod byte   // 0 = binary, 1 = base64 (only set in header packet)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// parsePacket parses an unescaped packet.
func parsePacket(packet []byte) *Packet {
	if len(packet) < 16 {
		return nil
	}
	// Extract receiver from the first 7 bytes and sender from the next 7 bytes.
	receiver := decodeAX25Address(packet[0:7])
	sender := decodeAX25Address(packet[7:14])
	infoAndPayload := packet[16:]

	// FIRST: Check if this is an ACK packet (including FIN-ACK).
	prefix := string(infoAndPayload[:min(50, len(infoAndPayload))])
	if strings.Contains(prefix, "ACK:") {
		fullInfo := string(infoAndPayload)
		partsAck := strings.Split(fullInfo, "ACK:")
		if len(partsAck) >= 2 {
			ackVal := strings.Trim(strings.Trim(partsAck[1], ":"), " ")
			return &Packet{
				Type:     "ack",
				Sender:   sender,
				Receiver: receiver,
				Ack:      ackVal,
				RawInfo:  fullInfo,
			}
		}
	}

	// Otherwise, treat as a data packet.
	// Use a simple heuristic: find the first two colons.
	firstColon := bytes.IndexByte(infoAndPayload, ':')
	if firstColon == -1 {
		return nil
	}
	secondColon := bytes.IndexByte(infoAndPayload[firstColon+1:], ':')
	if secondColon == -1 {
		return nil
	}
	infoFieldEnd := firstColon + 1 + secondColon + 1
	var infoField, payload []byte
	if infoFieldEnd < 32 {
		// Header packet: variable-length info field.
		infoField = infoAndPayload[:infoFieldEnd]
		payload = infoAndPayload[infoFieldEnd:]
	} else {
		// Data packet: fixed 32-byte info field.
		infoField = infoAndPayload[:32]
		payload = infoAndPayload[32:]
	}

	infoStr := string(infoField)
	parts := strings.Split(infoStr, ":")
	var fileID, seqBurst string
	if len(parts) == 3 {
		fileID = strings.TrimSpace(parts[0])
		seqBurst = strings.TrimSpace(parts[1])
	} else {
		if len(parts) < 4 {
			return nil
		}
		fileID = strings.TrimSpace(parts[1])
		seqBurst = strings.TrimSpace(parts[2])
	}

	var seq int
	var burstTo int
	total := 0
	if strings.Contains(seqBurst, "/") {
		if len(seqBurst) < 8 {
			return nil
		}
		seq = 1
		burstPart := seqBurst[4:8]
		b, err := strconv.ParseInt(burstPart, 16, 32)
		if err != nil {
			return nil
		}
		burstTo = int(b)
		spl := strings.Split(seqBurst, "/")
		if len(spl) < 2 {
			return nil
		}
		t, err := strconv.ParseInt(spl[1], 16, 32)
		if err != nil {
			return nil
		}
		total = int(t)
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

	var encodingMethod byte = 0
	if seq == 1 {
		headerFields := strings.Split(string(payload), "|")
		if len(headerFields) >= 10 {
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

// ---------------------
// Connection Interfaces and Implementations
// ---------------------

// KISSConnection defines methods for sending and receiving KISS frames.
type KISSConnection interface {
	SendFrame(frame []byte) error
	RecvData(timeout time.Duration) ([]byte, error)
	Close() error
}

// TCPKISSConnection implements KISSConnection over TCP.
type TCPKISSConnection struct {
	conn     net.Conn
	listener net.Listener // used in server mode
	isServer bool
	lock     sync.Mutex
}

func newTCPKISSConnection(host string, port int, isServer bool) (*TCPKISSConnection, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	tcpConn := &TCPKISSConnection{isServer: isServer}
	if isServer {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return nil, err
		}
		tcpConn.listener = ln
		log.Printf("[TCP Server] Listening on %s …", addr)
		conn, err := ln.Accept()
		if err != nil {
			return nil, err
		}
		tcpConn.conn = conn
		log.Printf("[TCP Server] Connection from %s", conn.RemoteAddr().String())
	} else {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			return nil, err
		}
		tcpConn.conn = conn
		log.Printf("[TCP Client] Connected to %s", addr)
	}
	return tcpConn, nil
}

func (t *TCPKISSConnection) SendFrame(frame []byte) error {
	t.lock.Lock()
	defer t.lock.Unlock()
	_, err := t.conn.Write(frame)
	return err
}

func (t *TCPKISSConnection) RecvData(timeout time.Duration) ([]byte, error) {
	t.conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1024)
	n, err := t.conn.Read(buf)
	if err != nil {
		// Return EOF and other errors instead of swallowing them
		if err == io.EOF {
			return nil, err
		}
		if nErr, ok := err.(net.Error); ok && nErr.Timeout() {
			return []byte{}, nil
		}
		return nil, err
	}
	return buf[:n], nil
}

func (t *TCPKISSConnection) Close() error {
	if t.conn != nil {
		t.conn.Close()
	}
	if t.isServer && t.listener != nil {
		t.listener.Close()
	}
	return nil
}

// SerialKISSConnection implements KISSConnection over a serial port.
type SerialKISSConnection struct {
	ser  serial.Port
	lock sync.Mutex
}

func newSerialKISSConnection(portName string, baud int) (*SerialKISSConnection, error) {
	mode := &serial.Mode{
		BaudRate: baud,
		DataBits: 8,
		Parity:   serial.NoParity,
		StopBits: serial.OneStopBit,
	}
	ser, err := serial.Open(portName, mode)
	if err != nil {
		return nil, err
	}
	// Set a read timeout of 100ms.
	if err := ser.SetReadTimeout(100 * time.Millisecond); err != nil {
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
			return nil, err
		}
		return nil, err
	}
	return buf[:n], nil
}

func (s *SerialKISSConnection) Close() error {
	return s.ser.Close()
}

// ---------------------
// Frame Reader
// ---------------------

// FrameReader continuously reads from a KISSConnection, extracts complete KISS frames,
// unescapes them, and sends the resulting packet bytes over a channel.
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
			// Suppress logging if the error is due to a closed connection.
			if !(err == io.EOF || strings.Contains(err.Error(), "use of closed network connection")) {
				log.Printf("Receive error: %v", err)
			}
			setLastDataTime(time.Unix(0, 0))
			fr.running = false
			break
		}
		if len(data) > 0 {
			// Update global lastDataTime when data is received.
			updateLastDataTime()
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

// ---------------------
// Receiver Data Structures and Functions
// ---------------------

// Transfer holds state for an incoming file transfer.
type Transfer struct {
	Sender           string
	Filename         string
	OrigSize         int
	CompSize         int
	MD5              string
	Compress         bool
	Packets          map[int][]byte
	BurstTo          int
	LastReceived     time.Time
	LastAckSent      time.Time
	RetryCount       int
	TimeoutSeconds   int     // now an integer
	TimeoutRetries   int
	RetryInterval    float64 // in seconds
	Total            int
	StartTime        time.Time
	BytesReceived    int
	DuplicateCount   int
	BurstBytes       int
	LastBurstAckTime time.Time
	EncodingMethod   byte // 0 = binary, 1 = Base64 (set from header)
	LastCumulativeAck int // New field to track the last acknowledged contiguous seq number
}

// computeCumulativeAck computes the highest contiguous sequence number received.
// If only the header is present, it returns "0001".
// Otherwise it returns "0001-XXXX" where XXXX is the highest contiguous packet.
func computeCumulativeAck(t *Transfer) string {
	var keys []int
	for k := range t.Packets {
		if k >= 2 {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return "0001"
	}
	maxSeq := 0
	for i := 2; ; i++ {
		if _, ok := t.Packets[i]; ok {
			maxSeq = i
		} else {
			break
		}
	}
	if maxSeq == 0 {
		return "0001"
	}
	return fmt.Sprintf("0001-%04X", maxSeq)
}

// sendAck builds and sends an ACK packet.
func sendAck(conn KISSConnection, myCallsign, remote, fileID, ackStr string) {
	// Directly use the AX.25 header for callsign formatting.
	// Build the AX.25 header with the sender (myCallsign) and receiver (remote) callsigns.
	ackPkt := append(buildAX25Header(myCallsign, remote), []byte(fmt.Sprintf("%s:ACK:%s", fileID, ackStr))...)
	// Build the KISS frame and send it.
	frame := buildKISSFrame(ackPkt)
	conn.SendFrame(frame)
	log.Printf("Sent ACK: %s for file %s", ackStr, fileID)
}

// ---------------------
// Command‑Line Arguments (Receiver‑Only)
// ---------------------

// Arguments holds the command‑line arguments.
type Arguments struct {
	MyCallsign       string  // Your callsign (required)
	Connection       string  // "tcp" or "serial"
	Debug            bool    // Enable debug output
	Host             string  // TCP host
	Port             int     // TCP port
	SerialPort       string  // Serial port (e.g. COM3 or /dev/ttyUSB0)
	Baud             int     // Baud rate for serial
	OneFile       	 bool    // Exit after successfully receiving one file
	OneFileHeaderTimeout int // Exit if no header seen within this period
	Execute          string  // If received file's name matches this, execute it with bash instead of saving.
	Replace          bool    // Overwrite existing files if a new file is received with the same name.
	OnlyFrom         string  // Only accept files from the specified callsign.
	ExecuteTimeout   float64 // Maximum seconds to allow executed file to run (0 means unlimited)
	Stdout           bool    // Output received file to stdout instead of saving
	TcpReadDeadline  int     // tcp-read-deadline (in seconds) for TCP inactivity detection.
	AllowedCallsigns string  // Comma delimited list of valid sender callsigns (optional; supports wildcards, e.g. MM5NDH-*,*-15)
	FileID           string  // Specify file ID
}

func parseArguments() *Arguments {
	args := &Arguments{}
	flag.StringVar(&args.MyCallsign, "my-callsign", "", "Your callsign (required)")
	flag.StringVar(&args.Connection, "connection", "tcp", "Connection type: tcp or serial")
	flag.BoolVar(&args.Debug, "debug", false, "Enable debug output")
	flag.StringVar(&args.Host, "host", "127.0.0.1", "TCP host")
	flag.IntVar(&args.Port, "port", 9001, "TCP port")
	flag.StringVar(&args.SerialPort, "serial-port", "", "Serial port (e.g. COM3 or /dev/ttyUSB0)")
	flag.IntVar(&args.Baud, "baud", 115200, "Baud rate for serial")
	flag.BoolVar(&args.OneFile, "one-file", false, "Exit after successfully receiving one file")
	flag.IntVar(&args.OneFileHeaderTimeout, "one-file-header-timeout", 0, "Timeout in seconds to wait for a header packet in one-file mode (0 means never timeout)")
	flag.StringVar(&args.Execute, "execute", "", "If received file's name matches this, execute it with bash instead of saving")
	flag.BoolVar(&args.Replace, "replace", false, "Overwrite existing files if a new file is received with the same name")
	flag.Float64Var(&args.ExecuteTimeout, "execute-timeout", 0, "Maximum seconds to allow executed file to run (0 means unlimited)")
	flag.BoolVar(&args.Stdout, "stdout", false, "Output the received file to stdout instead of saving to disk")
	flag.IntVar(&args.TcpReadDeadline, "tcp-read-deadline", 600, "Time (in seconds) without data before triggering reconnect (TCP only)")
	flag.StringVar(&args.AllowedCallsigns, "callsigns", "", "Comma delimited list of valid sender callsigns (optional; supports wildcards, e.g. MM5NDH-*,*-15)")
	flag.StringVar(&args.FileID, "fileid", "", "Specify file ID (2 alphanumeric characters). Only allowed with --one-file.")
	flag.Parse()

	if args.MyCallsign == "" {
		log.Fatalf("--my-callsign is required.")
	}
	if args.Connection == "serial" && args.SerialPort == "" {
		log.Fatalf("--serial-port is required for serial connection.")
	}
	if args.FileID != "" {
		if !args.OneFile {
			log.Fatalf("--fileid can only be used with --one-file.")
		}
		if len(args.FileID) != 2 {
			log.Fatalf("--fileid must be exactly 2 characters long.")
		}
		// Check that each character is alphanumeric.
		for _, ch := range args.FileID {
			if !(('0' <= ch && ch <= '9') || ('A' <= ch && ch <= 'Z') || ('a' <= ch && ch <= 'z')) {
				log.Fatalf("--fileid must contain only alphanumeric characters.")
			}
		}
	}
	return args
}

// ---------------------
// Receiver Main Function
// ---------------------

func receiverMain(args *Arguments) {
	if args.AllowedCallsigns != "" {
		for _, cs := range strings.Split(args.AllowedCallsigns, ",") {
			cs = strings.ToUpper(strings.TrimSpace(cs))
			if cs != "" {
				allowedCallsigns = append(allowedCallsigns, cs)
			}
		}
		log.Printf("Allowed callsign patterns: %v", allowedCallsigns)
	}
	var conn KISSConnection
	var err error
	headerStartTime := time.Now()
	if args.Connection == "tcp" {
		conn, err = newTCPKISSConnection(args.Host, args.Port, false)
		if err != nil {
			log.Fatalf("TCP connection error: %v", err)
		}
	} else {
		conn, err = newSerialKISSConnection(args.SerialPort, args.Baud)
		if err != nil {
			log.Fatalf("Serial connection error: %v", err)
		}
	}
	// Set the initial lastDataTime
	updateLastDataTime()

	frameChan := make(chan []byte, 100)
	reader := NewFrameReader(conn, frameChan)
	go reader.Run()
	log.Printf("Receiver started. My callsign: %s", strings.ToUpper(args.MyCallsign))
	transfers := make(map[string]*Transfer)

	// ---------------------
	// TCP Inactivity Monitor & Reconnect Logic
	// ---------------------
	if args.Connection == "tcp" {
		tcpTimeout := time.Duration(args.TcpReadDeadline) * time.Second
		go func() {
			for {
				time.Sleep(1 * time.Second)
				lastDataMutex.Lock()
				last := lastDataTime
				lastDataMutex.Unlock()
				if time.Since(last) > tcpTimeout {
					log.Printf("No data received for %v; triggering reconnect...", tcpTimeout)
					// Stop the current frame reader and close the connection.
					reader.Stop()
					conn.Close()
					// Attempt to reconnect in a loop.
					var newConn KISSConnection
					for {
						log.Println("Attempting to reconnect in 5 seconds...")
						time.Sleep(5 * time.Second)
						newConn, err = newTCPKISSConnection(args.Host, args.Port, false)
						if err != nil {
							log.Printf("Reconnect failed: %v", err)
						} else {
							break
						}
					}
					conn = newConn
					// Reset the lastDataTime.
					updateLastDataTime()
					// Start a new frame reader with the new connection.
					reader = NewFrameReader(conn, frameChan)
					go reader.Run()
					log.Println("Reconnected successfully to the TCP device.")
				}
			}
		}()
	}

	// Main receiver loop.
	for {
		select {
		case pktBytes := <-frameChan:
			parsed := parsePacket(pktBytes)
			if parsed == nil {
				log.Printf("Could not parse packet.")
				continue
			}
			if parsed.Type == "ack" {
				log.Printf("Received an ACK packet (ignored on receiver).")
				continue
			}
			if args.FileID != "" && parsed.FileID != args.FileID {
				log.Printf("Ignoring packet: fileid mismatch (got %s, expected %s).", parsed.FileID, args.FileID)
				continue
			}
			seq := parsed.Seq
			fileID := parsed.FileID
			sender := parsed.Sender
			receiverStr := parsed.Receiver
			log.Printf("Received data packet: seq=%d, file_id=%s, burst_to=%d, sender=%s, receiver=%s", seq, fileID, parsed.BurstTo, sender, receiverStr)
			localCS := strings.ToUpper(strings.TrimSpace(args.MyCallsign))
			if strings.ToUpper(strings.TrimSpace(receiverStr)) != localCS {
				log.Printf("Packet intended for %s, not me (%s). Ignoring.", receiverStr, localCS)
				continue
			}

			// If allowed callsigns are set, filter based on them.
			if len(allowedCallsigns) > 0 {
				if !callsignAllowed(parsed.Sender) {
					log.Printf("Dropping packet for file %s from %s: sender callsign not allowed",
						parsed.FileID, parsed.Sender)
					continue
				}
			}

			// If the transfer has not yet started, only accept header packets (seq == 1)
			if _, ok := transfers[fileID]; !ok {
				if seq != 1 {
					log.Printf("Received non-header packet (seq=%d) for unknown transfer %s. Ignoring.", seq, fileID)
					continue
				}
				// Process header packet to start new transfer.
				headerPayload := parsed.Payload
				headerInfo := string(headerPayload)
				parts := strings.Split(headerInfo, "|")
				if len(parts) < 10 {
					log.Printf("Invalid header info – ignoring transfer.")
					continue
				}
				transferTimeoutSeconds, _ := strconv.Atoi(parts[0])
				transferTimeoutRetries, _ := strconv.Atoi(parts[1])
				filename := parts[2]
				origSize, _ := strconv.Atoi(parts[3])
				compSize, _ := strconv.Atoi(parts[4])
				md5Hash := parts[5]
				encodingMethodVal, _ := strconv.Atoi(parts[7])
				compFlag := parts[8]
				totalPackets, _ := strconv.Atoi(parts[9])
				compress := (compFlag == "1")
				transfers[fileID] = &Transfer{
					Sender:           sender,
					Filename:         filename,
					OrigSize:         origSize,
					CompSize:         compSize,
					MD5:              md5Hash,
					Compress:         compress,
					Packets:          make(map[int][]byte),
					BurstTo:          parsed.BurstTo,
					LastReceived:     time.Now(),
					LastAckSent:      time.Now(),
					RetryCount:       0,
					TimeoutSeconds:   transferTimeoutSeconds,
					TimeoutRetries:   transferTimeoutRetries,
					RetryInterval:    float64(transferTimeoutSeconds),
					Total:            totalPackets,
					StartTime:        time.Now(),
					BytesReceived:    0,
					DuplicateCount:   0,
					BurstBytes:       0,
					LastBurstAckTime: time.Now(),
					EncodingMethod:   byte(encodingMethodVal),
				}
				log.Printf("Started transfer from %s (File: %s, ID: %s)", sender, filename, fileID)
				log.Printf("Total packets required (including header): %d", totalPackets)
				sendAck(conn, args.MyCallsign, sender, fileID, "0001")
				continue
			} else {
				// Transfer already exists.
				// If a duplicate header packet (seq==1) is received, ignore it.
				if seq == 1 {
					log.Printf("Duplicate header packet received for file %s; ignoring.", fileID)
					continue
				}
			}

			transfer := transfers[fileID]
			transfer.LastReceived = time.Now()
			transfer.RetryInterval = float64(transfer.TimeoutSeconds)
			if parsed.BurstTo > transfer.BurstTo {
				transfer.BurstTo = parsed.BurstTo
			}
			if _, exists := transfer.Packets[seq]; exists {
    			    transfer.DuplicateCount++
			    log.Printf("Duplicate packet seq %d received; duplicates so far: %d.", seq, transfer.DuplicateCount)
	                    // If this duplicate's sequence equals the burst marker, send the cumulative ACK immediately.
			    if seq == transfer.BurstTo {
			        ackRange := computeCumulativeAck(transfer)
			        sendAck(conn, args.MyCallsign, sender, fileID, ackRange)
			        transfer.LastAckSent = time.Now()
			    }
			    continue
			}


			transfer.Packets[seq] = parsed.Payload
			transfer.BytesReceived += len(parsed.Payload)
			transfer.BurstBytes += len(parsed.Payload)
			// Compute the new cumulative ACK string
			newCumulativeAckStr := computeCumulativeAck(transfer)
			// Convert the ACK string to an integer (we assume the format is "0001-XXXX")
			var newCumulativeAck int
			if newCumulativeAckStr == "0001" {
			    newCumulativeAck = 1
			} else {
			    // Scanf will parse the XXXX hex value
			    fmt.Sscanf(newCumulativeAckStr, "0001-%04X", &newCumulativeAck)
			}
			
			// If the contiguous block has grown, update LastCumulativeAck and send a new ACK
			if newCumulativeAck > transfer.LastCumulativeAck {
			    transfer.LastCumulativeAck = newCumulativeAck
			    transfer.RetryCount = 0
			    transfer.RetryInterval = float64(transfer.TimeoutSeconds)
			    // Optionally, log that the contiguous block has increased:
			    log.Printf("Updated cumulative ACK to %s", newCumulativeAckStr)
			}

if transfer.BurstTo != 0 && seq == transfer.BurstTo {
    // First, compute the current contiguous (cumulative) ACK.
    ackRange := computeCumulativeAck(transfer)
    var contig int
    if ackRange == "0001" {
        contig = 1
    } else {
        // Parse the hex part of the ACK string.
        fmt.Sscanf(ackRange, "0001-%04X", &contig)
    }
    // Only send an immediate ACK if the contiguous block extends to burst_to.
    if contig == transfer.BurstTo {
        now := time.Now()
        burstDuration := now.Sub(transfer.LastBurstAckTime).Seconds()
        burstRate := float64(transfer.BurstBytes) / burstDuration
        overallElapsed := now.Sub(transfer.StartTime).Seconds()
        overallRate := float64(transfer.BytesReceived) / overallElapsed
        progress := (float64(transfer.BytesReceived) / float64(transfer.CompSize)) * 100
        var eta float64
        if overallRate > 0 {
            eta = float64(transfer.CompSize-transfer.BytesReceived) / overallRate
        }
        log.Printf("--- Stats ---")
        log.Printf("Previous burst: %d bytes in %.2fs (%.2f bytes/s)", transfer.BurstBytes, burstDuration, burstRate)
        log.Printf("Overall: %d/%d bytes (%.2f%%), elapsed: %.2fs, ETA: %.2fs", transfer.BytesReceived, transfer.CompSize, progress, overallElapsed, eta)
        log.Printf("Overall bytes/sec: %.2f bytes/s", overallRate)
        log.Printf("--------------")
        sendAck(conn, args.MyCallsign, sender, fileID, ackRange)
        transfer.LastAckSent = time.Now()
        transfer.BurstBytes = 0
        transfer.LastBurstAckTime = now
        transfer.RetryCount = 0
        transfer.RetryInterval = float64(transfer.TimeoutSeconds)
    } else {
        // Not all contiguous packets are received.
        log.Printf("Not all contiguous packets are present (contiguous up to %04X, burst_to %04X); waiting for timeout.", contig, transfer.BurstTo)
    }
}

			// Check if all expected packets (excluding header) have been received.
			if transfer.Total > 0 && len(transfer.Packets) == transfer.Total-1 {
				overallElapsed := time.Since(transfer.StartTime).Seconds()
				overallRate := float64(transfer.BytesReceived) / overallElapsed
				log.Printf("=== Receiver Final Summary for file %s ===", fileID)
				log.Printf("Total bytes received: %d bytes in %.2fs (%.2f bytes/s), Duplicates: %d.",
					transfer.BytesReceived, overallElapsed, overallRate, transfer.DuplicateCount)
				log.Printf("===============================================")
				log.Printf("Transfer complete for file %s. Reassembling file …", fileID)
				var fileDataBuffer bytes.Buffer
				complete := true
				for i := 2; i <= transfer.Total; i++ {
					part, ok := transfer.Packets[i]
					if !ok {
						log.Printf("Missing packet %d – cannot reassemble.", i)
						complete = false
						break
					}
					// Use the encoding method from the header.
					if transfer.EncodingMethod == 1 {
						decoded, err := base64.StdEncoding.DecodeString(string(part))
						if err != nil {
							log.Printf("Error decoding base64 for packet %d: %v", i, err)
							complete = false
							break
						}
						fileDataBuffer.Write(decoded)
					} else {
						fileDataBuffer.Write(part)
					}
				}
				if !complete {
					continue
				}
				fullData := fileDataBuffer.Bytes()
				if transfer.Compress {
					b := bytes.NewReader(fullData)
					zr, err := zlib.NewReader(b)
					if err != nil {
						log.Printf("Decompression error: %v", err)
						continue
					}
					decompressed, err := ioutil.ReadAll(zr)
					zr.Close()
					if err != nil {
						log.Printf("Decompression error: %v", err)
						continue
					}
					fullData = decompressed
				}
				calculatedMD5 := md5.Sum(fullData)
				calculatedMD5Str := hex.EncodeToString(calculatedMD5[:])
				if calculatedMD5Str == transfer.MD5 {
					log.Printf("Checksum OK.")
				} else {
					log.Printf("Checksum mismatch! (Expected: %s, Got: %s)", transfer.MD5, calculatedMD5Str)
				}

				// Output or process the file based on options.
				if args.Stdout {
					log.Printf("Outputting received file %s to stdout.", transfer.Filename)
					_, err = os.Stdout.Write(fullData)
					if err != nil {
						log.Printf("Error writing to stdout: %v", err)
					}
				} else if args.Execute != "" && transfer.Filename == args.Execute {
					log.Printf("Received file %s matches -execute option; executing file instead of saving.", transfer.Filename)
					tmpFile, err := ioutil.TempFile("", "rxexec-")
					if err != nil {
						log.Printf("Error creating temporary file for execution: %v", err)
						continue
					}
					tmpName := tmpFile.Name()
					tmpFile.Close()
					err = ioutil.WriteFile(tmpName, fullData, 0755)
					if err != nil {
						log.Printf("Error writing to temporary file: %v", err)
						os.Remove(tmpName)
						continue
					}
					log.Printf("Executing file %s asynchronously", tmpName)
					cmd := exec.Command("bash", tmpName)
					cmd.Stdout = os.Stdout
					cmd.Stderr = os.Stderr
					cmd.Stdin = os.Stdin
					if err = cmd.Start(); err != nil {
						log.Printf("Error executing file: %v", err)
						os.Remove(tmpName)
						continue
					}
					go func(tmpName string, cmd *exec.Cmd, timeout float64) {
						if timeout > 0 {
							log.Printf("Execution timeout is set to %.2f seconds", timeout)
							done := make(chan error, 1)
							go func() {
								done <- cmd.Wait()
							}()
							select {
							case err := <-done:
								if err != nil {
									log.Printf("Asynchronous execution finished with error: %v", err)
								} else {
									log.Printf("Asynchronous execution finished successfully.")
								}
							case <-time.After(time.Duration(timeout) * time.Second):
								log.Printf("Execution of file %s exceeded timeout of %.2f seconds. Killing process.", tmpName, timeout)
								if err := cmd.Process.Kill(); err != nil {
									log.Printf("Failed to kill process: %v", err)
								}
								err := <-done
								if err != nil {
									log.Printf("Asynchronous execution finished with error after killing process: %v", err)
								}
							}
						} else {
							err := cmd.Wait()
							if err != nil {
								log.Printf("Asynchronous execution finished with error: %v", err)
							} else {
								log.Printf("Asynchronous execution finished successfully.")
							}
						}
						os.Remove(tmpName)
					}(tmpName, cmd, args.ExecuteTimeout)
				} else {
					var outname string
					if args.Replace {
						outname = transfer.Filename
					} else {
						outname = transfer.Filename
						base := outname
						ext := ""
						if dot := strings.LastIndex(outname, "."); dot != -1 {
							base = outname[:dot]
							ext = outname[dot:]
						}
						cnt := 1
						for {
							if _, err := os.Stat(outname); os.IsNotExist(err) {
								break
							}
							outname = fmt.Sprintf("%s_%d%s", base, cnt, ext)
							cnt++
						}
					}
					err = ioutil.WriteFile(outname, fullData, 0644)
					if err != nil {
						log.Printf("Error saving file: %v", err)
					} else {
						log.Printf("Saved received file as %s", outname)
					}
				}
				log.Printf("Waiting for sender's final confirmation (FIN-ACK)...")
				var finalConfirmation string
				retries := 0
				for finalConfirmation == "" && retries < transfer.TimeoutRetries {
					select {
					case ackPkt := <-frameChan:
						parsedAck := parsePacket(ackPkt)
						if parsedAck != nil && parsedAck.Type == "ack" && strings.Contains(parsedAck.Ack, "FIN-ACK") {
							finalConfirmation = parsedAck.Ack
							log.Printf("Received sender's final confirmation FIN-ACK.")
						}
					case <-time.After(time.Duration(transfer.TimeoutSeconds) * time.Second):
						retries++
						log.Printf("Timeout waiting for final confirmation (FIN-ACK) (retry %d/%d). Resending cumulative ACK.", retries, transfer.TimeoutRetries)
						ackRange := computeCumulativeAck(transfer)
						sendAck(conn, args.MyCallsign, sender, fileID, ackRange)
					}
				}
				if finalConfirmation == "" {
					log.Printf("Final confirmation FIN-ACK not received after maximum retries.")
				} else {
					log.Printf("Final handshake completed successfully.")
				}
				delete(transfers, fileID)
				if args.OneFile {
					log.Printf("Received one file successfully. Exiting receiver mode as --one-file flag is set.")
					reader.Stop()
					conn.Close()
					return
				}
			}
		case <-time.After(500 * time.Millisecond):
    			if args.OneFile && args.OneFileHeaderTimeout > 0 && len(transfers) == 0 {
			        if time.Since(headerStartTime) >= time.Duration(args.OneFileHeaderTimeout)*time.Second {
        			        log.Printf("Header packet timeout: no header received within %d seconds. Exiting.", args.OneFileHeaderTimeout)
	        		        os.Exit(1)
        			}
    			}
			now := time.Now()
			for fid, transfer := range transfers {
				lastEvent := transfer.LastReceived
				if transfer.LastAckSent.After(lastEvent) {
					lastEvent = transfer.LastAckSent
				}
				if now.Sub(lastEvent).Seconds() >= transfer.RetryInterval {
					if transfer.RetryCount < transfer.TimeoutRetries {
						ackRange := computeCumulativeAck(transfer)
						sendAck(conn, args.MyCallsign, transfer.Sender, fid, ackRange)
						transfer.LastAckSent = now
						transfer.RetryCount++
						log.Printf("Resent ACK %s for file %s due to inactivity (retry %d/%d, interval %.2fs).",
							ackRange, fid, transfer.RetryCount, transfer.TimeoutRetries, transfer.RetryInterval)
						transfer.RetryInterval *= 1.5
					} else {
						log.Printf("Giving up on transfer %s after %d ACK retries due to inactivity.", fid, transfer.TimeoutRetries)
						delete(transfers, fid)
						if args.OneFile {
					            log.Printf("Exiting receiver in one-file mode due to transfer timeout.")
					            os.Exit(1)
					        }
					}
				}
			}
		}
	}
}

// ---------------------
// Main
// ---------------------

func main() {
	rand.Seed(time.Now().UnixNano())
	log.SetFlags(log.LstdFlags)
	args := parseArguments()
	if args.Debug {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	}
	receiverMain(args)
}
