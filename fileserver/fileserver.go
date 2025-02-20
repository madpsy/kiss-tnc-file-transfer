// fileserver.go
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"go.bug.st/serial"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Global constants for KISS framing.
const (
	KISS_FLAG     = 0xC0
	KISS_CMD_DATA = 0x00
)

// Global variable for server's callsign.
var serverCallsign string

// Command-line arguments structure.
type Arguments struct {
	MyCallsign       string // your own callsign
	Connection       string // "tcp" or "serial"
	Host             string // used with TCP
	Port             int    // used with TCP
	SerialPort       string // used with serial
	Baud             int    // used with serial
	AllowedCallsigns string // comma-delimited list for filtering sender callsigns
	Directory        string // directory to serve files from (mandatory)
	SenderBinary     string // path to the binary used to send files (mandatory)
}

func parseArguments() *Arguments {
	args := &Arguments{}
	flag.StringVar(&args.MyCallsign, "my-callsign", "", "Your callsign (required)")
	flag.StringVar(&args.Connection, "connection", "tcp", "Connection type: tcp or serial")
	flag.StringVar(&args.Host, "host", "127.0.0.1", "TCP host (if connection is tcp)")
	flag.IntVar(&args.Port, "port", 9001, "TCP port (if connection is tcp)")
	flag.StringVar(&args.SerialPort, "serial-port", "", "Serial port (e.g., COM3 or /dev/ttyUSB0)")
	flag.IntVar(&args.Baud, "baud", 115200, "Baud rate for serial connection")
	flag.StringVar(&args.AllowedCallsigns, "callsigns", "", "Comma delimited list of allowed sender callsign patterns (supports wildcards, e.g. MM5NDH-*,*-15)")
	flag.StringVar(&args.Directory, "directory", "", "Directory to serve files from (mandatory)")
	flag.StringVar(&args.SenderBinary, "sender-binary", "", "Path to the binary used to send files (mandatory)")
	flag.Parse()

	if args.MyCallsign == "" {
		log.Fatalf("--my-callsign is required.")
	}
	if args.Connection == "serial" && args.SerialPort == "" {
		log.Fatalf("--serial-port is required for serial connection.")
	}
	if args.Directory == "" {
		log.Fatalf("--directory is required.")
	}
	if args.SenderBinary == "" {
		log.Fatalf("--sender-binary is required.")
	}
	return args
}

// KISSConnection is the minimal interface we need.
type KISSConnection interface {
	RecvData(timeout time.Duration) ([]byte, error)
	Close() error
}

// TCPKISSConnection implements KISSConnection over TCP.
type TCPKISSConnection struct {
	conn net.Conn
	lock sync.Mutex
}

func newTCPKISSConnection(host string, port int) (*TCPKISSConnection, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	log.Printf("[TCP] Connected to %s", addr)
	return &TCPKISSConnection{conn: conn}, nil
}

func (t *TCPKISSConnection) RecvData(timeout time.Duration) ([]byte, error) {
	t.conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1024)
	n, err := t.conn.Read(buf)
	if err != nil {
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
	return t.conn.Close()
}

// SerialKISSConnection implements KISSConnection over serial.
type SerialKISSConnection struct {
	ser serial.Port
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
	// Set a read timeout.
	if err := ser.SetReadTimeout(100 * time.Millisecond); err != nil {
		return nil, err
	}
	log.Printf("[Serial] Opened %s at %d baud", portName, baud)
	return &SerialKISSConnection{ser: ser}, nil
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

// Helper: unescapeData reverses KISS escaping.
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

// Helper: extractKISSFrames extracts complete KISS frames from a buffer.
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

// encodeAX25Address now supports SSIDs.
// It splits the callsign on "-" (if present), pads/truncates the base callsign to 6 characters,
// and encodes an optional SSID (if any) in the lower 4 bits of the 7th byte.
func encodeAX25Address(callsign string, isLast bool) []byte {
	parts := strings.Split(callsign, "-")
	base := strings.ToUpper(strings.TrimSpace(parts[0]))
	var ssid int
	if len(parts) > 1 {
		fmt.Sscanf(parts[1], "%d", &ssid)
	}
	if len(base) < 6 {
		base = base + strings.Repeat(" ", 6-len(base))
	} else if len(base) > 6 {
		base = base[:6]
	}
	addr := make([]byte, 7)
	for i := 0; i < 6; i++ {
		addr[i] = base[i] << 1
	}
	// Encode the SSID into the lower 4 bits (shifted left by 1) plus the constant 0x60.
	addr[6] = byte((ssid & 0x0F) << 1) | 0x60
	if isLast {
		addr[6] |= 0x01
	}
	return addr
}

// decodeAX25Address decodes a 7-byte AX.25 address field,
// reconstructing the base callsign and appending the SSID if non-zero.
func decodeAX25Address(addr []byte) string {
	if len(addr) < 7 {
		return ""
	}
	var call bytes.Buffer
	for i := 0; i < 6; i++ {
		call.WriteByte(addr[i] >> 1)
	}
	base := strings.TrimSpace(call.String())
	ssid := (addr[6] >> 1) & 0x0F
	if ssid != 0 {
		return fmt.Sprintf("%s-%d", base, ssid)
	}
	return base
}

// parseCommandPacket tries to parse a command packet.
// It now expects an unescaped packet with at least 80 bytes:
// 16 bytes AX.25 header + 64 bytes command info field.
func parseCommandPacket(packet []byte) (sender, command string, ok bool) {
	if len(packet) < 80 {
		return "", "", false
	}
	header := packet[:16]

	// Extract destination callsign from the first 7 bytes.
	dest := decodeAX25Address(header[0:7])
	if dest != serverCallsign {
		log.Printf("Dropping packet: destination %s does not match our callsign %s", dest, serverCallsign)
		return "", "", false
	}

	// Now extract 64 bytes of command info.
	infoField := packet[16:80]
	infoStr := strings.TrimSpace(string(infoField))
	if !strings.HasPrefix(infoStr, "CMD:") {
		return "", "", false
	}
	command = strings.TrimSpace(infoStr[4:])

	// The sender's callsign is stored in the second 7-byte block of the header.
	sender = decodeAX25Address(header[7:14])
	return sender, command, true
}

// Global slice for allowed sender callsigns.
var allowedCallsigns []string

// callsignAllowed returns true if the given callsign matches any allowed pattern.
func callsignAllowed(cs string) bool {
	cs = strings.ToUpper(strings.TrimSpace(cs))
	for _, pattern := range allowedCallsigns {
		if match, err := filepath.Match(pattern, cs); err == nil && match {
			return true
		}
	}
	return false
}

// listFiles returns a newline-separated list of file names in the specified directory.
func listFiles(dir string) (string, error) {
	entries, err := ioutil.ReadDir(dir)
	if err != nil {
		return "", err
	}
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() {
			names = append(names, entry.Name())
		}
	}
	return strings.Join(names, "\n"), nil
}

// invokeSenderBinary constructs and executes the sender binary.
// It passes the following arguments:
//   - Connection options (-connection, and either -host/-port or -serial-port/-baud)
//   - -my-callsign (our own callsign)
//   - -receiver-callsign (set to the sender’s callsign from the command packet)
//   - -stdin flag (tells sender-binary to read from stdin)
//   - -file-name (as specified)
// If inputData is non-empty, it is piped to the sender binary via stdin;
// otherwise, os.Stdin is used.
//
// This version streams the sender binary's output in real time.
func invokeSenderBinary(args *Arguments, receiverCallsign, fileName, inputData string) {
	var cmdArgs []string
	cmdArgs = append(cmdArgs, fmt.Sprintf("-connection=%s", args.Connection))
	if strings.ToLower(args.Connection) == "tcp" {
		cmdArgs = append(cmdArgs, fmt.Sprintf("-host=%s", args.Host), fmt.Sprintf("-port=%d", args.Port))
	} else {
		cmdArgs = append(cmdArgs, fmt.Sprintf("-serial-port=%s", args.SerialPort), fmt.Sprintf("-baud=%d", args.Baud))
	}
	cmdArgs = append(cmdArgs, fmt.Sprintf("-my-callsign=%s", args.MyCallsign))
	cmdArgs = append(cmdArgs, fmt.Sprintf("-receiver-callsign=%s", receiverCallsign))
	cmdArgs = append(cmdArgs, "-stdin")
	cmdArgs = append(cmdArgs, fmt.Sprintf("-file-name=%s", fileName))
	fullCmd := fmt.Sprintf("%s %s", args.SenderBinary, strings.Join(cmdArgs, " "))
	log.Printf("Invoking sender binary: %s", fullCmd)

	cmd := exec.Command(args.SenderBinary, cmdArgs...)
	if inputData != "" {
		cmd.Stdin = strings.NewReader(inputData)
	} else {
		cmd.Stdin = os.Stdin
	}

	// Set up pipes for stdout and stderr.
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		log.Printf("Error obtaining stdout pipe: %v", err)
		return
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		log.Printf("Error obtaining stderr pipe: %v", err)
		return
	}

	// Start the command.
	if err := cmd.Start(); err != nil {
		log.Printf("Error starting sender binary: %v", err)
		return
	}

	// Stream stdout.
	go func() {
		scanner := bufio.NewScanner(stdoutPipe)
		for scanner.Scan() {
			log.Printf("[sender stdout] %s", scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			log.Printf("Error reading sender stdout: %v", err)
		}
	}()

	// Stream stderr.
	go func() {
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			log.Printf("[sender stderr] %s", scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			log.Printf("Error reading sender stderr: %v", err)
		}
	}()

	// Wait for the command to complete.
	if err := cmd.Wait(); err != nil {
		log.Printf("Sender binary exited with error: %v", err)
	} else {
		log.Printf("Sender binary completed successfully.")
	}
}

func main() {
	args := parseArguments()

	// Set server callsign from the parsed arguments.
	serverCallsign = strings.ToUpper(args.MyCallsign)

	log.Printf("Serving files from directory: %s", args.Directory)
	log.Printf("Sender binary set to: %s", args.SenderBinary)

	if args.AllowedCallsigns != "" {
		for _, cs := range strings.Split(args.AllowedCallsigns, ",") {
			cs = strings.ToUpper(strings.TrimSpace(cs))
			if cs != "" {
				allowedCallsigns = append(allowedCallsigns, cs)
			}
		}
		log.Printf("Allowed sender callsign patterns: %v", allowedCallsigns)
	} else {
		log.Printf("No callsign filtering enabled.")
	}

	var conn KISSConnection
	var err error
	if strings.ToLower(args.Connection) == "tcp" {
		conn, err = newTCPKISSConnection(args.Host, args.Port)
		if err != nil {
			log.Fatalf("TCP connection error: %v", err)
		}
	} else {
		conn, err = newSerialKISSConnection(args.SerialPort, args.Baud)
		if err != nil {
			log.Fatalf("Serial connection error: %v", err)
		}
	}
	defer conn.Close()

	log.Printf("File Server started. My callsign: %s", serverCallsign)

	var buffer []byte
	for {
		data, err := conn.RecvData(100 * time.Millisecond)
		if err != nil {
			log.Printf("Receive error: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if len(data) > 0 {
			buffer = append(buffer, data...)
			frames, remaining := extractKISSFrames(buffer)
			buffer = remaining
			for _, frame := range frames {
				if len(frame) < 2 || frame[0] != KISS_FLAG || frame[len(frame)-1] != KISS_FLAG {
					continue
				}
				inner := frame[2 : len(frame)-1]
				unesc := unescapeData(inner)
				sender, command, ok := parseCommandPacket(unesc)
				if !ok {
					continue
				}
				if len(allowedCallsigns) > 0 && !callsignAllowed(sender) {
					log.Printf("Dropping command from sender %s: not allowed.", sender)
					continue
				}
				log.Printf("Received command '%s' from sender %s", command, sender)

				upperCmd := strings.ToUpper(command)
				if strings.HasPrefix(upperCmd, "GET ") {
					// Everything after "GET " is the filename, supporting spaces.
					fileName := strings.TrimSpace(command[4:])
					fullPath := filepath.Join(args.Directory, fileName)
					if _, err := os.Stat(fullPath); err != nil {
						log.Printf("Requested file '%s' does not exist in directory %s", fileName, args.Directory)
						continue
					}
					data, err := ioutil.ReadFile(fullPath)
					if err != nil {
						log.Printf("Error reading file '%s': %v", fullPath, err)
						continue
					}
					invokeSenderBinary(args, sender, fileName, string(data))
				} else if upperCmd == "LIST" {
					fileList, err := listFiles(args.Directory)
					if err != nil {
						log.Printf("Error listing files: %v", err)
						continue
					}
					invokeSenderBinary(args, sender, "LIST.txt", fileList)
				} else {
					log.Printf("Unrecognized command: %s", command)
				}
			}
		}
	}
}
