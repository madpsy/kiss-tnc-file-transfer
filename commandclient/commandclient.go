// commandclient.go
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"go.bug.st/serial"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Global constants for KISS framing.
const (
	KISS_FLAG     = 0xC0
	KISS_CMD_DATA = 0x00
)

// Global debug flag.
var debugEnabled bool

// Command-line arguments structure.
type Arguments struct {
	MyCallsign         string // your own callsign
	FileServerCallsign string // target file server's callsign
	Connection         string // "tcp" or "serial"
	Host               string // used with TCP
	Port               int    // used with TCP
	SerialPort         string // used with serial
	Baud               int    // used with serial
	ReceiverPort       int    // port for transparent passthrough (TCP listener)
	ReceiverBinary     string // path to the receiver binary
	Debug              bool   // enable debug logging
}

func parseArguments() *Arguments {
	args := &Arguments{}
	flag.StringVar(&args.MyCallsign, "my-callsign", "", "Your callsign (required)")
	flag.StringVar(&args.FileServerCallsign, "file-server-callsign", "", "File server's callsign (required)")
	flag.StringVar(&args.Connection, "connection", "tcp", "Connection type: tcp or serial")
	flag.StringVar(&args.Host, "host", "127.0.0.1", "TCP host (if connection is tcp)")
	flag.IntVar(&args.Port, "port", 9001, "TCP port (if connection is tcp)")
	flag.StringVar(&args.SerialPort, "serial-port", "", "Serial port (e.g., COM3 or /dev/ttyUSB0)")
	flag.IntVar(&args.Baud, "baud", 115200, "Baud rate for serial connection")
	flag.IntVar(&args.ReceiverPort, "receiver-port", 5012, "TCP port for transparent passthrough (default 5012)")
	flag.StringVar(&args.ReceiverBinary, "receiver-binary", "receiver", "Path to the receiver binary")
	flag.BoolVar(&args.Debug, "debug", false, "Enable debug logging")
	flag.Parse()

	if args.MyCallsign == "" {
		log.Fatalf("--my-callsign is required.")
	}
	if args.FileServerCallsign == "" {
		log.Fatalf("--file-server-callsign is required.")
	}
	if args.Connection == "serial" && args.SerialPort == "" {
		log.Fatalf("--serial-port is required for serial connection.")
	}
	return args
}

// KISSConnection defines methods for sending frames and reading/writing data.
type KISSConnection interface {
	SendFrame(frame []byte) error
	Close() error
	io.ReadWriteCloser
}

// TCPKISSConnection implements KISSConnection over TCP.
type TCPKISSConnection struct {
	conn net.Conn
}

func newTCPKISSConnection(host string, port int) (*TCPKISSConnection, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	if debugEnabled {
		log.Printf("[TCP] Connected to %s", addr)
	}
	return &TCPKISSConnection{conn: conn}, nil
}

func (t *TCPKISSConnection) SendFrame(frame []byte) error {
	_, err := t.conn.Write(frame)
	return err
}

func (t *TCPKISSConnection) Read(b []byte) (int, error) {
	return t.conn.Read(b)
}

func (t *TCPKISSConnection) Write(b []byte) (int, error) {
	return t.conn.Write(b)
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
	if err := ser.SetReadTimeout(100 * time.Millisecond); err != nil {
		return nil, err
	}
	if debugEnabled {
		log.Printf("[Serial] Opened %s at %d baud", portName, baud)
	}
	return &SerialKISSConnection{ser: ser}, nil
}

func (s *SerialKISSConnection) SendFrame(frame []byte) error {
	_, err := s.ser.Write(frame)
	return err
}

func (s *SerialKISSConnection) Read(b []byte) (int, error) {
	return s.ser.Read(b)
}

func (s *SerialKISSConnection) Write(b []byte) (int, error) {
	return s.ser.Write(b)
}

func (s *SerialKISSConnection) Close() error {
	return s.ser.Close()
}

// Helper: escapeData applies KISS escaping.
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

// buildKISSFrame wraps the packet in a KISS frame.
func buildKISSFrame(packet []byte) []byte {
	escaped := escapeData(packet)
	frame := []byte{KISS_FLAG, KISS_CMD_DATA}
	frame = append(frame, escaped...)
	frame = append(frame, KISS_FLAG)
	return frame
}

// encodeAX25Address encodes the callsign into the AX.25 format.
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
	// Encode the SSID in the lower 4 bits (shifted left by 1) plus constant 0x60.
	addr[6] = byte((ssid & 0x0F) << 1) | 0x60
	if isLast {
		addr[6] |= 0x01
	}
	return addr
}

// buildAX25Header constructs a 16-byte AX.25 header.
func buildAX25Header(source, destination string) []byte {
	destAddr := encodeAX25Address(destination, false)
	srcAddr := encodeAX25Address(source, true)
	header := append(destAddr, srcAddr...)
	header = append(header, 0x03, 0xF0)
	return header
}

// buildCommandPacket creates an 80-byte command packet.
func buildCommandPacket(myCallsign, fileServerCallsign, commandLine string) []byte {
	header := buildAX25Header(myCallsign, fileServerCallsign)
	info := "CMD:" + commandLine
	if len(info) > 64 {
		info = info[:64]
	} else {
		info = info + strings.Repeat(" ", 64-len(info))
	}
	packet := append(header, []byte(info)...)
	return packet
}

// ------------------ Broadcaster ------------------

// Broadcaster distributes new data from the underlying connection to all subscribed receivers.
type Broadcaster struct {
	subscribers map[chan []byte]struct{}
	lock        sync.Mutex
}

func NewBroadcaster() *Broadcaster {
	return &Broadcaster{
		subscribers: make(map[chan []byte]struct{}),
	}
}

// Subscribe returns a new channel that will receive only new data.
func (b *Broadcaster) Subscribe() chan []byte {
	ch := make(chan []byte, 100)
	b.lock.Lock()
	b.subscribers[ch] = struct{}{}
	b.lock.Unlock()
	return ch
}

// Unsubscribe removes a channel from the broadcaster.
func (b *Broadcaster) Unsubscribe(ch chan []byte) {
	b.lock.Lock()
	delete(b.subscribers, ch)
	close(ch)
	b.lock.Unlock()
}

// Broadcast sends data to all current subscribers.
func (b *Broadcaster) Broadcast(data []byte) {
	b.lock.Lock()
	defer b.lock.Unlock()
	for ch := range b.subscribers {
		// Use non-blocking send so a slow subscriber does not block others.
		select {
		case ch <- data:
		default:
		}
	}
}

// startUnderlyingReader continuously reads from the underlying connection and broadcasts new data.
func startUnderlyingReader(underlying io.Reader, b *Broadcaster) {
	buf := make([]byte, 1024)
	for {
		n, err := underlying.Read(buf)
		if err != nil {
			if err != io.EOF {
				if debugEnabled {
					log.Printf("Underlying read error: %v", err)
				}
			}
			break
		}
		if n > 0 {
			// Copy the data since buf will be reused.
			data := make([]byte, n)
			copy(data, buf[:n])
			b.Broadcast(data)
		}
	}
}

// handleReceiverConnection uses the broadcaster so that only new data is sent to the receiver.
func handleReceiverConnection(remoteConn net.Conn, b *Broadcaster, underlying io.Writer) {
	defer remoteConn.Close()

	if debugEnabled {
		log.Printf("Accepted receiver connection from %s", remoteConn.RemoteAddr())
	}

	// Forward data from remote to underlying.
	go func() {
		_, err := io.Copy(underlying, remoteConn)
		if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			if debugEnabled {
				log.Printf("Error copying from remote to underlying: %v", err)
			}
		}
	}()

	// Subscribe to the broadcaster for new data.
	sub := b.Subscribe()
	defer b.Unsubscribe(sub)

	// Relay new data from the underlying connection to the remote client.
	for data := range sub {
		_, err := remoteConn.Write(data)
		if err != nil {
			if !strings.Contains(err.Error(), "use of closed network connection") && debugEnabled {
				log.Printf("Error writing to remote: %v", err)
			}
			return
		}
	}
}

// spawnReceiverProcess spawns the receiver process with required arguments.
// All stderr messages are printed immediately, and stdout is buffered
// and returned only after the process has completed.
// If the expected file (extracted from a stderr message) does not match the expected value,
// the receiver process is killed. It returns the stdout output, the process exit code, and an error.
func spawnReceiverProcess(args *Arguments, expectedFile string) ([]byte, int, error) {
	recvArgs := []string{
		"-connection", "tcp",
		"-host", "localhost",
		"-port", strconv.Itoa(args.ReceiverPort),
		"-my-callsign", args.MyCallsign,
		"-callsigns", args.FileServerCallsign,
		"-stdout",
		"-one-file",
	}
	cmd := exec.Command(args.ReceiverBinary, recvArgs...)

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, 0, fmt.Errorf("error getting stdout pipe: %v", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, 0, fmt.Errorf("error getting stderr pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, 0, fmt.Errorf("error starting receiver process: %v", err)
	}

	var stdoutBuf bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(2)

	// Process stdout: collect the output.
	go func() {
		scanner := bufio.NewScanner(stdoutPipe)
		for scanner.Scan() {
			line := scanner.Text()
			stdoutBuf.WriteString(line + "\n")
		}
		wg.Done()
	}()

	// Process stderr: print all lines immediately and check for file info.
	regex := regexp.MustCompile(`\(File:\s*([^,]+),\s*ID:`)
	go func() {
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			line := scanner.Text()
			fmt.Println(line)
			if expectedFile != "" {
				if m := regex.FindStringSubmatch(line); m != nil {
					actual := m[1]
					if actual != expectedFile {
						fmt.Printf("Expected file %s but got %s. Killing receiver process.\n", expectedFile, actual)
						cmd.Process.Kill()
					}
				}
			}
		}
		wg.Done()
	}()

	// Create channel to capture process exit.
	doneChan := make(chan error, 1)
	go func() {
		doneChan <- cmd.Wait()
	}()

	// Setup channel for Ctrl-C.
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	defer signal.Stop(sigChan)

	var procErr error
	select {
	case <-sigChan:
		if killErr := cmd.Process.Kill(); killErr != nil {
			procErr = fmt.Errorf("failed to kill receiver process: %v", killErr)
		} else {
			procErr = fmt.Errorf("receiver process killed by user")
		}
		procErr = <-doneChan
	case procErr = <-doneChan:
		// Process terminated normally.
	}

	wg.Wait()

	exitCode := 0
	if procErr != nil {
		if exitError, ok := procErr.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			exitCode = 1
		}
	}

	return stdoutBuf.Bytes(), exitCode, procErr
}

// ------------------ Main ------------------

func main() {
	args := parseArguments()
	debugEnabled = args.Debug

	// Establish the underlying connection.
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

	// Create a broadcaster to distribute new data from the underlying connection.
	broadcaster := NewBroadcaster()
	go startUnderlyingReader(conn, broadcaster)

	// Start the receiver TCP listener for transparent passthrough.
	receiverAddr := fmt.Sprintf(":%d", args.ReceiverPort)
	listener, err := net.Listen("tcp", receiverAddr)
	if err != nil {
		log.Fatalf("Receiver listener error: %v", err)
	}
	defer listener.Close()
	if debugEnabled {
		log.Printf("Receiver listening on %s", receiverAddr)
	}

	// Launch a goroutine to handle incoming passthrough connections.
	go func() {
		for {
			remoteConn, err := listener.Accept()
			if err != nil {
				if debugEnabled {
					log.Printf("Error accepting connection: %v", err)
				}
				continue
			}
			go handleReceiverConnection(remoteConn, broadcaster, conn)
		}
	}()

	log.Printf("Command Client started. My callsign: %s, File Server callsign: %s",
		strings.ToUpper(args.MyCallsign), strings.ToUpper(args.FileServerCallsign))
	log.Printf("Enter commands (e.g. LIST, GET filename, etc.):")

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			break
		}
		commandLine := scanner.Text()
		if strings.TrimSpace(commandLine) == "" {
			continue
		}

		// Build and send the command.
		packet := buildCommandPacket(args.MyCallsign, args.FileServerCallsign, commandLine)
		frame := buildKISSFrame(packet)
		err := conn.SendFrame(frame)
		if err != nil {
			log.Printf("Error sending command: %v", err)
			continue
		}
		log.Printf("Sent command: %s", commandLine)

		// Check if the command is LIST or GET.
		tokens := strings.Fields(commandLine)
		if len(tokens) == 0 {
			continue
		}
		cmdType := strings.ToUpper(tokens[0])
		if cmdType != "LIST" && cmdType != "GET" {
			continue
		}

		var expectedFile string
		if cmdType == "LIST" {
			expectedFile = "LIST.txt"
		} else if cmdType == "GET" {
			if len(tokens) < 2 {
				log.Printf("GET command requires a filename")
				continue
			}
			expectedFile = tokens[1]
		}

		output, exitCode, procErr := spawnReceiverProcess(args, expectedFile)
		if exitCode == 0 {
			fmt.Println("##########")
			fmt.Println("SUCCESS")
			fmt.Println("##########")
			if cmdType == "LIST" {
				fmt.Println("LIST contents:\n")
				fmt.Print(string(output))
			} else if cmdType == "GET" {
				err = os.WriteFile(expectedFile, output, 0644)
				if err != nil {
					log.Printf("Error writing to file %s: %v", expectedFile, err)
				} else {
					log.Printf("Saved output to %s", expectedFile)
				}
			}
		} else {
			fmt.Println("##########")
			fmt.Println("FAILED")
			fmt.Println("##########")
			log.Printf("Receiver process error: %v", procErr)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Printf("Input error: %v", err)
	}
}
