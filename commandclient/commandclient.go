// commandclient.go
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"flag"
	"fmt"
	"go.bug.st/serial"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"sort"
)

// Global constants for KISS framing.
const (
	KISS_FLAG     = 0xC0
	KISS_CMD_DATA = 0x00
)

// Global debug flag.
var debugEnabled bool

// Global command counter for generating 2-character command IDs.
var cmdCounter int

var (
	lastDataTime    time.Time
	reconnectMutex  sync.Mutex
	reconnecting    bool
	globalArgs      *Arguments     // Holds the parsed command-line arguments.
	globalConn      KISSConnection // The current active connection.
	broadcaster     *Broadcaster   // Global broadcaster for connection data.
)

func listFormattedFiles(dir string) (string, error) {
    entries, err := os.ReadDir(dir)
    if err != nil {
        return "", err
    }
    var files []os.DirEntry
    for _, entry := range entries {
        // Filter out directories and hidden files.
        if !entry.IsDir() && !strings.HasPrefix(entry.Name(), ".") {
            files = append(files, entry)
        }
    }
    // Sort files alphabetically (case-insensitive).
    sort.Slice(files, func(i, j int) bool {
        return strings.ToLower(files[i].Name()) < strings.ToLower(files[j].Name())
    })

    // Determine dynamic column widths.
    maxNameLen := len("File Name")
    maxSizeWidth := len("Size")
    var fileInfos []os.FileInfo
    for _, f := range files {
        info, err := f.Info()
        if err != nil {
            continue
        }
        fileInfos = append(fileInfos, info)
        if len(info.Name()) > maxNameLen {
            maxNameLen = len(info.Name())
        }
        sizeStr := fmt.Sprintf("%d", info.Size())
        if len(sizeStr) > maxSizeWidth {
            maxSizeWidth = len(sizeStr)
        }
    }

    // Build header and separator.
    headerFormat := fmt.Sprintf("%%-%ds %%-%ds %%%ds\n", maxNameLen, 20, maxSizeWidth)
    rowFormat := fmt.Sprintf("%%-%ds %%-%ds %%%dd\n", maxNameLen, 20, maxSizeWidth)
    var output strings.Builder
    output.WriteString(fmt.Sprintf(headerFormat, "File Name", "Modified Date", "Size"))
    separatorLen := maxNameLen + 1 + 20 + 1 + maxSizeWidth
    output.WriteString(strings.Repeat("-", separatorLen) + "\n")

    // Write each file's details.
    for _, info := range fileInfos {
        modTime := info.ModTime().Format("2006-01-02 15:04:05")
        output.WriteString(fmt.Sprintf(rowFormat, info.Name(), modTime, info.Size()))
    }
    return output.String(), nil
}

func generateCmdID() string {
	b := make([]byte, 1)
	if _, err := rand.Read(b); err != nil {
		// Fallback to counter if randomness fails.
		cmdCounter++
		return fmt.Sprintf("%02X", cmdCounter%256)
	}
	return fmt.Sprintf("%02X", b[0])
}

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
	SenderBinary       string // path to the sender binary
	Debug              bool   // enable debug logging
	SaveDirectory      string // directory to save files (formerly -directory)
	ServeDirectory     string // directory to send files from for sender logic
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
	flag.StringVar(&args.SenderBinary, "sender-binary", "sender", "Path to the sender binary")
	flag.BoolVar(&args.Debug, "debug", false, "Enable debug logging")
	flag.StringVar(&args.SaveDirectory, "save-directory", ".", "Directory to save files (optional, default current directory)")
	flag.StringVar(&args.ServeDirectory, "serve-directory", ".", "Directory to send files from for sender logic")
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

func getUniqueFilePath(dir, filename string) string {
	ext := filepath.Ext(filename)                      // e.g., ".txt"
	baseName := strings.TrimSuffix(filename, ext)      // e.g., "file"
	candidate := filepath.Join(dir, filename)
	if _, err := os.Stat(candidate); os.IsNotExist(err) {
		return candidate // File doesn't exist; use the original name.
	}
	// File exists, so keep trying with suffixes until a non-existent filename is found.
	for i := 1; ; i++ {
		candidate = filepath.Join(dir, fmt.Sprintf("%s_%d%s", baseName, i, ext))
		if _, err := os.Stat(candidate); os.IsNotExist(err) {
			break
		}
	}
	return candidate
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
// The new format is "CMD:" + <2-char cmdID> + " " + <command text>
// (The rest of the 64-byte info field is padded or truncated.)
func buildCommandPacket(myCallsign, fileServerCallsign, commandText string) ([]byte, string) {
	header := buildAX25Header(myCallsign, fileServerCallsign)
	cmdID := generateCmdID() // Randomized CMD ID.
	info := "CMD:" + cmdID + " " + commandText
	if len(info) > 64 {
		info = info[:64]
	} else {
		info = info + strings.Repeat(" ", 64-len(info))
	}
	packet := append(header, []byte(info)...)
	return packet, cmdID
}

// parseResponsePacket parses a 64-byte response info field in the format:
// "RSP:<cmdID> <status> <message>".
func parseResponsePacket(payload []byte) (cmdID string, status int, msg string, ok bool) {
	str := strings.TrimSpace(string(payload))
	if !strings.HasPrefix(str, "RSP:") {
		return "", 0, "", false
	}
	// Expected format: RSP:XX <status> <message>
	parts := strings.Fields(str)
	if len(parts) < 2 {
		return "", 0, "", false
	}
	if len(parts[0]) < 5 {
		return "", 0, "", false
	}
	cmdID = parts[0][4:6]
	st, err := strconv.Atoi(parts[1])
	if err != nil {
		return "", 0, "", false
	}
	status = st
	if len(parts) > 2 {
		msg = strings.Join(parts[2:], " ")
	}
	return cmdID, status, msg, true
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

// monitorInactivity triggers a reconnect if no data is received within the specified timeout.
func monitorInactivity(timeout time.Duration) {
	for {
		time.Sleep(1 * time.Second)
		if time.Since(lastDataTime) > timeout {
			log.Println("No data received for the inactivity deadline; triggering reconnect")
			go doReconnect()
		}
	}
}

// doReconnect attempts to re-establish the underlying connection using the current configuration.
func doReconnect() {
	reconnectMutex.Lock()
	if reconnecting {
		reconnectMutex.Unlock()
		return
	}
	reconnecting = true
	reconnectMutex.Unlock()

	log.Println("Triggering reconnect...")

	// Close the current connection to force the reader to exit.
	if globalConn != nil {
		globalConn.Close()
	}

	// Loop until reconnection is successful.
	for {
		log.Println("Attempting to reconnect in 5 seconds...")
		time.Sleep(5 * time.Second)
		var err error
		// Reconnect based on the connection type.
		if strings.ToLower(globalArgs.Connection) == "tcp" {
			globalConn, err = newTCPKISSConnection(globalArgs.Host, globalArgs.Port)
		} else {
			globalConn, err = newSerialKISSConnection(globalArgs.SerialPort, globalArgs.Baud)
		}
		if err != nil {
			log.Printf("Reconnect failed: %v", err)
			continue
		}
		// Reset the inactivity timer.
		lastDataTime = time.Now()
		log.Println("Reconnected successfully to the underlying device")
		// Restart the underlying reader so that new data is broadcast.
		go startUnderlyingReader(globalConn, broadcaster)
		go monitorInactivity(600 * time.Second)
		break
	}

	reconnectMutex.Lock()
	reconnecting = false
	reconnectMutex.Unlock()
}

// startUnderlyingReader continuously reads from the underlying connection,
// updates the inactivity timer, and triggers a reconnect on error.
func startUnderlyingReader(underlying io.Reader, b *Broadcaster) {
	buf := make([]byte, 1024)
	for {
		n, err := underlying.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Printf("Underlying read error: %v", err)
				go doReconnect() // Trigger reconnect on read error.
			}
			break
		}
		if n > 0 {
			lastDataTime = time.Now() // Update the inactivity timer.
			data := make([]byte, n)
			copy(data, buf[:n])
			b.Broadcast(data)
		}
	}
}

// waitForResponse waits for a complete KISS frame from the broadcaster that contains a response.
// It returns the unescaped 64-byte payload.
func waitForResponse(b *Broadcaster, timeout time.Duration, expectedCmdID string) ([]byte, error) {
	sub := b.Subscribe()
	defer b.Unsubscribe(sub)
	timeoutTimer := time.NewTimer(timeout)
	defer timeoutTimer.Stop()
	var buffer []byte
	for {
		select {
		case data := <-sub:
			buffer = append(buffer, data...)
			frames, remaining := extractKISSFrames(buffer)
			buffer = remaining
			for _, frame := range frames {
				if len(frame) < 2 || frame[0] != KISS_FLAG || frame[len(frame)-1] != KISS_FLAG {
					continue
				}
				inner := frame[2 : len(frame)-1]
				payload := unescapeData(inner)
				var info []byte
				if len(payload) == 80 {
					// New RSP packet with header: skip the 16-byte header.
					info = payload[16:]
				} else if len(payload) == 64 {
					// Old style RSP packet without header.
					info = payload
				} else {
					if debugEnabled {
						log.Printf("Ignoring frame with unexpected payload length: %d", len(payload))
					}
					continue
				}
				respCmdID, _, _, ok := parseResponsePacket(info)
				if !ok {
					if debugEnabled {
						log.Printf("Malformed RSP info field")
					}
					continue
				}
				if respCmdID != expectedCmdID {
					if debugEnabled {
						log.Printf("Ignoring response with mismatched CMD ID: got %s, expected %s", respCmdID, expectedCmdID)
					}
					continue
				}
				return info, nil
			}
		case <-timeoutTimer.C:
			return nil, fmt.Errorf("timeout waiting for response with CMD ID %s", expectedCmdID)
		}
	}
}

// extractKISSFrames extracts complete KISS frames from a buffer.
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
func spawnReceiverProcess(args *Arguments, fileid string, expectedFile string) ([]byte, int, error) {
	recvArgs := []string{
		"-connection", "tcp",
		"-host", "localhost",
		"-port", strconv.Itoa(args.ReceiverPort),
		"-my-callsign", args.MyCallsign,
		"-callsigns", args.FileServerCallsign,
		"-stdout",
		"-one-file",
		"-fileid", fileid,
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

	// Stream stderr output in real time.
	go func() {
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "Overall:") {
				fmt.Println(line)
			} else if debugEnabled {
				// Optionally print other lines when in debug mode.
				fmt.Println(line)
			}
		}
	}()

	// Read stdout completely (for binary file content).
	output, err := io.ReadAll(stdoutPipe)
	if err != nil {
		return nil, 0, fmt.Errorf("error reading stdout: %v", err)
	}

	// Wait for the process to finish.
	err = cmd.Wait()
	exitCode := 0
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			exitCode = 1
		}
		return output, exitCode, err
	}

	return output, exitCode, nil
}


// spawnSenderProcess spawns the sender process for a PUT command.
// It uses the same options as the receiver process except using -stdin instead of -stdout,
// and adds -receiver-callsign with the file server's callsign.
// It reads the file (from the serve-directory) and pipes its contents to the sender's stdin.
func spawnSenderProcess(args *Arguments, fileid string, filename string) (int, error) {
	senderArgs := []string{
		"-connection", "tcp",
		"-host", "localhost",
		"-port", strconv.Itoa(args.ReceiverPort),
		"-my-callsign", args.MyCallsign,
		"-stdin",
		"-fileid", fileid,
		"-receiver-callsign", args.FileServerCallsign,
		"-file-name", filename, // Added file-name argument
	}
	cmd := exec.Command(args.SenderBinary, senderArgs...)

	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return 1, fmt.Errorf("error getting stdin pipe: %v", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return 1, fmt.Errorf("error getting stderr pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		return 1, fmt.Errorf("error starting sender process: %v", err)
	}

	// Read file content from the serve directory.
	filePath := filepath.Join(args.ServeDirectory, filename)
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		return 1, fmt.Errorf("error reading file %s: %v", filePath, err)
	}

	_, err = stdinPipe.Write(fileData)
	if err != nil {
		return 1, fmt.Errorf("error writing to sender process stdin: %v", err)
	}
	stdinPipe.Close()

	// Process stderr: print all lines immediately.
	go func() {
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "Overall:") {
				fmt.Println(line)
			} else if debugEnabled {
				fmt.Println(line)
			}
		}
	}()

	err = cmd.Wait()
	exitCode := 0
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			exitCode = 1
		}
		return exitCode, err
	}
	return exitCode, nil
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
	log.Printf("Enter commands (e.g. LS (list local files), LIST (list remote files), GET filename, PUT filename, etc.):")

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

		// Split the command into tokens.
		tokens := strings.Fields(commandLine)
		if len(tokens) == 0 {
			continue
		}

		// Add local LS command (case-insensitive).
		if strings.EqualFold(tokens[0], "LS") {
		    listing, err := listFormattedFiles(args.ServeDirectory)
		    if err != nil {
		        log.Printf("Error listing files in serve directory: %v", err)
		    } else {
		        fmt.Println(listing)
		    }
		    continue
		}

		// If the command is a PUT, verify that the file is accessible before sending.
		if len(tokens) > 0 && strings.ToUpper(tokens[0]) == "PUT" {
			idx := strings.Index(commandLine, " ")
			if idx == -1 {
				log.Printf("PUT command requires a filename")
				continue
			}
			filename := strings.TrimSpace(commandLine[idx:])
			if filename == "" {
				log.Printf("PUT command requires a filename")
				continue
			}
			filePath := filepath.Join(args.ServeDirectory, filename)
			if _, err := os.Stat(filePath); err != nil {
				log.Printf("Cannot read file %s: %v", filePath, err)
				continue
			}
		}

		// Build and send the command (which now includes a 2-char ID).
		packet, cmdID := buildCommandPacket(args.MyCallsign, args.FileServerCallsign, commandLine)
		frame := buildKISSFrame(packet)
		err := conn.SendFrame(frame)
		if err != nil {
			log.Printf("Error sending command: %v", err)
			continue
		}
		log.Printf("Sent command: %s [%s]", commandLine, cmdID)

		// Wait for the direct response from the server.
		respPayload, err := waitForResponse(broadcaster, 10*time.Second, cmdID)
		if err != nil {
			log.Printf("Error waiting for response: %v", err)
			continue
		}
		_, status, msg, ok := parseResponsePacket(respPayload)
		if !ok {
			log.Printf("Received malformed response")
			continue
		}
		if status == 1 {
			fmt.Println("##########")
			fmt.Println("Success:", msg)
			fmt.Println("##########")
		} else {
			fmt.Println("##########")
			fmt.Println("Failed:", msg)
			fmt.Println("##########")
		}

		// For LIST, GET, or PUT commands, spawn the appropriate process.
		// (Note: The file existence check for PUT has already been performed.)
		tokens = strings.Fields(commandLine)
		if len(tokens) == 0 {
			continue
		}
		cmdType := strings.ToUpper(tokens[0])
		if cmdType != "LIST" && cmdType != "GET" && cmdType != "PUT" {
			continue
		}

		// Only proceed with file transfer if the response was a success.
		if status != 1 {
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
			expectedFile = strings.Join(tokens[1:], " ")
		} else if cmdType == "PUT" {
			// Use the entire remainder of the command line as the filename.
			idx := strings.Index(commandLine, " ")
			if idx == -1 {
				log.Printf("PUT command requires a filename")
				continue
			}
			expectedFile = strings.TrimSpace(commandLine[idx:])
			if expectedFile == "" {
				log.Printf("PUT command requires a filename")
				continue
			}
		}

		if cmdType == "PUT" {
			exitCode, procErr := spawnSenderProcess(args, cmdID, expectedFile)
			if exitCode == 0 {
				log.Printf("PUT command successful: sent %s", expectedFile)
			} else {
				log.Printf("Sender process error: %v", procErr)
			}
		} else { // LIST or GET
			output, exitCode, procErr := spawnReceiverProcess(args, cmdID, expectedFile)
			if exitCode == 0 {
				if cmdType == "LIST" {
					fmt.Println("LIST contents:\n")
					fmt.Print(string(output))
				} else if cmdType == "GET" {
					// Determine a unique file path to avoid overwriting an existing file.
					uniqueFilePath := getUniqueFilePath(args.SaveDirectory, expectedFile)
					err = os.WriteFile(uniqueFilePath, output, 0644)
					if err != nil {
						log.Printf("Error writing to file %s: %v", uniqueFilePath, err)
					} else {
						log.Printf("Saved output to %s", uniqueFilePath)
					}
				}
			} else {
				log.Printf("Receiver process error: %v", procErr)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		log.Printf("Input error: %v", err)
	}
}
