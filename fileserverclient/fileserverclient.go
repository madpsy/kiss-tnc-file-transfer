// fileserverclient.go
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
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"sort"
	"encoding/csv"
)

// Global constants for KISS framing.
const (
	KISS_FLAG     = 0xC0
	KISS_CMD_DATA = 0x00
)

// Global debug flag.
var debugEnabled bool

var getQueueMutex sync.Mutex

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

// csvToPretty converts CSV text into a pretty-printed table.
func csvToPretty(csvText string) (string, error) {
	r := csv.NewReader(strings.NewReader(csvText))
	records, err := r.ReadAll()
	if err != nil {
		return "", err
	}
	if len(records) == 0 {
		return "", fmt.Errorf("no CSV data found")
	}

	// Determine the maximum width for each column.
	numCols := len(records[0])
	widths := make([]int, numCols)
	for _, row := range records {
		for i, cell := range row {
			if len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}

	// Build the formatted table.
	var sb strings.Builder
	// Header row.
	header := records[0]
	format := ""
	for _, w := range widths {
		format += fmt.Sprintf("%%-%ds ", w)
	}
	format = strings.TrimSpace(format) + "\n"
	sb.WriteString(fmt.Sprintf(format, toInterfaceSlice(header)...))

	// Separator row.
	for _, w := range widths {
		sb.WriteString(strings.Repeat("-", w) + " ")
	}
	sb.WriteString("\n")

	// Data rows.
	for _, row := range records[1:] {
		sb.WriteString(fmt.Sprintf(format, toInterfaceSlice(row)...))
	}
	return sb.String(), nil
}

// toInterfaceSlice converts a slice of strings into a slice of empty interfaces.
func toInterfaceSlice(strs []string) []interface{} {
	out := make([]interface{}, len(strs))
	for i, s := range strs {
		out[i] = s
	}
	return out
}

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
	RunCommand         string // Optional: run a single command non-interactively and exit.
	HTTPServerPort     int    // Optional: if non-zero, run an HTTP server for GET requests.
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
	// New optional flag to run a single command and exit.
	flag.StringVar(&args.RunCommand, "run-command", "", "Run a single command non-interactively (e.g., \"PUT my-file.txt\") and exit")
	// New flag: HTTP server port.
	flag.IntVar(&args.HTTPServerPort, "http-server-port", 0, "If set, start an HTTP server on the specified port for GET requests")
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
	ext := filepath.Ext(filename)                 // e.g., ".txt"
	baseName := strings.TrimSuffix(filename, ext) // e.g., "file"
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

func buildCommandPacket(myCallsign, fileServerCallsign, commandText string) ([]byte, string) {
	header := buildAX25Header(myCallsign, fileServerCallsign)
	cmdID := generateCmdID() // Randomized CMD ID.
	// New format: "cmdID:CMD:<cmd text>"
	info := fmt.Sprintf("%s:CMD:%s", cmdID, commandText)
	packet := append(header, []byte(info)...)
	return packet, cmdID
}


func parseResponsePacket(payload []byte) (cmdID string, status int, msg string, ok bool) {
	str := strings.TrimSpace(string(payload))
	// Expected format: "cmdID:RSP:<status>:<msg>"
	parts := strings.SplitN(str, ":", 4)
	if len(parts) != 4 {
		return "", 0, "", false
	}
	cmdID = parts[0]
	if strings.ToUpper(parts[1]) != "RSP" {
		return "", 0, "", false
	}
	st, err := strconv.Atoi(parts[2])
	if err != nil {
		return "", 0, "", false
	}
	status = st
	msg = parts[3]
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
				if len(payload) <= 16 {
					continue
				}
				info := payload[16:] // Extract info field after the 16-byte header.
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

// handleCommand processes a single command line as if it were entered manually.
// It returns an exit code: 0 on success, non-zero if the command (or any file transfer) failed.
func handleCommand(commandLine string, args *Arguments, conn KISSConnection, b *Broadcaster) int {
	if strings.TrimSpace(commandLine) == "" {
		return 0
	}
	tokens := strings.Fields(commandLine)
	if len(tokens) == 0 {
		return 0
	}

	// Local LS command.
	if strings.EqualFold(tokens[0], "LS") {
		listing, err := listFormattedFiles(args.ServeDirectory)
		if err != nil {
			log.Printf("Error listing files in serve directory: %v", err)
			return 1
		} else {
			fmt.Println(listing)
		}
		return 0
	}

	// For PUT command, check file accessibility.
	if strings.ToUpper(tokens[0]) == "PUT" {
		idx := strings.Index(commandLine, " ")
		if idx == -1 {
			log.Printf("PUT command requires a filename")
			return 1
		}
		filename := strings.TrimSpace(commandLine[idx:])
		if filename == "" {
			log.Printf("PUT command requires a filename")
			return 1
		}
		filePath := filepath.Join(args.ServeDirectory, filename)
		if _, err := os.Stat(filePath); err != nil {
			log.Printf("Cannot read file %s: %v", filePath, err)
			return 1
		}
	}

	// For MKD command, ensure a directory name is provided.
	if strings.ToUpper(tokens[0]) == "MKD" {
		idx := strings.Index(commandLine, " ")
		if idx == -1 {
			log.Printf("MKD command requires a directory name")
			return 1
		}
		dirName := strings.TrimSpace(commandLine[idx:])
		if dirName == "" {
			log.Printf("MKD command requires a directory name")
			return 1
		}
	}

	// Build and send the command.
	packet, cmdID := buildCommandPacket(args.MyCallsign, args.FileServerCallsign, commandLine)
	frame := buildKISSFrame(packet)
	err := conn.SendFrame(frame)
	if err != nil {
		log.Printf("Error sending command: %v", err)
		return 1
	}
	log.Printf("Sent command: %s [%s]", commandLine, cmdID)

	// Wait for the direct response.
	respPayload, err := waitForResponse(b, 10*time.Second, cmdID)
	if err != nil {
		log.Printf("Error waiting for response: %v", err)
		return 1
	}
	_, status, msg, ok := parseResponsePacket(respPayload)
	if !ok {
		log.Printf("Received malformed response")
		return 1
	}
	if status == 1 {
		fmt.Println("##########")
		fmt.Println("Success:", msg)
		fmt.Println("##########")
	} else {
		fmt.Println("##########")
		fmt.Println("Failed:", msg)
		fmt.Println("##########")
		return 1
	}

	// For commands that require file transfers: LIST, GET, or PUT.
	tokens = strings.Fields(commandLine)
	if len(tokens) == 0 {
		return 0
	}
	cmdType := strings.ToUpper(tokens[0])
	if cmdType != "LIST" && cmdType != "GET" && cmdType != "PUT" {
		// MKD (and any other non-transfer command) ends here.
		return 0
	}

	// Determine expected file name.
	var expectedFile string
	if cmdType == "LIST" {
		expectedFile = "LIST.txt"
	} else if cmdType == "GET" {
		if len(tokens) < 2 {
			log.Printf("GET command requires a filename")
			return 1
		}
		expectedFile = filepath.Base(strings.Join(tokens[1:], " "))
	} else if cmdType == "PUT" {
		idx := strings.Index(commandLine, " ")
		if idx == -1 {
			log.Printf("PUT command requires a filename")
			return 1
		}
		expectedFile = strings.TrimSpace(commandLine[idx:])
		if expectedFile == "" {
			log.Printf("PUT command requires a filename")
			return 1
		}
	}

	if cmdType == "PUT" {
		exitCode, procErr := spawnSenderProcess(args, cmdID, expectedFile)
		if exitCode == 0 {
			log.Printf("PUT command successful: sent %s", expectedFile)
			return 0
		} else {
			log.Printf("Sender process error: %v", procErr)
			return exitCode
		}
	} else { // LIST or GET
		output, exitCode, procErr := spawnReceiverProcess(args, cmdID, expectedFile)
		if exitCode == 0 {
			if cmdType == "LIST" {
				pretty, err := csvToPretty(string(output))
				if err != nil {
					log.Printf("Error converting CSV to table: %v", err)
					fmt.Println("LIST contents:\n")
					fmt.Print(string(output))
				} else {
					fmt.Println("LIST contents:\n")
					fmt.Print(pretty)
				}
			} else if cmdType == "GET" {
				uniqueFilePath := getUniqueFilePath(args.SaveDirectory, expectedFile)
				err = os.WriteFile(uniqueFilePath, output, 0644)
				if err != nil {
					log.Printf("Error writing to file %s: %v", uniqueFilePath, err)
					return 1
				} else {
					log.Printf("Saved file to %s", uniqueFilePath)
				}
			}
			return 0
		} else {
			log.Printf("Receiver process error: %v", procErr)
			return exitCode
		}
	}
}


// startHTTPServer launches an HTTP server on the specified port to handle GET requests.
func startHTTPServer(args *Arguments, conn KISSConnection, b *Broadcaster) {
	// Define MIME types mapping.
	mimeTypes := map[string]string{
		"svg":  "image/svg+xml",
		"css":  "text/css",
		"js":   "application/javascript",
		"html": "text/html",
		"json": "application/json",
		"png":  "image/png",
		"jpg":  "image/jpeg",
		"jpeg": "image/jpeg",
		"gif":  "image/gif",
		"ico":  "image/x-icon",
		"mp3":  "audio/mpeg",
		"wav":  "audio/wav",
		"mp4":  "video/mp4",
		"webm": "video/webm",
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Only GET allowed", http.StatusMethodNotAllowed)
			return
		}

		// Serialize GET requests.
		getQueueMutex.Lock()
		defer getQueueMutex.Unlock()

		requestedPath := r.URL.Path
		// Remove leading '/' if present.
		if strings.HasPrefix(requestedPath, "/") {
			requestedPath = requestedPath[1:]
		}
		// Default to index.html if root or directory.
		if requestedPath == "" || strings.HasSuffix(requestedPath, "/") {
			requestedPath = requestedPath + "index.html"
		}
		if requestedPath == "" {
			http.Error(w, "No file specified", http.StatusBadRequest)
			return
		}

		// Attempt to send GET command and wait for response (with retries).
		const maxRetries = 3
		var respPayload []byte
		var err error
		var cmdID string
		for attempt := 1; attempt <= maxRetries; attempt++ {
			commandLine := "GET " + requestedPath
			var packet []byte
			packet, cmdID = buildCommandPacket(args.MyCallsign, args.FileServerCallsign, commandLine)
			frame := buildKISSFrame(packet)
			err = conn.SendFrame(frame)
			if err != nil {
				http.Error(w, "Error sending GET command: "+err.Error(), http.StatusInternalServerError)
				return
			}
			log.Printf("HTTP GET: sent command for file '%s' with CMD ID %s (attempt %d)", requestedPath, cmdID, attempt)
			// Wait for the direct response with a 10-second timeout.
			respPayload, err = waitForResponse(b, 10*time.Second, cmdID)
			if err == nil {
				break
			}
			log.Printf("Attempt %d: Error waiting for GET response: %v", attempt, err)
		}
		if err != nil {
			http.Error(w, "Error waiting for GET response after retries: "+err.Error(), http.StatusGatewayTimeout)
			return
		}
		_, status, msg, ok := parseResponsePacket(respPayload)
		// If the command response indicates failure, return 404.
		if !ok || status != 1 {
			http.Error(w, "GET command failed: "+msg, http.StatusNotFound)
			return
		}

		// Wrap spawnReceiverProcess in a goroutine so we can apply an overall timeout.
		type receiverResult struct {
			output   []byte
			exitCode int
			err      error
		}
		resultCh := make(chan receiverResult, 1)
		go func() {
			output, exitCode, procErr := spawnReceiverProcess(args, cmdID, requestedPath)
			resultCh <- receiverResult{output: output, exitCode: exitCode, err: procErr}
		}()

		// Use a 10-minute overall timeout for the receiver process.
		select {
		case res := <-resultCh:
			if res.exitCode != 0 {
				http.Error(w, "Error retrieving file: "+res.err.Error(), http.StatusInternalServerError)
				return
			}

			// Set the Content-Type header based on file extension.
			ext := strings.TrimPrefix(strings.ToLower(filepath.Ext(requestedPath)), ".")
			if mime, exists := mimeTypes[ext]; exists {
				w.Header().Set("Content-Type", mime)
				// Use inline disposition so that the browser displays the file if possible.
				w.Header().Set("Content-Disposition", "inline; filename=\""+filepath.Base(requestedPath)+"\"")
			} else {
				// Fallback headers.
				w.Header().Set("Content-Type", "application/octet-stream")
				w.Header().Set("Content-Disposition", "attachment; filename=\""+filepath.Base(requestedPath)+"\"")
			}

			// Set caching headers: cache for 24 hours.
			w.Header().Set("Cache-Control", "public, max-age=86400")
			w.Header().Set("Expires", time.Now().Add(24*time.Hour).Format(http.TimeFormat))

			_, _ = w.Write(res.output)

		case <-time.After(10 * time.Minute):
			http.Error(w, "Receiver process timed out", http.StatusGatewayTimeout)
			return
		}
	})

	addr := fmt.Sprintf(":%d", args.HTTPServerPort)
	log.Printf("HTTP server listening on %s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("HTTP server error: %v", err)
	}
}

// ------------------ Main ------------------

func main() {
	args := parseArguments()
	debugEnabled = args.Debug
	globalArgs = args

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
	globalConn = conn

	// Create a broadcaster to distribute new data from the underlying connection.
	broadcaster = NewBroadcaster()
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

	// If HTTP server port is set, start the HTTP server in a goroutine.
	if args.HTTPServerPort != 0 {
		go startHTTPServer(args, conn, broadcaster)
	}

	log.Printf("Command Client started. My callsign: %s, File Server callsign: %s",
		strings.ToUpper(args.MyCallsign), strings.ToUpper(args.FileServerCallsign))
	log.Printf("Enter commands (e.g. LS, LIST, GET filename, PUT filename, etc.):")

	// If -run-command was provided, execute it and exit with the proper exit code.
	if args.RunCommand != "" {
		fmt.Printf("> %s\n", args.RunCommand)
		exitCode := handleCommand(args.RunCommand, args, conn, broadcaster)
		os.Exit(exitCode)
	}

	// Otherwise, enter the interactive command loop.
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			break
		}
		commandLine := scanner.Text()
		handleCommand(commandLine, args, conn, broadcaster)
	}
	if err := scanner.Err(); err != nil {
		log.Printf("Input error: %v", err)
	}
}
