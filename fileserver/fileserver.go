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
	"sort"
	"strings"
	"sync"
	"time"
)

var disallowedFilenames = []string{
	"LIST.txt", // used internally for file lists
}

// Global constants for KISS framing.
const (
	KISS_FLAG     = 0xC0
	KISS_CMD_DATA = 0x00
)

// Global variable for server's callsign.
var serverCallsign string

var globalArgs *Arguments

// Global variables for reconnection logic.
var (
	lastDataTime   time.Time
	reconnectMutex sync.Mutex
	reconnecting   bool
	// globalConn is now protected by connLock and should be accessed via getConn() and setConn().
	globalConn  KISSConnection
	broadcaster *Broadcaster // Already used for broadcasting.
	connLock    sync.RWMutex // Protects access to globalConn.
)

// Global slices for allowed sender callsigns.
var getAllowedCallsigns []string
var putAllowedCallsigns []string
// New: allowed ADMIN callsigns. If empty then admin commands are denied.
var adminAllowedCallsigns []string

// Maximum allowed file name length.
const maxFileNameLen = 58

// Absolute paths for directories.
var absServeDir string
var absSaveDir string

// Global map to track running processes per sender callsign.
var runningSender sync.Map
var runningReceiver sync.Map

// --- Duplicate response cache ---

type cachedResponse struct {
	timestamp time.Time
	frame     []byte
}

var (
	rspCache     = make(map[string]cachedResponse)
	rspCacheLock sync.Mutex
)

// cacheCleanup periodically removes cache entries older than 30 seconds.
func cacheCleanup() {
	for {
		time.Sleep(1 * time.Minute)
		now := time.Now()
		rspCacheLock.Lock()
		for key, cached := range rspCache {
			if now.Sub(cached.timestamp) > 30*time.Second {
				delete(rspCache, key)
			}
		}
		rspCacheLock.Unlock()
	}
}

// --- In-progress command tracking ---
// This ensures that concurrent duplicate commands wait for the first to finish processing.
var (
	processingCommands     = make(map[string]chan struct{})
	processingCommandsLock sync.Mutex
)

// --- Thread-safe connection accessor functions ---

func isFilenameDisallowed(fileName string) bool {
	for _, disallowed := range disallowedFilenames {
		if strings.EqualFold(fileName, disallowed) {
			return true
		}
	}
	return false
}

func getConn() KISSConnection {
	connLock.RLock()
	defer connLock.RUnlock()
	return globalConn
}

func setConn(newConn KISSConnection) {
	connLock.Lock()
	// If there’s an existing connection, close it.
	if globalConn != nil {
		globalConn.Close()
	}
	globalConn = newConn
	connLock.Unlock()
}

// Command-line arguments structure.
type Arguments struct {
	MyCallsign      string // your own callsign
	Connection      string // "tcp" or "serial"
	Host            string // used with TCP
	Port            int    // used with TCP
	SerialPort      string // used with serial
	Baud            int    // used with serial
	GetCallsigns    string // comma-delimited list for filtering GET sender callsigns (supports wildcards).
	PutCallsigns    string // comma-delimited list for filtering PUT sender callsigns (supports wildcards).
	AdminCallsigns  string // comma-delimited list for filtering ADMIN sender callsigns (supports wildcards).
	ServeDirectory  string // directory to serve files from (mandatory unless -per-callsign is used)
	SaveDirectory   string // where received files should be saved (default current directory; not used in per-callsign mode)
	SenderBinary    string // path to the binary used to send files (mandatory)
	ReceiverBinary  string // path to the binary used to receive files (default "receiver")
	PassthroughPort int    // TCP port for transparent passthrough (default 5011)
	IdPeriod        int    // Minutes between sending an ID packet (0 means never)
	PerCallsignDir  string // New: base directory for per-callsign subdirectories (mutually exclusive with serve-directory, save-directory, get-callsigns, put-callsigns, and admin-callsigns)
	OverwriteExisting bool // New: if true, overwrite existing files instead of appending _x
}

func parseArguments() *Arguments {
	args := &Arguments{}
	flag.StringVar(&args.MyCallsign, "my-callsign", "", "Your callsign (required)")
	flag.StringVar(&args.Connection, "connection", "tcp", "Connection type: tcp or serial")
	flag.StringVar(&args.Host, "host", "127.0.0.1", "TCP host (if connection is tcp)")
	flag.IntVar(&args.Port, "port", 9001, "TCP port (if connection is tcp)")
	flag.StringVar(&args.SerialPort, "serial-port", "", "Serial port (e.g., COM3 or /dev/ttyUSB0)")
	flag.IntVar(&args.Baud, "baud", 115200, "Baud rate for serial connection")
	flag.StringVar(&args.GetCallsigns, "get-callsigns", "", "Comma delimited list of allowed sender callsign patterns for GET command (supports wildcards)")
	flag.StringVar(&args.PutCallsigns, "put-callsigns", "", "Comma delimited list of allowed sender callsign patterns for PUT command (supports wildcards)")
	flag.StringVar(&args.AdminCallsigns, "admin-callsigns", "", "Comma delimited list of allowed sender callsign patterns for ADMIN commands (supports wildcards)")
	flag.StringVar(&args.ServeDirectory, "serve-directory", "", "Directory to serve files from (mandatory unless -per-callsign is used)")
	flag.StringVar(&args.SaveDirectory, "save-directory", ".", "Directory where received files should be saved (default current directory; not used in per-callsign mode)")
	flag.StringVar(&args.SenderBinary, "sender-binary", "sender", "Path to the binary used to send files (default 'sender')")
	flag.StringVar(&args.ReceiverBinary, "receiver-binary", "receiver", "Path to the binary used to receive files (default 'receiver')")
	flag.IntVar(&args.PassthroughPort, "passthrough-port", 5011, "TCP port for transparent passthrough (default 5011)")
	flag.IntVar(&args.IdPeriod, "id-period", 30, "Minutes between sending an ID packet (0 means never)")
	flag.StringVar(&args.PerCallsignDir, "per-callsign", "", "Base directory for per-callsign subdirectories (mutually exclusive with serve-directory, save-directory, get-callsigns, put-callsigns, and admin-callsigns)")
	flag.BoolVar(&args.OverwriteExisting, "overwrite-existing", false, "Overwrite existing files instead of appending _x to file names")
	flag.Parse()

	if args.PerCallsignDir != "" {
		if args.ServeDirectory != "" || args.SaveDirectory != "." || args.GetCallsigns != "" || args.PutCallsigns != "" || args.AdminCallsigns != "" {
			log.Fatalf("When using -per-callsign, do not specify serve-directory, save-directory, get-callsigns, put-callsigns or admin-callsigns.")
		}
	} else {
		if args.ServeDirectory == "" {
			log.Fatalf("--serve-directory is required.")
		}
	}
	if args.MyCallsign == "" {
		log.Fatalf("--my-callsign is required.")
	}
	if args.Connection == "serial" && args.SerialPort == "" {
		log.Fatalf("--serial-port is required for serial connection.")
	}
	return args
}

// KISSConnection is the minimal interface we need.
type KISSConnection interface {
	RecvData(timeout time.Duration) ([]byte, error)
	Write([]byte) (int, error)
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

func (t *TCPKISSConnection) Write(b []byte) (int, error) {
	t.lock.Lock()
	defer t.lock.Unlock()
	return t.conn.Write(b)
}

func (t *TCPKISSConnection) Close() error {
	return t.conn.Close()
}

// SerialKISSConnection implements KISSConnection over serial.
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

func (s *SerialKISSConnection) Write(b []byte) (int, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	return s.ser.Write(b)
}

func (s *SerialKISSConnection) Close() error {
	return s.ser.Close()
}

// createRSPPacket builds the RSP packet with an AX.25 header.
func createRSPPacket(destCallsign, srcCallsign, cmdID string, status int, msg string) []byte {
	// Build the AX.25 header:
	//  - Destination: original sender's callsign (no "last" flag).
	//  - Source: our server's callsign (with "last" flag set).
	destAddr := encodeAX25Address(destCallsign, false)
	srcAddr := encodeAX25Address(srcCallsign, true)
	// Append control (0x03) and PID (0xF0) bytes to complete the 16-byte header.
	header := append(append(destAddr, srcAddr...), 0x03, 0xF0)

	// Build the info field (128 bytes) with the RSP message.
	responseText := fmt.Sprintf("RSP:%s %d %s", cmdID, status, msg)
	if len(responseText) > 128 {
		responseText = responseText[:128]
	} else {
		responseText = responseText + strings.Repeat(" ", 128-len(responseText))
	}
	infoField := []byte(responseText)

	// Combine header and info field to form the full packet.
	packet := append(header, infoField...)
	return packet
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

// Helper: escapeData applies KISS escaping.
func escapeData(data []byte) []byte {
	var out bytes.Buffer
	for _, b := range data {
		if b == KISS_FLAG {
			out.WriteByte(0xDB)
			out.WriteByte(0xDC)
		} else if b == 0xDB {
			out.WriteByte(0xDB)
			out.WriteByte(0xDD)
		} else {
			out.WriteByte(b)
		}
	}
	return out.Bytes()
}

// sendResponse wraps the payload in a KISS frame and writes it directly to the connection.
func sendResponse(responsePayload []byte) error {
	conn := getConn()
	escaped := escapeData(responsePayload)
	frame := []byte{KISS_FLAG, KISS_CMD_DATA}
	frame = append(frame, escaped...)
	frame = append(frame, KISS_FLAG)
	_, err := conn.Write(frame)
	return err
}

// sendResponseWithDetails builds the response packet, logs the details,
// sends it, and caches the response. It returns the full frame and any error.
func sendResponseWithDetails(sender, cmdID, command string, status int, msg string) ([]byte, error) {
	conn := getConn() // always use the current connection
	rspPacket := createRSPPacket(sender, serverCallsign, cmdID, status, msg)
	escaped := escapeData(rspPacket)
	frame := []byte{KISS_FLAG, KISS_CMD_DATA}
	frame = append(frame, escaped...)
	frame = append(frame, KISS_FLAG)

	statusText := "FAILED"
	if status == 1 {
		statusText = "SUCCESS"
	}
	log.Printf("Sending RSP packet for command '%s' (ID: %s): %s - %s", command, cmdID, statusText, msg)
	_, err := conn.Write(frame)
	// Cache the response
	cacheKey := sender + ":" + cmdID
	rspCacheLock.Lock()
	rspCache[cacheKey] = cachedResponse{
		timestamp: time.Now(),
		frame:     frame,
	}
	rspCacheLock.Unlock()
	return frame, err
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
	addr[6] = byte((ssid & 0x0F) << 1) | 0x60
	if isLast {
		addr[6] |= 0x01
	}
	return addr
}

// decodeAX25Address decodes a 7-byte AX.25 address field.
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

// parseCommandPacket now extracts the 2-character ID after "CMD:".
// Note: the packet now must be at least 144 bytes long (16-byte header + 128-byte info field).
func parseCommandPacket(packet []byte) (sender, cmdID, command string, ok bool) {
	if len(packet) < 144 {
		return "", "", "", false
	}
	header := packet[:16]
	dest := decodeAX25Address(header[0:7])
	if dest != serverCallsign {
		log.Printf("Dropping packet: destination %s does not match our callsign %s", dest, serverCallsign)
		return "", "", "", false
	}
	infoField := packet[16:144]
	infoStr := strings.TrimSpace(string(infoField))
	if !strings.HasPrefix(infoStr, "CMD:") {
		return "", "", "", false
	}
	// Ensure there is room for a 2-character ID
	if len(infoStr) < 6 {
		return "", "", "", false
	}
	cmdID = infoStr[4:6]
	command = strings.TrimSpace(infoStr[6:])
	sender = decodeAX25Address(header[7:14])
	return sender, cmdID, command, true
}

// createResponsePacket builds the response payload.
// The response format is "RSP:<cmdID> <status> <message>" padded or truncated to 128 bytes.
func createResponsePacket(cmdID string, status int, msg string) []byte {
	responseText := fmt.Sprintf("RSP:%s %d %s", cmdID, status, msg)
	if len(responseText) > 128 {
		responseText = responseText[:128]
	} else {
		responseText = responseText + strings.Repeat(" ", 128-len(responseText))
	}
	return []byte(responseText)
}

func callsignAllowedForGet(cs string) bool {
	// If no restrictions provided, do not allow any GETs.
	if len(getAllowedCallsigns) == 0 {
		return false
	}
	cs = strings.ToUpper(strings.TrimSpace(cs))
	for _, pattern := range getAllowedCallsigns {
		if match, err := filepath.Match(pattern, cs); err == nil && match {
			return true
		}
	}
	return false
}

func callsignAllowedForPut(cs string) bool {
	// If no restrictions provided, do not allow any PUTs.
	if len(putAllowedCallsigns) == 0 {
		return false
	}
	cs = strings.ToUpper(strings.TrimSpace(cs))
	for _, pattern := range putAllowedCallsigns {
		if match, err := filepath.Match(pattern, cs); err == nil && match {
			return true
		}
	}
	return false
}

// Helper function to check if a sender is allowed for ADMIN commands.
func callsignAllowedForAdmin(cs string) bool {
	if len(adminAllowedCallsigns) == 0 {
		return false
	}
	cs = strings.ToUpper(strings.TrimSpace(cs))
	for _, pattern := range adminAllowedCallsigns {
		if match, err := filepath.Match(pattern, cs); err == nil && match {
			return true
		}
	}
	return false
}

func listFiles(dir string) (string, error) {
	entries, err := ioutil.ReadDir(dir)
	if err != nil {
		return "", err
	}

	// Filter out directories and hidden files.
	var files []os.FileInfo
	for _, entry := range entries {
		if !entry.IsDir() && !strings.HasPrefix(entry.Name(), ".") {
			files = append(files, entry)
		}
	}

	// Sort files alphanumerically.
	sort.Slice(files, func(i, j int) bool {
		return strings.ToLower(files[i].Name()) < strings.ToLower(files[j].Name())
	})

	var output strings.Builder
	// Write CSV header.
	output.WriteString("File Name,Modified Date,Size\n")

	// Write file details in CSV format.
	for _, file := range files {
		modTime := file.ModTime().Format("2006-01-02 15:04:05")
		output.WriteString(fmt.Sprintf("\"%s\",\"%s\",%d\n", file.Name(), modTime, file.Size()))
	}

	return output.String(), nil
}

// --- Broadcaster ---
// This helper will allow multiple goroutines to receive the same data from the underlying KISS connection.
type Broadcaster struct {
	subscribers map[chan []byte]struct{}
	lock        sync.Mutex
}

func NewBroadcaster() *Broadcaster {
	return &Broadcaster{
		subscribers: make(map[chan []byte]struct{}),
	}
}

func (b *Broadcaster) Subscribe() chan []byte {
	ch := make(chan []byte, 100)
	b.lock.Lock()
	b.subscribers[ch] = struct{}{}
	b.lock.Unlock()
	return ch
}

func (b *Broadcaster) Unsubscribe(ch chan []byte) {
	b.lock.Lock()
	delete(b.subscribers, ch)
	close(ch)
	b.lock.Unlock()
}

func (b *Broadcaster) Broadcast(data []byte) {
	b.lock.Lock()
	defer b.lock.Unlock()
	for ch := range b.subscribers {
		select {
		case ch <- data:
		default:
		}
	}
}

// startKISSReader continuously reads from the underlying connection and broadcasts data.
func startKISSReader(conn KISSConnection, b *Broadcaster) {
	for {
		data, err := conn.RecvData(100 * time.Millisecond)
		if err != nil {
			if err != io.EOF {
				log.Printf("Underlying read error: %v", err)
				go doReconnect()
			}
			break
		}
		if len(data) > 0 {
			lastDataTime = time.Now()
			b.Broadcast(data)
		}
	}
}

func monitorInactivity(timeout time.Duration) {
	for {
		time.Sleep(1 * time.Second)
		if time.Since(lastDataTime) > timeout {
			log.Println("No data received for the inactivity deadline; triggering reconnect")
			go doReconnect()
		}
	}
}

func doReconnect() {
	reconnectMutex.Lock()
	if reconnecting {
		reconnectMutex.Unlock()
		return
	}
	reconnecting = true
	reconnectMutex.Unlock()

	log.Println("Triggering reconnect...")

	for {
		log.Println("Attempting to reconnect in 5 seconds...")
		time.Sleep(5 * time.Second)
		var err error
		var newConn KISSConnection
		if strings.ToLower(globalArgs.Connection) == "tcp" {
			newConn, err = newTCPKISSConnection(globalArgs.Host, globalArgs.Port)
		} else {
			newConn, err = newSerialKISSConnection(globalArgs.SerialPort, globalArgs.Baud)
		}
		if err != nil {
			log.Printf("Reconnect failed: %v", err)
			continue
		}
		setConn(newConn)
		lastDataTime = time.Now()
		log.Println("Reconnected successfully to the underlying device")
		go startKISSReader(newConn, broadcaster)
		go monitorInactivity(600 * time.Second)
		break
	}

	reconnectMutex.Lock()
	reconnecting = false
	reconnectMutex.Unlock()
}

// --- Transparent Passthrough Handler ---
func handleTransparentConnection(remoteConn net.Conn, b *Broadcaster) {
	defer remoteConn.Close()
	log.Printf("Accepted transparent connection from %s", remoteConn.RemoteAddr())
	go func() {
		// Continuously write to the current connection.
		for {
			currentConn := getConn()
			if currentConn == nil {
				return
			}
			_, err := io.Copy(currentConn, remoteConn)
			if err != nil {
				if !strings.Contains(err.Error(), "use of closed network connection") {
					log.Printf("Error copying from transparent client to underlying: %v", err)
				}
				return
			}
		}
	}()
	sub := b.Subscribe()
	defer b.Unsubscribe(sub)
	for data := range sub {
		_, err := remoteConn.Write(data)
		if err != nil {
			return
		}
	}
}

func startTransparentListener(port int, b *Broadcaster) {
	addr := fmt.Sprintf(":%d", port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Transparent listener error: %v", err)
	}
	defer listener.Close()
	log.Printf("Transparent sender listener active on %s", addr)
	for {
		remoteConn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting transparent connection: %v", err)
			continue
		}
		go handleTransparentConnection(remoteConn, b)
	}
}

// --- Invoking the Sender Binary ---
func invokeSenderBinary(args *Arguments, receiverCallsign, fileName, inputData, cmdID string) {
	// Check if a sender binary is already running for this callsign.
	if _, alreadyRunning := runningSender.LoadOrStore(receiverCallsign, true); alreadyRunning {
		log.Printf("A sender binary is already running for callsign %s, skipping.", receiverCallsign)
		return
	}
	// Ensure we remove the entry when done.
	defer runningSender.Delete(receiverCallsign)

	var cmdArgs []string
	cmdArgs = append(cmdArgs, "-connection=tcp", "-host=localhost", fmt.Sprintf("-port=%d", args.PassthroughPort))
	cmdArgs = append(cmdArgs, fmt.Sprintf("-my-callsign=%s", args.MyCallsign))
	cmdArgs = append(cmdArgs, fmt.Sprintf("-receiver-callsign=%s", receiverCallsign))
	cmdArgs = append(cmdArgs, "-stdin", "-file-name="+fileName)
	cmdArgs = append(cmdArgs, fmt.Sprintf("-fileid=%s", cmdID))
	cmdArgs = append(cmdArgs, "-timeout-seconds=5")
	cmdArgs = append(cmdArgs, "-timeout-retries=3")
	fullCmd := fmt.Sprintf("%s %s", args.SenderBinary, strings.Join(cmdArgs, " "))
	log.Printf("Invoking sender binary: %s", fullCmd)

	cmd := exec.Command(args.SenderBinary, cmdArgs...)
	if inputData != "" {
		cmd.Stdin = strings.NewReader(inputData)
	} else {
		cmd.Stdin = os.Stdin
	}
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
	if err := cmd.Start(); err != nil {
		log.Printf("Error starting sender binary: %v", err)
		return
	}
	go func() {
		scanner := bufio.NewScanner(stdoutPipe)
		for scanner.Scan() {
			log.Printf("[sender stdout] %s", scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			log.Printf("Error reading sender stdout: %v", err)
		}
	}()
	go func() {
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			log.Printf("[sender stderr] %s", scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			log.Printf("Error reading sender stderr: %v", err)
		}
	}()
	if err := cmd.Wait(); err != nil {
		log.Printf("Sender binary exited with error: %v", err)
	} else {
		log.Printf("Sender binary completed successfully.")
	}
}

// --- Invoking the Receiver Binary ---
func invokeReceiverBinary(args *Arguments, senderCallsign, fileName, cmdID, baseDir string) error {
	if _, alreadyRunning := runningReceiver.LoadOrStore(senderCallsign, true); alreadyRunning {
		log.Printf("A receiver binary is already running for callsign %s", senderCallsign)
		return fmt.Errorf("receiver binary already running for callsign %s", senderCallsign)
	}

	var cmdArgs []string
	cmdArgs = append(cmdArgs, "-connection=tcp", "-host=localhost", fmt.Sprintf("-port=%d", args.PassthroughPort))
	cmdArgs = append(cmdArgs, fmt.Sprintf("-my-callsign=%s", args.MyCallsign))
	cmdArgs = append(cmdArgs, fmt.Sprintf("-callsigns=%s", senderCallsign))
	cmdArgs = append(cmdArgs, fmt.Sprintf("-fileid=%s", cmdID))
	cmdArgs = append(cmdArgs, "-one-file", "-one-file-header-timeout=10", "-stdout")
	fullCmd := fmt.Sprintf("%s %s", args.ReceiverBinary, strings.Join(cmdArgs, " "))
	log.Printf("Invoking receiver binary: %s", fullCmd)

	cmd := exec.Command(args.ReceiverBinary, cmdArgs...)
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		runningReceiver.Delete(senderCallsign)
		return fmt.Errorf("Error obtaining stdout pipe: %v", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		runningReceiver.Delete(senderCallsign)
		return fmt.Errorf("Error obtaining stderr pipe: %v", err)
	}
	go func() {
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			log.Printf("[receiver stderr] %s", scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			log.Printf("Error reading receiver stderr: %v", err)
		}
	}()

	if err := cmd.Start(); err != nil {
		runningReceiver.Delete(senderCallsign)
		return fmt.Errorf("Error starting receiver binary: %v", err)
	}

	go func() {
		output, err := io.ReadAll(stdoutPipe)
		if err != nil {
			log.Printf("Error reading receiver stdout: %v", err)
		}
		waitErr := cmd.Wait()
		if waitErr != nil {
			log.Printf("Receiver binary exited with error: %v", waitErr)
			runningReceiver.Delete(senderCallsign)
			return
		} else {
			log.Printf("Receiver binary completed successfully.")
		}

		// Compute and write the received file only if no error occurred.
		savePath := filepath.Join(baseDir, fileName)
		cleanSavePath := filepath.Clean(savePath)
		if !strings.HasPrefix(cleanSavePath, baseDir) {
			log.Printf("PUT command: attempted directory traversal in file name '%s'", fileName)
		} else {
			// If the overwrite flag is NOT set, append a counter if the file exists.
			if !globalArgs.OverwriteExisting {
				if _, err := os.Stat(cleanSavePath); err == nil {
					baseName := strings.TrimSuffix(fileName, filepath.Ext(fileName))
					ext := filepath.Ext(fileName)
					counter := 1
					for {
						newFileName := fmt.Sprintf("%s_%d%s", baseName, counter, ext)
						newPath := filepath.Join(baseDir, newFileName)
						newPath = filepath.Clean(newPath)
						if _, err := os.Stat(newPath); os.IsNotExist(err) {
							cleanSavePath = newPath
							break
						}
						counter++
					}
				}
			}
			err = ioutil.WriteFile(cleanSavePath, output, 0644)
			if err != nil {
				log.Printf("Error writing received file to %s: %v", cleanSavePath, err)
			} else {
				log.Printf("Received file saved to %s", cleanSavePath)
			}
		}
		runningReceiver.Delete(senderCallsign)
	}()

	return nil
}


// --- Periodic ID Packet Functions ---
func createIDPacket() []byte {
	dest := encodeAX25Address("BEACON", false)
	src := encodeAX25Address(serverCallsign, true)
	header := append(append(dest, src...), 0x03, 0xF0)
	info := ">KISS File Server https://github.com/madpsy/kiss-tnc-file-transfer"
	if len(info) > 128 {
		info = info[:128]
	} else {
		info += strings.Repeat(" ", 128-len(info))
	}
	return append(header, []byte(info)...)
}

func sendIDPacket() {
	conn := getConn()
	packet := createIDPacket()
	escaped := escapeData(packet)
	frame := []byte{KISS_FLAG, KISS_CMD_DATA}
	frame = append(frame, escaped...)
	frame = append(frame, KISS_FLAG)
	if _, err := conn.Write(frame); err != nil {
		log.Printf("Error sending ID packet: %v", err)
	} else {
		log.Printf("Sent ID packet")
	}
}

func main() {
	args := parseArguments()
	globalArgs = args
	serverCallsign = strings.ToUpper(args.MyCallsign)

	var absPerCallsignDir string
	if args.PerCallsignDir != "" {
		var err error
		absPerCallsignDir, err = filepath.Abs(args.PerCallsignDir)
		if err != nil {
			log.Fatalf("Error resolving per-callsign directory: %v", err)
		}
		log.Printf("Per-callsign mode active. Base directory: %s", absPerCallsignDir)
	} else {
		var err error
		absServeDir, err = filepath.Abs(args.ServeDirectory)
		if err != nil {
			log.Fatalf("Error resolving serve directory: %v", err)
		}
		absSaveDir, err = filepath.Abs(args.SaveDirectory)
		if err != nil {
			log.Fatalf("Error resolving save directory: %v", err)
		}
		log.Printf("Serving files from directory: %s", absServeDir)
		log.Printf("Received files will be saved to: %s", absSaveDir)
	}

	log.Printf("Sender binary set to: %s", args.SenderBinary)
	log.Printf("Receiver binary set to: %s", args.ReceiverBinary)

	// Populate allowed GET callsigns.
	if args.GetCallsigns != "" {
		for _, cs := range strings.Split(args.GetCallsigns, ",") {
			cs = strings.ToUpper(strings.TrimSpace(cs))
			if cs != "" {
				getAllowedCallsigns = append(getAllowedCallsigns, cs)
			}
		}
		log.Printf("Allowed GET sender callsign patterns: %v", getAllowedCallsigns)
	} else {
		log.Printf("No GET callsign filtering enabled.")
	}

	// Populate allowed PUT callsigns.
	if args.PutCallsigns != "" {
		for _, cs := range strings.Split(args.PutCallsigns, ",") {
			cs = strings.ToUpper(strings.TrimSpace(cs))
			if cs != "" {
				putAllowedCallsigns = append(putAllowedCallsigns, cs)
			}
		}
		log.Printf("Allowed PUT sender callsign patterns: %v", putAllowedCallsigns)
	} else {
		log.Printf("No PUT callsign filtering enabled.")
	}

	// Populate allowed ADMIN callsigns.
	if args.AdminCallsigns != "" {
		for _, cs := range strings.Split(args.AdminCallsigns, ",") {
			cs = strings.ToUpper(strings.TrimSpace(cs))
			if cs != "" {
				adminAllowedCallsigns = append(adminAllowedCallsigns, cs)
			}
		}
		log.Printf("Allowed ADMIN sender callsign patterns: %v", adminAllowedCallsigns)
	} else {
		log.Printf("No ADMIN callsign filtering enabled; admin commands will be denied.")
	}

	// Establish the underlying KISS connection.
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
	setConn(conn)
	defer conn.Close()

	log.Printf("File Server started. My callsign: %s", serverCallsign)

	// Start periodic ID packet sender if enabled.
	if args.IdPeriod > 0 {
		go func() {
			ticker := time.NewTicker(time.Duration(args.IdPeriod) * time.Minute)
			defer ticker.Stop()
			sendIDPacket()
			for range ticker.C {
				sendIDPacket()
			}
		}()
	}

	// Start cache cleanup goroutine.
	go cacheCleanup()

	// Create a broadcaster to distribute data read from the underlying connection.
	broadcaster = NewBroadcaster()
	lastDataTime = time.Now()
	go startKISSReader(getConn(), broadcaster)
	go monitorInactivity(600 * time.Second)
	go startTransparentListener(args.PassthroughPort, broadcaster)

	// Command processing: subscribe to the broadcaster.
	cmdSub := broadcaster.Subscribe()
	defer broadcaster.Unsubscribe(cmdSub)
	var buffer []byte
	for data := range cmdSub {
		buffer = append(buffer, data...)
		frames, remaining := extractKISSFrames(buffer)
		buffer = remaining
		for _, frame := range frames {
			if len(frame) < 3 {
				continue
			}
			if frame[0] != KISS_FLAG || frame[len(frame)-1] != KISS_FLAG {
				continue
			}
			inner := frame[2 : len(frame)-1]
			unesc := unescapeData(inner)
			sender, cmdID, command, ok := parseCommandPacket(unesc)
			if !ok {
				continue
			}
			cacheKey := sender + ":" + cmdID

			// First, check if a valid cached response exists.
			rspCacheLock.Lock()
			if cached, exists := rspCache[cacheKey]; exists && time.Since(cached.timestamp) < 30*time.Second {
				rspCacheLock.Unlock()
				conn := getConn()
				_, err := conn.Write(cached.frame)
				if err != nil {
					log.Printf("Error sending cached response for duplicate command: %v", err)
				} else {
					log.Printf("Duplicate CMD received. Resent cached response for key %s", cacheKey)
				}
				continue
			}
			rspCacheLock.Unlock()

			// Next, check if this command is already being processed.
			processingCommandsLock.Lock()
			if ch, exists := processingCommands[cacheKey]; exists {
				processingCommandsLock.Unlock()
				<-ch // wait until processing completes
				// Then re-check the cache.
				rspCacheLock.Lock()
				if cached, exists := rspCache[cacheKey]; exists && time.Since(cached.timestamp) < 30*time.Second {
					rspCacheLock.Unlock()
					conn := getConn()
					_, err := conn.Write(cached.frame)
					if err != nil {
						log.Printf("Error sending cached response for duplicate command: %v", err)
					} else {
						log.Printf("Duplicate CMD received while processing. Resent cached response for key %s", cacheKey)
					}
					continue
				}
				rspCacheLock.Unlock()
			} else {
				// Mark this command as in progress.
				ch := make(chan struct{})
				processingCommands[cacheKey] = ch
				processingCommandsLock.Unlock()
				// Ensure that we remove the processing marker when done.
				defer func(key string, ch chan struct{}) {
					processingCommandsLock.Lock()
					close(ch)
					delete(processingCommands, key)
					processingCommandsLock.Unlock()
				}(cacheKey, ch)
			}

			upperCmd := strings.ToUpper(command)
			var baseDir string
			if globalArgs.PerCallsignDir != "" {
				baseDir = filepath.Join(absPerCallsignDir, sender)
				os.MkdirAll(baseDir, 0755)
				readmePath := filepath.Join(baseDir, "README.txt")
				if _, err := os.Stat(readmePath); os.IsNotExist(err) {
					readmeContent := fmt.Sprintf("Welcome %s to your personal file store!\n\nYou have full permissions to all files here and can use it to store any files you wish.\n\nHave fun!", sender)
					if err := ioutil.WriteFile(readmePath, []byte(readmeContent), 0644); err != nil {
						log.Printf("Error creating README.txt: %v", err)
					}
				}
			}
			if strings.HasPrefix(upperCmd, "GET ") {
				if globalArgs.PerCallsignDir == "" && !callsignAllowedForGet(sender) {
					log.Printf("Dropping GET command from sender %s: not allowed.", sender)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "CALLSIGN NOT ALLOWED")
					continue
				}
				fileName := strings.TrimSpace(command[4:])
				if len(fileName) > maxFileNameLen {
					log.Printf("GET command: file name '%s' too long", fileName)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "FILE NAME TOO LONG")
					continue
				}
				if isFilenameDisallowed(fileName) {
					log.Printf("GET command: access to file '%s' is forbidden", fileName)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "FILE NAME NOT ALLOWED")
					continue
				}
				var dir string
				if globalArgs.PerCallsignDir != "" {
					dir = baseDir
				} else {
					dir = absServeDir
				}
				requestedPath := filepath.Join(dir, fileName)
				cleanPath := filepath.Clean(requestedPath)
				if !strings.HasPrefix(cleanPath, dir) {
					log.Printf("GET command: attempted directory traversal in '%s'", fileName)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "INVALID FILE PATH")
					continue
				}
				content, err := ioutil.ReadFile(cleanPath)
				if err != nil {
					log.Printf("Requested file '%s' does not exist in directory %s", fileName, dir)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "CANNOT FIND/READ FILE")
					continue
				}
				if _, alreadyRunning := runningSender.Load(sender); alreadyRunning {
					log.Printf("A sender binary is already running for callsign %s", sender)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "REQUEST ALREADY IN PROGRESS")
					continue
				}
				_, _ = sendResponseWithDetails(sender, cmdID, command, 1, "GET OK")
				go invokeSenderBinary(args, sender, fileName, string(content), cmdID)
			} else if strings.HasPrefix(upperCmd, "LIST") {
				var dir string
				if globalArgs.PerCallsignDir != "" {
					dir = baseDir
				} else {
					dir = absServeDir
				}
				listing, err := listFiles(dir)
				if err != nil {
					log.Printf("Error listing files: %v", err)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "LIST CANNOT READ")
					continue
				}
				if _, alreadyRunning := runningSender.Load(sender); alreadyRunning {
					log.Printf("A sender binary is already running for callsign %s", sender)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "REQUEST ALREADY IN PROGRESS")
					continue
				}
				_, _ = sendResponseWithDetails(sender, cmdID, command, 1, "LIST OK")
				go invokeSenderBinary(args, sender, "LIST.txt", listing, cmdID)
			} else if strings.HasPrefix(upperCmd, "PUT ") {
				if globalArgs.PerCallsignDir == "" && !callsignAllowedForPut(sender) {
					log.Printf("PUT command from sender %s not allowed.", sender)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "CALLSIGN NOT ALLOWED")
					continue
				}
				fileName := strings.TrimSpace(command[4:])
				if len(fileName) > maxFileNameLen {
					log.Printf("PUT command: file name '%s' too long", fileName)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "FILE NAME TOO LONG")
					continue
				}
				if isFilenameDisallowed(fileName) {
					log.Printf("PUT command: access to file '%s' is forbidden", fileName)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "FILE NAME NOT ALLOWED")
					continue
				}
				var dir string
				if globalArgs.PerCallsignDir != "" {
					dir = baseDir
				} else {
					dir = absSaveDir
				}
				savePath := filepath.Join(dir, fileName)
				cleanSavePath := filepath.Clean(savePath)
				if !strings.HasPrefix(cleanSavePath, dir) {
					log.Printf("PUT command: attempted directory traversal in '%s'", fileName)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "INVALID FILE PATH")
					continue
				}
				if _, alreadyRunning := runningReceiver.Load(sender); alreadyRunning {
					log.Printf("A receiver binary is already running for callsign %s", sender)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "REQUEST ALREADY IN PROGRESS")
					continue
				}
				err := invokeReceiverBinary(args, sender, fileName, cmdID, dir)
				if err != nil {
					log.Printf("Receiver binary error: %v", err)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "PUT FAILED: CANNOT START RECEIVER")
				} else {
					_, _ = sendResponseWithDetails(sender, cmdID, command, 1, "PUT OK - WAITING FOR FILE")
				}
			} else if strings.HasPrefix(upperCmd, "DEL ") {
				if globalArgs.PerCallsignDir == "" && !callsignAllowedForAdmin(sender) {
					log.Printf("Admin command DEL from sender %s not allowed.", sender)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "CALLSIGN NOT ALLOWED")
					continue
				}
				fileName := strings.TrimSpace(command[4:])
				if len(fileName) > maxFileNameLen {
					log.Printf("DEL command: file name '%s' too long", fileName)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "FILE NAME TOO LONG")
					continue
				}
				if isFilenameDisallowed(fileName) {
					log.Printf("DEL command: access to file '%s' is forbidden", fileName)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "FILE NAME NOT ALLOWED")
					continue
				}
				var dir string
				if globalArgs.PerCallsignDir != "" {
					dir = baseDir
				} else {
					dir = absServeDir
				}
				fullPath := filepath.Join(dir, fileName)
				cleanPath := filepath.Clean(fullPath)
				if !strings.HasPrefix(cleanPath, dir) {
					log.Printf("DEL command: attempted directory traversal in '%s'", fileName)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "INVALID FILE PATH")
					continue
				}
				if _, err := os.Stat(cleanPath); os.IsNotExist(err) {
					log.Printf("DEL command: file '%s' does not exist", fileName)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "FILE DOES NOT EXIST")
					continue
				}
				err := os.Remove(cleanPath)
				if err != nil {
					log.Printf("DEL command: error deleting file '%s': %v", fileName, err)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "DEL FAILED")
				} else {
					log.Printf("DEL command: file '%s' deleted successfully", fileName)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 1, "DEL OK")
				}
			} else if strings.HasPrefix(upperCmd, "REN ") {
				if globalArgs.PerCallsignDir == "" && !callsignAllowedForAdmin(sender) {
					log.Printf("Admin command REN from sender %s not allowed.", sender)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "CALLSIGN NOT ALLOWED")
					continue
				}
				params := strings.TrimSpace(command[4:])
				parts := strings.SplitN(params, "|", 2)
				if len(parts) != 2 || strings.TrimSpace(parts[1]) == "" {
					log.Printf("REN command: new filename not specified in '%s'", params)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "NEW FILENAME NOT SPECIFIED")
					continue
				}
				currentFile := strings.TrimSpace(parts[0])
				newFile := strings.TrimSpace(parts[1])
				if len(currentFile) > maxFileNameLen || len(newFile) > maxFileNameLen {
					log.Printf("REN command: one or both filenames ('%s', '%s') are too long", currentFile, newFile)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "FILE NAME TOO LONG")
					continue
				}
				if isFilenameDisallowed(currentFile) || isFilenameDisallowed(newFile) {
					log.Printf("REN command: renaming of file '%s' or '%s' is forbidden", currentFile, newFile)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "FILE NAME NOT ALLOWED")
					continue
				}
				var dir string
				if globalArgs.PerCallsignDir != "" {
					dir = baseDir
				} else {
					dir = absServeDir
				}
				currentPath := filepath.Join(dir, currentFile)
				newPath := filepath.Join(dir, newFile)
				cleanCurrent := filepath.Clean(currentPath)
				cleanNew := filepath.Clean(newPath)
				if !strings.HasPrefix(cleanCurrent, dir) || !strings.HasPrefix(cleanNew, dir) {
					log.Printf("REN command: attempted directory traversal with filenames '%s' or '%s'", currentFile, newFile)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "INVALID FILE PATH")
					continue
				}
				if _, err := os.Stat(cleanCurrent); os.IsNotExist(err) {
					log.Printf("REN command: current file '%s' does not exist", currentFile)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "CURRENT FILE DOES NOT EXIST")
					continue
				}
				if _, err := os.Stat(cleanNew); err == nil {
					log.Printf("REN command: new file '%s' already exists", newFile)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "NEW FILE ALREADY EXISTS")
					continue
				}
				err := os.Rename(cleanCurrent, cleanNew)
				if err != nil {
					log.Printf("REN command: error renaming file from '%s' to '%s': %v", currentFile, newFile, err)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "REN FAILED")
				} else {
					log.Printf("REN command: file renamed from '%s' to '%s' successfully", currentFile, newFile)
					_, _ = sendResponseWithDetails(sender, cmdID, command, 1, "REN OK")
				}
			} else {
				log.Printf("Unrecognized command: %s", command)
				_, _ = sendResponseWithDetails(sender, cmdID, command, 0, "AVAILABLE: LIST, GET [FILE], PUT [FILE], DEL [FILE], REN [CUR]|[NEW]")
			}
		}
	}
}
