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
	"encoding/base64"

	"github.com/gorilla/handlers"
)

// CacheEntry represents a cached file.
type CacheEntry struct {
    Content    []byte
    Expiration time.Time
    Negative   bool
}

var (
    fileCache      = make(map[string]CacheEntry)
    fileCacheMutex sync.RWMutex
)

// Global constants for KISS framing.
const (
	KISS_FLAG     = 0xC0
	KISS_CMD_DATA = 0x00
)

// Global debug flag.
var debugEnabled bool

// (Note: getQueueMutex is no longer used for GET request queuing.)
// var getQueueMutex sync.Mutex

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

func checkValidCallsign(s string) bool {
	// Inline ASCII helper functions.
	isLetter := func(b byte) bool { return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') }
	isDigit := func(b byte) bool { return b >= '0' && b <= '9' }
	isAlphaNum := func(b byte) bool { return isLetter(b) || isDigit(b) }

	// Process optional SSID if a dash exists (but not at the start).
	if i := strings.Index(s, "-"); i > 0 {
		ssid := s[i+1:]
		if strings.Index(ssid, "-") != -1 || len(ssid) > 2 {
			return false
		}
		for j := 0; j < len(ssid); j++ {
			if !isAlphaNum(ssid[j]) {
				return false
			}
		}
		s = s[:i]
	}
	n := len(s)
	if n < 4 || n > 6 {
		return false
	}
	// If callsign is shorter than 6 and follows letter-digit-letter-letter, prepend a space.
	if n < 6 && isLetter(s[0]) && isDigit(s[1]) && isLetter(s[2]) && isLetter(s[3]) {
		s = " " + s
	}
	// Check key positions: normally index 2 must be a digit and index 3 a letter,
	// unless a special 'R' exception applies.
	if !(isDigit(s[2]) && isLetter(s[3])) && (s[0] != 'R' || !isDigit(s[1]) || !isLetter(s[2])) {
		return false
	}
	// Allowed patterns.
	if !(((s[0] == ' ' || isLetter(s[0]) || isDigit(s[0])) && isLetter(s[1])) ||
		(isLetter(s[0]) && isDigit(s[1])) ||
		(s[0] == 'R' && len(s) == 6 && isDigit(s[1]) && isLetter(s[2]) && isLetter(s[3]) && isLetter(s[4]))) {
		return false
	}
	// For callsigns longer than 4, ensure all extra characters are letters.
	for i := 4; i < len(s); i++ {
		if !isLetter(s[i]) {
			return false
		}
	}
	return true
}

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

// csvToHTML converts CSV text into an HTML table where the first column's value is an anchor link.
func csvToHTML(csvText string) (string, error) {
	r := csv.NewReader(strings.NewReader(csvText))
	records, err := r.ReadAll()
	if err != nil {
		return "", err
	}
	if len(records) == 0 {
		return "", fmt.Errorf("no CSV data found")
	}
	var sb strings.Builder
	sb.WriteString("<html><head><title>File List</title></head><body>\n")
	sb.WriteString("<table border='1'>\n")
	// Header row.
	sb.WriteString("<tr>")
	for _, cell := range records[0] {
		sb.WriteString("<th>" + cell + "</th>")
	}
	sb.WriteString("</tr>\n")
	// Data rows.
	for _, row := range records[1:] {
		sb.WriteString("<tr>")
		if len(row) > 0 {
			fileName := row[0]
			link := fmt.Sprintf("<a href=\"/%s\">%s</a>", fileName, fileName)
			sb.WriteString("<td>" + link + "</td>")
		}
		for i := 1; i < len(row); i++ {
			sb.WriteString("<td>" + row[i] + "</td>")
		}
		sb.WriteString("</tr>\n")
	}
	sb.WriteString("</table>\n")
	sb.WriteString("</body></html>")
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
	HTTPQueueLimit     int    // Maximum GET requests queued before returning 429 (default 5)
	NonInteractive     bool   // If true, do not start interactive command interface.
	HttpLogFile        string // (New) Path to file for HTTP logging (if specified, logs are written there)
	HTTPMaxRequestTime time.Duration // Maximum time to wait for an HTTP GET request before timing out (default 10 minutes)
	HTTPCacheTime      int           // Cache time for HTTP responses in minutes (0 disables caching); default 5 minutes
	HTTPNegativeCache  bool          // New: Cache negative GET responses; default false
	HTTPFavicon404     bool          // New: if true, favicon.ico requests always return a 404
	HTTPRobotsDisallow bool          // New: if true, robots.txt request returns fixed disallow content
	HTTPCallsignAuth   bool          // New: if true, require basic auth with valid callsign username for HTTP requests
	HTTPCacheList      bool          // New: cache the response for HTTP "LIST" requests (default false)
	HTTPIgnoreCacheControl bool     // New: if true, serve files from cache even if the browser sends a no-cache header
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
	// New flag: HTTP queue limit.
	flag.IntVar(&args.HTTPQueueLimit, "http-queue", 5, "Maximum GET requests queued before returning 429")
	flag.BoolVar(&args.NonInteractive, "non-interactive", false, "Run the program without starting the interactive command interface")
	flag.StringVar(&args.HttpLogFile, "http-log-file", "", "Path to HTTP log file (if specified, logs will be written there in Apache combined format)")
	flag.DurationVar(&args.HTTPMaxRequestTime, "http-max-request-time", 10*time.Minute, "Maximum time to wait for an HTTP GET request before timing out")
	flag.IntVar(&args.HTTPCacheTime, "http-cache-time", 5, "Cache time for HTTP responses in minutes (0 disables caching)")
	flag.BoolVar(&args.HTTPNegativeCache, "http-negative-cache", false, "Cache negative GET responses (default false)")
	flag.BoolVar(&args.HTTPFavicon404, "http-favicon-404", false, "If set, HTTP server returns 404 for favicon.ico requests")
	flag.BoolVar(&args.HTTPRobotsDisallow, "http-robots-disallow", false, "If set, robots.txt returns fixed disallow content (default false)")
	// New flag: require basic auth with callsign username for HTTP requests.
	flag.BoolVar(&args.HTTPCallsignAuth, "http-callsign-auth", false, "Require basic auth with valid callsign username for HTTP requests")
	flag.BoolVar(&args.HTTPCacheList, "http-cache-list", false, "Cache HTTP response for LIST requests (default false)")
	flag.BoolVar(&args.HTTPIgnoreCacheControl, "http-ignore-cache-control", false, "If set, serve files from cache even if the browser sends a no-cache header")
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

func myLogFormatter(writer io.Writer, params handlers.LogFormatterParams) {
    // Get the client IP from the remote address.
    ip, _, err := net.SplitHostPort(params.Request.RemoteAddr)
    if err != nil {
        ip = params.Request.RemoteAddr
    }

    // Retrieve the X-Forwarded-For header.
    xfwd := params.Request.Header.Get("X-Forwarded-For")
    if xfwd == "" {
        xfwd = "-"
    }

    username := "-"
    authHeader := params.Request.Header.Get("Authorization")
    if strings.HasPrefix(authHeader, "Basic ") {
        // Remove the "Basic " prefix and decode the credentials.
        decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authHeader, "Basic "))
        if err == nil {
            // The decoded string is in the format "username:password"
            parts := strings.SplitN(string(decoded), ":", 2)
            if len(parts) > 0 && parts[0] != "" {
                username = parts[0]
            }
        }
    }
    
    fmt.Fprintf(writer, "%s %s %s [%s] \"%s %s %s\" %d %d \"%s\" \"%s\"\n",
        ip,
        xfwd,
        username,
        params.TimeStamp.Format("02/Jan/2006:15:04:05 -0700"),
        params.Request.Method,
        params.Request.RequestURI,
        params.Request.Proto,
        params.StatusCode,
        params.Size,
        params.Request.Referer(),
        params.Request.UserAgent(),
    )
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
				// For CLI, keep the plain text pretty table.
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
        "svg":   "image/svg+xml",
        "css":   "text/css",
        "js":    "application/javascript",
        "html":  "text/html",
        "json":  "application/json",
        "png":   "image/png",
        "jpg":   "image/jpeg",
        "jpeg":  "image/jpeg",
        "gif":   "image/gif",
        "ico":   "image/x-icon",
        "mp3":   "audio/mpeg",
        "wav":   "audio/wav",
        "mp4":   "video/mp4",
        "webm":  "video/webm",
        "txt":   "text/plain",
        "csv":   "text/csv",
        "xml":   "application/xml",
        "pdf":   "application/pdf",
        "zip":   "application/zip",
        "tar":   "application/x-tar",
        "gz":    "application/gzip",
        "doc":   "application/msword",
        "docx":  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xls":   "application/vnd.ms-excel",
        "xlsx":  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "ppt":   "application/vnd.ms-powerpoint",
        "pptx":  "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "rtf":   "application/rtf",
        "7z":    "application/x-7z-compressed",
        "mpg":   "video/mpeg",
        "mpeg":  "video/mpeg",
        "avi":   "video/x-msvideo",
        "flac":  "audio/flac",
        "ogg":   "audio/ogg",
        "webp":  "image/webp",
        "woff":  "font/woff",
        "woff2": "font/woff2",
        "ttf":   "font/ttf",
        "otf":   "font/otf",
        "eot":   "application/vnd.ms-fontobject",
    }

    // Create a channel to limit the number of queued GET requests.
    getQueue := make(chan struct{}, args.HTTPQueueLimit)
    // Create a mutex to ensure that only one GET command is processed at a time.
    var getCmdMutex sync.Mutex

    // Create a new ServeMux and register the GET handler.
    mux := http.NewServeMux()
    mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodGet {
            http.Error(w, "Only GET allowed", http.StatusMethodNotAllowed)
            return
        }

        // If HTTPCallsignAuth is enabled, require Basic Auth with a valid callsign as username.
        if args.HTTPCallsignAuth {
            username, _, ok := r.BasicAuth()
            if !ok || !checkValidCallsign(username) {
                w.Header().Set("WWW-Authenticate", `Basic realm="Enter a valid amateur radio callsign"`)
                http.Error(w, "Unauthorised - use your amateur radio callsign as the username (password not required)", http.StatusUnauthorized)
                return
            }
        }

        // Attempt to queue the GET request.
        select {
        case getQueue <- struct{}{}:
            defer func() { <-getQueue }()
        default:
            queued := len(getQueue)
            w.WriteHeader(http.StatusTooManyRequests)
            fmt.Fprintf(w, "Please wait before sending more requests (%d)", queued)
            return
        }

        // Enforce that only one GET command is processed at a time.
        getCmdMutex.Lock()
        defer getCmdMutex.Unlock()

        requestedPath := r.URL.Path
        // Remove leading '/' if present.
        if strings.HasPrefix(requestedPath, "/") {
            requestedPath = requestedPath[1:]
        }

	// Check if the requested path is too long.
	if len(requestedPath) > 58 {
	    http.Error(w, "Error: Requested path too long", http.StatusNotFound)
	    return
	}

        // Normalize the requested path for list requests.
        if strings.EqualFold(requestedPath, "list") || strings.EqualFold(requestedPath, "list.txt") {
            requestedPath = "LIST.txt"
        }
        // If favicon.ico is requested and the option is enabled, immediately return a 404.
        if args.HTTPFavicon404 && strings.EqualFold(requestedPath, "favicon.ico") {
            http.Error(w, "Not Found", http.StatusNotFound)
            return
        }
        if args.HTTPRobotsDisallow && strings.EqualFold(requestedPath, "robots.txt") {
            w.Header().Set("Content-Type", "text/plain; charset=utf-8")
            w.WriteHeader(http.StatusOK)
            w.Write([]byte("User-agent: *\nDisallow: /"))
            return
        }
        // Default to index.html if root or directory.
        if requestedPath == "" || strings.HasSuffix(requestedPath, "/") {
            requestedPath = requestedPath + "index.html"
        }
        if requestedPath == "" {
            http.Error(w, "No file specified", http.StatusBadRequest)
            return
        }

        // Check for "Cache-Control: no-cache" header.
        cacheControl := r.Header.Get("Cache-Control")
        noCache := strings.Contains(cacheControl, "no-cache")

        // If the http-ignore-cache-control flag is set, ignore the browser's no-cache header.
        if args.HTTPIgnoreCacheControl {
            noCache = false
        }

        // Attempt to serve from cache if allowed.
        if !noCache {
            fileCacheMutex.RLock()
            entry, exists := fileCache[requestedPath]
            fileCacheMutex.RUnlock()
            if exists && time.Now().Before(entry.Expiration) {
                log.Printf("Serving %s from cache", requestedPath)
                // Check if the cache entry is negative; if so, return a 404.
                if entry.Negative {
                    http.Error(w, string(entry.Content), http.StatusNotFound)
                    return
                }
                // For a LIST request, force HTML content.
                if strings.EqualFold(requestedPath, "LIST.txt") {
                    w.Header().Set("Content-Type", "text/html")
                    w.Header().Set("Content-Disposition", "inline; filename=\"LIST.html\"")
                } else {
                    ext := strings.TrimPrefix(strings.ToLower(filepath.Ext(requestedPath)), ".")
                    if mime, exists := mimeTypes[ext]; exists {
                        w.Header().Set("Content-Type", mime)
                        w.Header().Set("Content-Disposition", "inline; filename=\""+filepath.Base(requestedPath)+"\"")
                    } else {
                        w.Header().Set("Content-Type", "application/octet-stream")
                        w.Header().Set("Content-Disposition", "attachment; filename=\""+filepath.Base(requestedPath)+"\"")
                    }
                }
                w.Header().Set("Cache-Control", "public, max-age=86400")
                w.Header().Set("Expires", time.Now().Add(24*time.Hour).Format(http.TimeFormat))
                w.Write(entry.Content)
                return
            }
        }

        // Determine the command to send.
        var commandLine string
        if requestedPath == "LIST.txt" {
            commandLine = "LIST"
        } else {
            commandLine = "GET " + requestedPath
        }

        // Attempt to send command and wait for response (with retries).
        const maxRetries = 3
        var respPayload []byte
        var err error
        var cmdID string
        for attempt := 1; attempt <= maxRetries; attempt++ {
            var packet []byte
            packet, cmdID = buildCommandPacket(args.MyCallsign, args.FileServerCallsign, commandLine)
            frame := buildKISSFrame(packet)
            err = conn.SendFrame(frame)
            if err != nil {
                http.Error(w, "Error sending command: "+err.Error(), http.StatusInternalServerError)
                return
            }
            log.Printf("HTTP GET: sent command '%s' with CMD ID %s (attempt %d)", commandLine, cmdID, attempt)
            // Wait for the direct response with a 10-second timeout.
            respPayload, err = waitForResponse(b, 10*time.Second, cmdID)
            if err == nil {
                break
            }
            log.Printf("Attempt %d: Error waiting for response: %v", attempt, err)
        }
        if err != nil {
            http.Error(w, "Error waiting for response after retries: "+err.Error(), http.StatusGatewayTimeout)
            return
        }
        _, status, msg, ok := parseResponsePacket(respPayload)
        // If the command response indicates failure, optionally cache negative responses.
        if !ok || status != 1 {
            if args.HTTPNegativeCache && !noCache && args.HTTPCacheTime > 0 && !strings.Contains(msg, "TRANSFER ALREADY IN PROGRESS") {
                fileCacheMutex.Lock()
                fileCache[requestedPath] = CacheEntry{
                    Content:    []byte("Command failed: " + msg),
                    Expiration: time.Now().Add(time.Duration(args.HTTPCacheTime) * time.Minute),
                    Negative:   true,
                }
                fileCacheMutex.Unlock()
            }
            http.Error(w, "Command failed: "+msg, http.StatusNotFound)
            return
        }

        // Spawn the receiver process to fetch the file.
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

            var contentToServe []byte
            // For a LIST command, convert the CSV to HTML.
            if commandLine == "LIST" {
                htmlTable, err := csvToHTML(string(res.output))
                if err != nil {
                    log.Printf("Error converting CSV to HTML: %v", err)
                    contentToServe = res.output
                } else {
                    contentToServe = []byte(htmlTable)
                    w.Header().Set("Content-Type", "text/html")
                    w.Header().Set("Content-Disposition", "inline; filename=\"LIST.html\"")
                }
            } else {
                contentToServe = res.output
                ext := strings.TrimPrefix(strings.ToLower(filepath.Ext(requestedPath)), ".")
                if mime, exists := mimeTypes[ext]; exists {
                    w.Header().Set("Content-Type", mime)
                    w.Header().Set("Content-Disposition", "inline; filename=\""+filepath.Base(requestedPath)+"\"")
                } else {
                    w.Header().Set("Content-Type", "application/octet-stream")
                    w.Header().Set("Content-Disposition", "attachment; filename=\""+filepath.Base(requestedPath)+"\"")
                }
            }
            w.Header().Set("Cache-Control", "public, max-age=86400")
            w.Header().Set("Expires", time.Now().Add(24*time.Hour).Format(http.TimeFormat))
            w.Write(contentToServe)

            // Cache the result if caching is allowed.
            if !noCache && args.HTTPCacheTime > 0 && (commandLine != "LIST" || (commandLine == "LIST" && args.HTTPCacheList)) {
                var contentToCache []byte
                if commandLine == "LIST" {
                    // Store the HTML version in the cache.
                    htmlTable, err := csvToHTML(string(res.output))
                    if err != nil {
                        contentToCache = res.output
                    } else {
                        contentToCache = []byte(htmlTable)
                    }
                } else {
                    contentToCache = res.output
                }
                fileCacheMutex.Lock()
                fileCache[requestedPath] = CacheEntry{
                    Content:    contentToCache,
                    Expiration: time.Now().Add(time.Duration(args.HTTPCacheTime) * time.Minute),
                    Negative:   false,
                }
                fileCacheMutex.Unlock()
            }
        case <-time.After(args.HTTPMaxRequestTime):
            http.Error(w, "Receiver process timed out", http.StatusGatewayTimeout)
            return
        }
    })

    addr := fmt.Sprintf(":%d", args.HTTPServerPort)
    log.Printf("HTTP server listening on %s", addr)
    if args.HttpLogFile != "" {
        logFile, err := os.OpenFile(args.HttpLogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
        if err != nil {
            log.Fatalf("Error opening HTTP log file: %v", err)
        }
        defer logFile.Close()
        if err := http.ListenAndServe(addr, handlers.CustomLoggingHandler(logFile, mux, myLogFormatter)); err != nil {
            log.Fatalf("HTTP server error: %v", err)
        }
    } else {
        if err := http.ListenAndServe(addr, mux); err != nil {
            log.Fatalf("HTTP server error: %v", err)
        }
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

	// If non-interactive mode is enabled, do not start the interactive command loop.
	if args.NonInteractive {
		log.Println("Running in non-interactive mode. Interactive command input is disabled.")
		// Block indefinitely to keep background services running.
		select {}
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
