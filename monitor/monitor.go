// monitor.go
package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

// KISS constants
const (
	KISS_FLAG    = 0xC0
	KISS_ESC     = 0xDB
	KISS_ESC_END = 0xDC
	KISS_ESC_ESC = 0xDD
)

// removeKISSFrame removes the starting and ending KISS_FLAG bytes and unescapes the payload.
// If the frame is malformed, it returns nil.
func removeKISSFrame(frame []byte) []byte {
	if len(frame) < 2 || frame[0] != KISS_FLAG || frame[len(frame)-1] != KISS_FLAG {
		return nil
	}
	payload := frame[1 : len(frame)-1]
	var unescaped bytes.Buffer
	i := 0
	for i < len(payload) {
		b := payload[i]
		if b == KISS_ESC && i+1 < len(payload) {
			next := payload[i+1]
			if next == KISS_ESC_END {
				unescaped.WriteByte(KISS_FLAG)
			} else if next == KISS_ESC_ESC {
				unescaped.WriteByte(KISS_ESC)
			} else {
				unescaped.WriteByte(b)
				unescaped.WriteByte(next)
			}
			i += 2
		} else {
			unescaped.WriteByte(b)
			i++
		}
	}
	return unescaped.Bytes()
}

var asciiOutput bool
var decodeFileTransfer bool

// decodeFileTransferPacket attempts to decode a file-transfer packet based on the original protocol.
// It returns a multi-line summary of all decoded fields (including total packet size) or an empty
// string if the packet cannot be decoded.
//
// For header packets (sequence 1) the info field is expected to be in the form:
//   SENDER>RECEIVER:FILEID:0001<burstHex>/<totalHex>:
// followed by a header payload:
//   timeoutSeconds|timeoutRetries|fileName|originalSize|compressedSize|md5Hash|fileID|encodingMethod|compressFlag|totalIncludingHeader
//
// For data packets the info field is expected to be in the form:
//   SENDER>RECEIVER:FILEID:<seqHex><burstHex>:
// and the payload is binary.
// decodeFileTransferPacket attempts to decode a file-transfer packet based on the original protocol.
// For ACK packets, we now extract the ACK value by splitting on "ACK:".
func decodeFileTransferPacket(packet []byte) string {
	// First, remove the KISS command byte that follows unescaping.
	if len(packet) < 1 {
		return ""
	}
	// Remove the first byte (KISS_CMD_DATA)
	packet = packet[1:]

	// Must have at least the 16-byte AX.25 header.
	if len(packet) < 16 {
		return ""
	}
	totalPacketSize := len(packet)

	// The info field and payload follow the 16-byte header.
	infoAndPayload := packet[16:]

	// If this is not an ACK packet and the info field is too short, drop it.
	if !strings.Contains(string(infoAndPayload), "ACK:") && len(infoAndPayload) < 32 {
		return ""
	}

	var infoField []byte
	var payload []byte
	// For header packets we expect a fixed structure.
	if len(infoAndPayload) >= 27 && string(infoAndPayload[23:27]) == "0001" {
		idx := bytes.IndexByte(infoAndPayload[27:], ':')
		if idx == -1 {
			return ""
		}
		endIdx := 27 + idx + 1
		infoField = infoAndPayload[:endIdx]
		payload = infoAndPayload[endIdx:]
	} else {
		// For ACK and data packets, if we're not in ACK mode, assume a fixed 32-byte info field.
		// However, for ACK packets, we'll use the entire infoAndPayload.
		if strings.Contains(string(infoAndPayload), "ACK:") {
			infoField = infoAndPayload
			payload = []byte{}
		} else {
			infoField = infoAndPayload[:32]
			payload = infoAndPayload[32:]
		}
	}

	// Use the full info string for ACK packets.
	var infoStr string
	if strings.Contains(string(infoAndPayload), "ACK:") {
		infoStr = string(infoAndPayload)
	} else {
		infoStr = string(infoField)
	}

	parts := strings.Split(infoStr, ":")
	if len(parts) < 3 {
		return ""
	}

	// Extract sender and receiver from the first field ("SENDER>RECEIVER")
	srParts := strings.Split(parts[0], ">")
	if len(srParts) != 2 {
		return ""
	}
	sender := strings.TrimSpace(srParts[0])
	receiver := strings.TrimSpace(srParts[1])

	// The fileID is in parts[1].
	fileID := strings.TrimSpace(parts[1])
	thirdField := strings.TrimSpace(parts[2])

	// ACK packet handling: Look for "ACK:" in the info string.
	if strings.Contains(infoStr, "ACK:") {
		ackParts := strings.Split(infoStr, "ACK:")
		if len(ackParts) < 2 {
			return ""
		}
		ackVal := strings.Trim(ackParts[1], ": ")
		return fmt.Sprintf("File Transfer ACK Packet:\n  Total Packet Size: %d bytes\n  Sender: %s\n  Receiver: %s\n  FileID: %s\n  ACK Value: %s",
			totalPacketSize, sender, receiver, fileID, ackVal)
	}

	// Header packet: sequence should start with "0001"
	if strings.HasPrefix(thirdField, "0001") {
		if len(thirdField) < 8 {
			return ""
		}
		// Extract burst-to (next 4 hex digits) and optionally total data packets.
		burstHex := thirdField[4:8]
		burstDec, err := strconv.ParseInt(burstHex, 16, 32)
		if err != nil {
			return ""
		}
		totalData := 0
		if slashIdx := strings.Index(thirdField, "/"); slashIdx != -1 && len(thirdField) > slashIdx+1 {
			totalHex := thirdField[slashIdx+1:]
			totalDec, err := strconv.ParseInt(totalHex, 16, 32)
			if err == nil {
				totalData = int(totalDec)
			}
		}
		// The header payload is expected to be "|" separated:
		// timeoutSeconds|timeoutRetries|fileName|originalSize|compressedSize|md5Hash|fileID|encodingMethod|compressFlag|totalIncludingHeader
		headerPayload := strings.TrimSpace(string(payload))
		headerFields := strings.Split(headerPayload, "|")
		if len(headerFields) < 10 {
			return ""
		}
		// Parse timeoutSeconds as integer
		timeoutSecondsStr := strings.TrimSpace(headerFields[0])
		timeoutSeconds, err := strconv.Atoi(timeoutSecondsStr)
		if err != nil {
			timeoutSeconds = 0
		}
		timeoutRetries := strings.TrimSpace(headerFields[1])
		fileName := headerFields[2]
		origSize := headerFields[3]
		compSize := headerFields[4]
		md5Hash := headerFields[5]
		encodingMethod := headerFields[7] // "0" = binary, "1" = base64
		compressFlag := headerFields[8]     // "1" if enabled
		totalIncludingHeader := headerFields[9]
		encStr := "Binary"
		if encodingMethod == "1" {
			encStr = "Base64"
		}
		compStr := "No"
		if compressFlag == "1" {
			compStr = "Yes"
		}
		return fmt.Sprintf("File Transfer HEADER Packet:\n  Total Packet Size: %d bytes\n  Sender: %s\n  Receiver: %s\n  FileID: %s\n  Sequence: 1\n  BurstTo: %d\n  Total Data Packets (excluding header): %d\n\n  Header Payload:\n    Timeout Seconds: %d\n    Timeout Retries: %s\n    File Name: %s\n    Original Size: %s bytes\n    Compressed Size: %s bytes\n    MD5 Hash: %s\n    Encoding: %s\n    Compression Enabled: %s\n    Total Packets (including header): %s",
			totalPacketSize, sender, receiver, fileID, burstDec, totalData,
			timeoutSeconds, timeoutRetries, fileName, origSize, compSize, md5Hash, encStr, compStr, totalIncludingHeader)
	}

	// Data packet: thirdField should be 8 hex digits (first 4 = sequence, next 4 = burstTo).
	if len(thirdField) < 8 {
		return ""
	}
	seqHex := thirdField[:4]
	burstHex := thirdField[4:8]
	seqDec, err := strconv.ParseInt(seqHex, 16, 32)
	if err != nil {
		return ""
	}
	burstDec, err := strconv.ParseInt(burstHex, 16, 32)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("File Transfer DATA Packet:\n  Total Packet Size: %d bytes\n  Sender: %s\n  Receiver: %s\n  FileID: %s\n  Sequence: %d\n  BurstTo: %d\n  Payload Length: %d bytes",
		totalPacketSize, sender, receiver, fileID, seqDec, burstDec, len(payload))
}


func main() {
	// Disable the default logger timestamp.
	log.SetFlags(0)

	// Command-line arguments for connecting to the broadcast server.
	host := flag.String("host", "127.0.0.1", "Broadcast host (default 127.0.0.1)")
	port := flag.Int("port", 0, "Broadcast port (required)")

	// MQTT options.
	mqttHost := flag.String("mqtt-host", "", "MQTT server host")
	mqttPort := flag.Int("mqtt-port", 0, "MQTT server port")
	mqttUser := flag.String("mqtt-user", "", "MQTT username")
	mqttPass := flag.String("mqtt-pass", "", "MQTT password")
	mqttTLS := flag.Bool("mqtt-tls", false, "Use TLS for MQTT")
	mqttTopic := flag.String("mqtt-topic", "", "MQTT topic to publish frames")

	// Flag for ascii output (for raw frames).
	flag.BoolVar(&asciiOutput, "ascii", false, "Print frames as ASCII text instead of hexadecimal")
	// Flag to attempt to decode file transfer packets.
	flag.BoolVar(&decodeFileTransfer, "decode-file-transfer", false, "Attempt to decode known file transfer packets")

	flag.Parse()

	if *port == 0 {
		fmt.Fprintln(os.Stderr, "Error: -port is required")
		flag.Usage()
		os.Exit(1)
	}

	mqttEnabled := false
	if *mqttHost != "" || *mqttPort != 0 || *mqttUser != "" || *mqttPass != "" || *mqttTopic != "" {
		if *mqttHost == "" || *mqttPort == 0 || *mqttUser == "" || *mqttPass == "" || *mqttTopic == "" {
			fmt.Fprintln(os.Stderr, "Error: When using MQTT, all MQTT parameters are required")
			flag.Usage()
			os.Exit(1)
		}
		mqttEnabled = true
	}

	addr := fmt.Sprintf("%s:%d", *host, *port)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		log.Fatalf("Error connecting to broadcast server at %s: %v", addr, err)
	}
	defer conn.Close()
	log.Printf("Connected to broadcast server at %s", addr)

	var mqttClient mqtt.Client
	if mqttEnabled {
		opts := mqtt.NewClientOptions()
		mqttAddr := fmt.Sprintf("tcp://%s:%d", *mqttHost, *mqttPort)
		if *mqttTLS {
			mqttAddr = fmt.Sprintf("ssl://%s:%d", *mqttHost, *mqttPort)
			tlsConfig := &tls.Config{InsecureSkipVerify: true}
			opts.SetTLSConfig(tlsConfig)
		}
		opts.AddBroker(mqttAddr)
		opts.SetUsername(*mqttUser)
		opts.SetPassword(*mqttPass)
		opts.SetClientID("monitor-client-" + fmt.Sprint(time.Now().UnixNano()))
		mqttClient = mqtt.NewClient(opts)
		if token := mqttClient.Connect(); token.Wait() && token.Error() != nil {
			log.Fatalf("Error connecting to MQTT broker: %v", token.Error())
		}
		log.Printf("Connected to MQTT broker at %s", mqttAddr)
	}

	buf := make([]byte, 4096)
	var dataBuffer []byte
	var lastPacketTime time.Time

	for {
		n, err := conn.Read(buf)
		if err != nil {
			log.Fatalf("Error reading from broadcast connection: %v", err)
		}
		if n > 0 {
			dataBuffer = append(dataBuffer, buf[:n]...)
			for {
				start := bytes.IndexByte(dataBuffer, KISS_FLAG)
				if start == -1 {
					dataBuffer = nil
					break
				}
				end := bytes.IndexByte(dataBuffer[start+1:], KISS_FLAG)
				if end == -1 {
					break
				}
				end = start + 1 + end
				frame := dataBuffer[start : end+1]
				dataBuffer = dataBuffer[end+1:]
				payload := removeKISSFrame(frame)
				if payload == nil {
					continue
				}

				// Always publish raw packet to MQTT if enabled.
				if mqttEnabled {
					token := mqttClient.Publish(*mqttTopic, 0, false, payload)
					token.Wait()
					if token.Error() != nil {
						log.Printf("Error publishing to MQTT: %v", token.Error())
					}
				}

				now := time.Now()
				delta := int64(0)
				if !lastPacketTime.IsZero() {
					delta = now.Sub(lastPacketTime).Milliseconds()
				}
				lastPacketTime = now
				timeStamp := fmt.Sprintf("[%s +%dms]", now.Format(time.RFC3339Nano), delta)

				// If decoding is enabled, only log decoded file transfer packets.
				if decodeFileTransfer {
					decoded := decodeFileTransferPacket(payload)
					if decoded != "" {
						log.Printf("%s\n%s", timeStamp, decoded)
					}
				} else {
					// Otherwise, print raw frame in ASCII or hex.
					if asciiOutput {
						log.Printf("%s %s", timeStamp, string(payload))
					} else {
						log.Printf("%s % X", timeStamp, payload)
					}
				}
			}
		}
	}
}
