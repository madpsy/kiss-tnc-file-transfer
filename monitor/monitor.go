// monitor.go
package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"os/signal"
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
var decodeAx25 bool

// decodeFileTransferPacket attempts to decode a file-transfer packet,
// and now also CMD/RSP packets.
func decodeFileTransferPacket(packet []byte) string {
	// First, remove the KISS command byte.
	if len(packet) < 1 {
		return ""
	}
	// Remove the first byte (e.g. KISS_CMD_DATA)
	packet = packet[1:]

	// Require at least 16 bytes for the AX.25 header.
	if len(packet) < 16 {
		return ""
	}
	totalPacketSize := len(packet)

	// Decode the AX.25 header addresses.
	header := packet[:16]
	dest := decodeAX25Address(header[0:7])
	src := decodeAX25Address(header[7:14])
	// For file-transfer packets, we now ignore any sender/receiver in the info field.
	sender := src
	receiver := dest

	// First, check if this is a CMD or RSP packet.
	if len(packet) >= 80 {
		infoField := packet[16:80]
		infoStr := strings.TrimSpace(string(infoField))
		if strings.HasPrefix(infoStr, "CMD:") || strings.HasPrefix(infoStr, "RSP:") {
			if strings.HasPrefix(infoStr, "CMD:") {
				if len(infoStr) < 6 {
					return ""
				}
				cmdID := infoStr[4:6]
				command := strings.TrimSpace(infoStr[6:])
				return fmt.Sprintf("CMD Packet:\n  Total Packet Size: %d bytes\n  Destination: %s\n  Source: %s\n  Command ID: %s\n  Command: %s",
					totalPacketSize, dest, src, cmdID, command)
			}
			if strings.HasPrefix(infoStr, "RSP:") {
				if len(infoStr) < 6 {
					return ""
				}
				cmdID := infoStr[4:6]
				fields := strings.Fields(infoStr)
				if len(fields) < 3 {
					return ""
				}
				statusWord := "failed"
				if fields[1] == "1" {
					statusWord = "success"
				}
				msg := strings.Join(fields[2:], " ")
				return fmt.Sprintf("RSP Packet:\n  Total Packet Size: %d bytes\n  Destination: %s\n  Source: %s\n  Command ID: %s\n  Status: %s\n  Message: %s",
					totalPacketSize, dest, src, cmdID, statusWord, msg)
			}
		}
	}

	// Now, process file-transfer packets.
	// The info field and payload follow the 16-byte header.
	infoAndPayload := packet[16:]
	if len(infoAndPayload) == 0 {
		return ""
	}

	var infoField, payload []byte

	// If this packet contains "ACK:", treat the entire remainder as the info field.
	if strings.Contains(string(infoAndPayload), "ACK:") {
		infoField = infoAndPayload
		payload = []byte{}
	} else if len(infoAndPayload) >= 17 && string(infoAndPayload[3:7]) == "0001" {
		// Header packet (seq == 1): first 17 bytes are the info field; remaining bytes are the header payload.
		infoField = infoAndPayload[:17]
		payload = infoAndPayload[17:]
	} else if len(infoAndPayload) >= 12 {
		// Data packet: 12-byte info field.
		infoField = infoAndPayload[:12]
		payload = infoAndPayload[12:]
	} else {
		return ""
	}

	infoStr := string(infoField)
	parts := strings.Split(infoStr, ":")
	if len(parts) < 3 {
		return ""
	}

	// In the new design the first field is the fileID.
	fileID := strings.TrimSpace(parts[0])

	// ACK packet handling.
	if strings.ToUpper(strings.TrimSpace(parts[1])) == "ACK" {
		// Expect format: fileID:ACK:ackValue:
		ackVal := strings.TrimSpace(parts[2])
		return fmt.Sprintf("ACK Packet:\n  Total Packet Size: %d bytes\n  Sender: %s\n  Receiver: %s\n  FileID: %s\n  ACK Value: %s",
			totalPacketSize, sender, receiver, fileID, ackVal)
	}

	// Header packet: expect second field to start with "0001"
	if strings.HasPrefix(parts[1], "0001") {
		if len(parts[1]) < 9 {
			return ""
		}
		// Extract burstTo from characters 4 to 8.
		burstHex := parts[1][4:8]
		burstDec, err := strconv.ParseInt(burstHex, 16, 32)
		if err != nil {
			return ""
		}
		// Extract total data packets from the part after "/"
		totalData := 0
		if slashIdx := strings.Index(parts[1], "/"); slashIdx != -1 && len(parts[1]) > slashIdx+1 {
			totalHex := parts[1][slashIdx+1:]
			totalDec, err := strconv.ParseInt(totalHex, 16, 32)
			if err == nil {
				totalData = int(totalDec)
			}
		}
		// The header payload (with additional file meta–data) is in the remaining payload.
		headerPayload := strings.TrimSpace(string(payload))
		headerFields := strings.Split(headerPayload, "|")
		if len(headerFields) < 10 {
			return ""
		}
		timeoutSeconds, err := strconv.Atoi(strings.TrimSpace(headerFields[0]))
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
		return fmt.Sprintf("HEADER Packet:\n  Total Packet Size: %d bytes\n  Sender: %s\n  Receiver: %s\n  FileID: %s\n  Sequence: 1\n  BurstTo: %d\n  Total Data Packets (excluding header): %d\n\n  Header Payload:\n    Timeout Seconds: %d\n    Timeout Retries: %s\n    File Name: %s\n    Original Size: %s bytes\n    Compressed Size: %s bytes\n    MD5 Hash: %s\n    Encoding: %s\n    Compression Enabled: %s\n    Total Packets (including header): %s",
			totalPacketSize, sender, receiver, fileID, burstDec, totalData,
			timeoutSeconds, timeoutRetries, fileName, origSize, compSize, md5Hash, encStr, compStr, totalIncludingHeader)
	}

	// Otherwise, assume a regular data packet.
	// In a data packet the second field should be exactly 8 hex digits: first 4 for sequence, next 4 for burstTo.
	if len(parts[1]) < 8 {
		return ""
	}
	seqHex := parts[1][:4]
	burstHex := parts[1][4:8]
	seqDec, err1 := strconv.ParseInt(seqHex, 16, 32)
	burstDec, err2 := strconv.ParseInt(burstHex, 16, 32)
	if err1 != nil || err2 != nil {
		return ""
	}
	return fmt.Sprintf("DATA Packet:\n  Total Packet Size: %d bytes\n  Sender: %s\n  Receiver: %s\n  FileID: %s\n  Sequence: %d\n  BurstTo: %d\n  Payload Length: %d bytes",
		totalPacketSize, sender, receiver, fileID, seqDec, burstDec, len(payload))
}

// decodeAX25Packet attempts to decode the AX.25 header and payload from the packet.
// If the PID is missing, it logs 'null' for the PID.
func decodeAX25Packet(packet []byte) string {
	if len(packet) == 0 {
		return "Empty packet"
	}

	// Assume the first byte is the KISS command.
	kissCmd := packet[0]
	packet = packet[1:]

	// We need at least 14 bytes for destination and source addresses.
	if len(packet) < 14 {
		return fmt.Sprintf("AX.25 header incomplete (KISS cmd 0x%02X), available bytes: % X", kissCmd, packet)
	}

	// Decode destination (first 7 bytes) and source (next 7 bytes).
	dest := decodeAX25Address(packet[0:7])
	src := decodeAX25Address(packet[7:14])

	// Decode control field if available.
	var control byte = 0
	if len(packet) >= 15 {
		control = packet[14]
	}

	// Decode PID if available; otherwise use "null".
	var pid string
	if len(packet) >= 16 {
		pid = fmt.Sprintf("0x%02X", packet[15])
	} else {
		pid = "null"
	}

	// The payload starts after the header. If PID is missing, payload starts at offset 15;
	// otherwise, it starts at offset 16.
	var payloadStart int
	if len(packet) >= 16 {
		payloadStart = 16
	} else {
		payloadStart = 15
	}

	var payloadInfo string
	if len(packet) > payloadStart {
		payloadInfo = "\nPayload (ASCII): " + string(packet[payloadStart:])
	}

	// Swap source and destination in the output.
	return fmt.Sprintf("AX.25 Header (KISS cmd 0x%02X):\n  Source: %s\n  Destination: %s\n  Control: 0x%02X\n  PID: %s",
		kissCmd, src, dest, control, pid) + payloadInfo
}

// decodeAX25Address decodes a 7-byte AX.25 address field into a human-readable callsign.
func decodeAX25Address(addr []byte) string {
	// Each address is 7 bytes. The first 6 bytes contain the callsign (each character shifted right by 1).
	callsign := ""
	for i := 0; i < 6; i++ {
		c := addr[i] >> 1
		// Only add non-space characters.
		if c != ' ' {
			callsign += string(c)
		}
	}
	// The 7th byte contains the SSID in bits 1-4.
	ssid := (addr[6] >> 1) & 0x0F
	if ssid > 0 {
		callsign += fmt.Sprintf("-%d", ssid)
	}
	return callsign
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
	// Flag to attempt to decode AX.25 packets.
	flag.BoolVar(&decodeAx25, "decode-ax25", false, "Attempt to decode all AX.25 packets")

	flag.Parse()

	// Enforce mutual exclusivity for decoding options.
	if decodeAx25 && (asciiOutput || decodeFileTransfer) {
		fmt.Fprintln(os.Stderr, "Error: -decode-ax25 is mutually exclusive with -ascii and -decode-file-transfer")
		flag.Usage()
		os.Exit(1)
	}

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

	// Setup MQTT client if enabled.
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
		// Enable automatic MQTT reconnection.
		opts.SetAutoReconnect(true)
		opts.SetConnectionLostHandler(func(client mqtt.Client, err error) {
			log.Printf("MQTT connection lost: %v. Reconnecting...", err)
		})
		mqttClient = mqtt.NewClient(opts)
		if token := mqttClient.Connect(); token.Wait() && token.Error() != nil {
			log.Fatalf("Error connecting to MQTT broker: %v", token.Error())
		}
		log.Printf("Connected to MQTT broker at %s", mqttAddr)
	}

	// --- Metrics variables ---
	var totalFrames int
	var totalBytes int
	var minDelta int64 = math.MaxInt64
	var maxDelta int64
	var lastPacketTime time.Time

	// Set up signal handling to catch Ctrl-C (SIGINT)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	go func() {
		<-sigChan
		// When Ctrl-C is caught, print the summary and exit.
		log.Printf("\n--- Summary ---")
		log.Printf("Total frames seen: %d", totalFrames)
		log.Printf("Total bytes seen: %d", totalBytes)
		if totalFrames > 1 {
			log.Printf("Minimum time between packets: %d ms", minDelta)
			log.Printf("Maximum time between packets: %d ms", maxDelta)
		} else {
			log.Printf("Not enough packets to compute time differences.")
		}
		os.Exit(0)
	}()

	// Prepare a buffer for incoming data.
	buf := make([]byte, 4096)
	var dataBuffer []byte

	addr := fmt.Sprintf("%s:%d", *host, *port)

	// Outer loop: attempt to (re)connect to the broadcast server.
	for {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			log.Printf("Error connecting to broadcast server at %s: %v. Retrying in 5 seconds...", addr, err)
			time.Sleep(5 * time.Second)
			continue
		}
		log.Printf("Connected to broadcast server at %s", addr)
		dataBuffer = nil // reset buffer for new connection

		// Inner loop: read data until an error occurs.
		for {
			n, err := conn.Read(buf)
			if err != nil {
				log.Printf("Error reading from broadcast connection: %v", err)
				conn.Close()
				break
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

					// Update metrics.
					totalFrames++
					totalBytes += len(payload)

					now := time.Now()
					var deltaStr string
					if !lastPacketTime.IsZero() {
						d := now.Sub(lastPacketTime)
						deltaMs := d.Milliseconds()
						// If the delta is less than 1ms, use microseconds.
						if deltaMs == 0 {
							deltaStr = fmt.Sprintf("+%dµs", d.Microseconds())
						} else {
							deltaStr = fmt.Sprintf("+%dms", deltaMs)
						}
						// Update the min/max metrics in ms.
						if deltaMs < minDelta {
							minDelta = deltaMs
						}
						if deltaMs > maxDelta {
							maxDelta = deltaMs
						}
					} else {
						deltaStr = ""
					}
					lastPacketTime = now
					timeStamp := fmt.Sprintf("[%s %s]", now.Format(time.RFC3339Nano), deltaStr)

					// Always publish raw packet to MQTT if enabled.
					if mqttEnabled {
						token := mqttClient.Publish(*mqttTopic, 0, false, payload)
						token.Wait()
						if token.Error() != nil {
							log.Printf("Error publishing to MQTT: %v", token.Error())
						}
					}

					// Determine which decoding/output mode to use.
					if decodeAx25 {
						decoded := decodeAX25Packet(payload)
						log.Printf("%s\n%s", timeStamp, decoded)
					} else if decodeFileTransfer {
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
		// Wait 5 seconds before attempting to reconnect.
		log.Printf("Reconnecting in 5 seconds...")
		time.Sleep(5 * time.Second)
	}
}
