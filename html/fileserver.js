// Generate a two-character command ID using crypto randomness.
function generateCmdID() {
  // crypto.getRandomValues returns a Uint8Array filled with cryptographically secure random bytes.
  const randomByte = crypto.getRandomValues(new Uint8Array(1))[0];
  // Convert to uppercase hex and pad with a leading zero if needed.
  return randomByte.toString(16).padStart(2, '0').toUpperCase();
}

// Build a CMD packet given your callsigns and command text.
// The packet consists of a 16-byte AX.25 header plus a 64-byte info field.
function buildCmdPacket(myCallsign, fileServerCallsign, commandText) {
  // Use your existing helper to build the AX.25 header (assumed to return a Uint8Array of length 16).
  const header = buildAX25Header(myCallsign, fileServerCallsign);
  // Generate a two-character command ID.
  const cmdID = generateCmdID();
  // Build the info field starting with "CMD:" + cmdID + " " followed by the command text.
  let infoStr = "CMD:" + cmdID + " " + commandText;
  // Ensure the info field is exactly 64 characters.
  if (infoStr.length > 64) {
    infoStr = infoStr.substring(0, 64);
  } else {
    infoStr = infoStr.padEnd(64, ' ');
  }
  const encoder = new TextEncoder();
  const infoBytes = encoder.encode(infoStr); // Should yield 64 bytes (assuming ASCII)
  // Concatenate the header and info field into an 80-byte packet.
  const packet = new Uint8Array(header.length + infoBytes.length);
  packet.set(header, 0);
  packet.set(infoBytes, header.length);
  return { packet, cmdID };
}

// Parse an RSP packet's info field. Expected format:
// "RSP:" + <2-character cmdID> + " " + <status> + " " + <message>
// Returns an object with the parsed cmdID, status (as a number), message, and an ok flag.
function parseRspPacket(payload) {
  // Assume 'payload' is a Uint8Array (the 64-byte info field after unescaping and trimming header if needed)
  const decoder = new TextDecoder();
  const str = decoder.decode(payload).trim();
  
  if (!str.startsWith("RSP:")) {
    return { ok: false, error: "Not an RSP packet" };
  }
  
  // Split the string by whitespace.
  const parts = str.split(/\s+/);
  if (parts.length < 2) {
    return { ok: false, error: "Incomplete RSP packet" };
  }
  
  // The first part should be "RSP:XX" where XX is the cmdID.
  const rspHeader = parts[0];
  if (rspHeader.length < 5) {
    return { ok: false, error: "Invalid RSP header" };
  }
  const cmdID = rspHeader.substring(4, 6);
  const status = parseInt(parts[1], 10);
  if (isNaN(status)) {
    return { ok: false, error: "Invalid status value" };
  }
  // The remainder of the parts (if any) form the response message.
  const message = parts.slice(2).join(" ");
  return { ok: true, cmdID, status, message };
}

// Optional: Send a CMD packet over the active connection and wait for its corresponding RSP.
// This function uses a pending responses map to associate incoming responses with sent commands.
const pendingCmdResponses = {};

function sendCmd(commandText) {
  return new Promise((resolve, reject) => {
    // Read the callsigns from the UI fields.
    const myCallsign = document.getElementById('senderCallsign').value.trim();
    const fileServerCallsign = document.getElementById('receiverCallsign').value.trim();
    // Build the CMD packet.
    const { packet, cmdID } = buildCmdPacket(myCallsign, fileServerCallsign, commandText);
    // Wrap the packet in a KISS frame.
    const kissFrame = buildKissFrame(packet);
    
    // Store the promise resolvers keyed by the command ID.
    pendingCmdResponses[cmdID] = { resolve, reject, timestamp: Date.now() };
    
    // Send the frame via websockets or serial.
    if (document.getElementById('connectionType').value === 'websockets') {
      if (socket) socket.emit('raw_kiss_frame', kissFrame);
      else reject("No websocket connection available.");
    } else if (document.getElementById('connectionType').value === 'serial' && serialWriter) {
      serialWriter.write(kissFrame).catch(err => reject(err));
    } else {
      reject("No valid connection available.");
    }
    
    // Optionally, set a timeout to reject the promise if no response arrives in time.
    const timeoutMS = (parseFloat(document.getElementById('timeoutSeconds').value) * 1000) || 10000;
    setTimeout(() => {
      if (pendingCmdResponses[cmdID]) {
        delete pendingCmdResponses[cmdID];
        reject("Timeout waiting for response for CMD ID " + cmdID);
      }
    }, timeoutMS);
  });
}