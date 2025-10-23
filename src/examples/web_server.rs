use std::io::prelude::*;
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::sync::{Arc, Mutex};
use std::collections::VecDeque;
use chrono::Local;

// Shared log buffer
type LogBuffer = Arc<Mutex<VecDeque<String>>>;

pub fn start_web_server() {
    println!("==================================================================================");
    println!("STARTING WEB SERVER - Real-time Log Streaming");
    println!("==================================================================================");
    println!("Starting HTTP server on http://127.0.0.1:8080");
    println!("Open http://127.0.0.1:8080 in your web browser to see the auction logs");
    println!("==================================================================================");
    
    let log_buffer: LogBuffer = Arc::new(Mutex::new(VecDeque::new()));
    
    // Start the server
    let listener = TcpListener::bind("127.0.0.1:8080").expect("Failed to bind to port 8080");
    
    println!("Server is ready! Waiting for connections...");
    
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let log_buffer = Arc::clone(&log_buffer);
                thread::spawn(move || {
                    handle_client(stream, log_buffer);
                });
            }
            Err(e) => {
                eprintln!("Error accepting connection: {}", e);
            }
        }
    }
}

fn handle_client(mut stream: TcpStream, log_buffer: LogBuffer) {
    let mut buffer = [0; 1024];
    stream.read(&mut buffer).unwrap();
    
    let request = String::from_utf8_lossy(&buffer[..]);
    let request_line = request.lines().next().unwrap_or("");
    
    if request_line.starts_with("GET / ") {
        // Serve the HTML page
        serve_html(&mut stream);
    } else if request_line.starts_with("GET /logs ") {
        // Serve the logs as Server-Sent Events
        serve_logs(&mut stream, log_buffer);
    } else if request_line.starts_with("POST /execute ") {
        // Execute the auction protocol
        execute_auction(&mut stream, log_buffer);
    } else {
        // 404 Not Found
        let response = "HTTP/1.1 404 NOT FOUND\r\n\r\n";
        stream.write_all(response.as_bytes()).unwrap();
    }
}

fn serve_html(stream: &mut TcpStream) {
    let html_content = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Live Auction Protocol - Real-Time Logs</title>
    <style>
        * {
            box-sizing: border-box;
        }
        body {
            font-family: 'Times New Roman', 'Georgia', serif;
            margin: 0;
            padding: 0;
            background: #f5f5f0;
            color: #333;
            line-height: 1.6;
            overflow-x: hidden;
        }
        .container {
            max-width: 100vw;
            margin: 0 auto;
            background: white;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
            border: 1px solid #ddd;
            min-height: 100vh;
            overflow-x: hidden;
        }
        .header {
            background: linear-gradient(135deg, #8B4513 0%, #A0522D 50%, #8B4513 100%);
            color: #F5F5DC;
            padding: 40px 30px;
            text-align: center;
            border-bottom: 4px solid #654321;
        }
        .header h1 {
            margin: 0;
            font-size: 3em;
            font-weight: bold;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.5);
            letter-spacing: 2px;
        }
        .header p {
            margin: 15px 0 0 0;
            font-size: 1.3em;
            font-style: italic;
            text-shadow: 1px 1px 2px rgba(0,0,0,0.5);
        }
        .header::after {
            content: '';
            display: block;
            height: 3px;
            background: linear-gradient(90deg, #FFD700, #FFA500, #FFD700);
            margin-top: 20px;
        }
        .content {
            padding: 40px;
            background: white;
        }
        .info-card {
            background: #faf9f7;
            border: 2px solid #8B4513;
            border-left: 6px solid #8B4513;
            padding: 25px;
            margin: 25px 0;
            border-radius: 0;
            box-shadow: 2px 2px 8px rgba(0,0,0,0.1);
        }
        .info-card h3 {
            color: #8B4513;
            margin-top: 0;
            font-size: 1.4em;
            border-bottom: 2px solid #8B4513;
            padding-bottom: 10px;
        }
        .form-group {
            margin: 25px 0;
        }
        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: bold;
            color: #8B4513;
            font-size: 1.1em;
        }
        .form-group input {
            width: 100%;
            padding: 15px;
            border: 2px solid #8B4513;
            border-radius: 0;
            font-size: 16px;
            font-family: 'Times New Roman', serif;
            background: #faf9f7;
            transition: border-color 0.3s, background-color 0.3s;
        }
        .form-group input:focus {
            outline: none;
            border-color: #654321;
            background: white;
            box-shadow: 0 0 5px rgba(139, 69, 19, 0.3);
        }
        .btn {
            background: linear-gradient(135deg, #8B4513 0%, #A0522D 100%);
            color: #F5F5DC;
            padding: 15px 35px;
            border: 2px solid #654321;
            border-radius: 0;
            font-size: 18px;
            font-weight: bold;
            font-family: 'Times New Roman', serif;
            cursor: pointer;
            transition: all 0.3s;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .btn:hover {
            background: linear-gradient(135deg, #A0522D 0%, #8B4513 100%);
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(139, 69, 19, 0.4);
        }
        .btn:disabled {
            background: #6c757d;
            border-color: #6c757d;
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
        }
        .log-container {
            margin-top: 30px;
            max-width: 100%;
            overflow: hidden;
        }
        .log-title {
            color: #8B4513;
            font-size: 1.4em;
            font-weight: bold;
            margin: 0 0 10px 0;
            padding: 10px 0;
            border-bottom: 2px solid #8B4513;
            text-align: center;
        }
        .bidder-pubkey {
            color: #654321;
            font-size: 0.65em;
            font-family: 'Courier New', monospace;
            text-align: center;
            margin: 0 0 15px 0;
            padding: 5px;
            background: #faf9f7;
            border: 1px solid #8B4513;
            font-weight: normal;
            word-break: break-all;
            overflow-wrap: break-word;
            max-width: 100%;
            overflow: hidden;
        }
        .bidder-logs-container {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 15px;
            margin-top: 20px;
            max-width: 100%;
            overflow: hidden;
        }
        @media (max-width: 1200px) {
            .bidder-logs-container {
                grid-template-columns: repeat(2, 1fr);
            }
        }
        @media (max-width: 768px) {
            .bidder-logs-container {
                grid-template-columns: 1fr;
            }
        }
        .log-section {
            margin-bottom: 30px;
            min-width: 0;
            overflow: hidden;
        }
        .log-box {
            background: #1a1a1a;
            color: #00ff00;
            padding: 15px;
            border-radius: 0;
            font-family: 'Courier New', monospace;
            font-size: 12px;
            height: 400px;
            overflow-y: auto;
            overflow-x: hidden;
            border: 3px solid #333;
            box-shadow: inset 0 0 10px rgba(0,0,0,0.5);
            word-break: break-all;
            overflow-wrap: break-word;
            max-width: 100%;
        }
        .log-box.host {
            border-color: #8B4513;
            border-width: 4px;
            height: 500px;
        }
        .log-box::-webkit-scrollbar {
            width: 12px;
        }
        .log-box::-webkit-scrollbar-track {
            background: #2a2a2a;
            border: 1px solid #444;
        }
        .log-box::-webkit-scrollbar-thumb {
            background: #8B4513;
            border: 1px solid #654321;
        }
        .log-box::-webkit-scrollbar-thumb:hover {
            background: #A0522D;
        }
        .log-entry {
            margin: 8px 0;
            padding: 8px;
            border-radius: 0;
            border-left: 3px solid transparent;
            word-break: break-all;
            overflow-wrap: break-word;
        }
        .log-entry.host {
            background: rgba(139, 69, 19, 0.1);
            border-left-color: #8B4513;
        }
        .log-entry.phase {
            background: rgba(255, 215, 0, 0.1);
            border-left-color: #FFD700;
            font-weight: bold;
        }
        .status {
            display: inline-block;
            padding: 5px 15px;
            border-radius: 3px;
            font-weight: bold;
            margin: 10px 0;
        }
        .status.running {
            background: #28a745;
            color: white;
            animation: pulse 1s infinite;
        }
        .status.completed {
            background: #007bff;
            color: white;
        }
        .status.idle {
            background: #6c757d;
            color: white;
        }
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.7; }
            100% { opacity: 1; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🏛️ CHRISTIE'S AUCTION HOUSE</h1>
            <p>Established 1766 • Live Protocol Execution with Real-Time Logs</p>
        </div>
        
        <div class="content">
            <div class="info-card">
                <h3>🔗 Real-Time Protocol Execution</h3>
                <p>This interface connects to a Rust web server that executes the actual <code>run_n_bidders_example</code> function
                and streams all <code>println!</code> output in real-time using Server-Sent Events (SSE).</p>
                <p><strong>Status:</strong> <span class="status idle" id="status">Idle</span></p>
            </div>
            
            <div class="form-group">
                <label for="bidderNames">Bidder Names (comma-separated):</label>
                <input type="text" id="bidderNames" value="Oscar,Bob,Alice" placeholder="Enter bidder names separated by commas">
            </div>
            
            <div class="form-group">
                <label for="bidValues">Bid Values (comma-separated):</label>
                <input type="text" id="bidValues" value="10000,5000,3000" placeholder="Enter bid values separated by commas">
            </div>
            
            <button class="btn" id="executeBtn" onclick="executeProtocol()">Execute Real Protocol</button>
            <button class="btn" id="clearBtn" onclick="clearLogs()" style="margin-left: 10px;">Clear Logs</button>
            
            <div class="log-container">
                <div class="bidder-logs-container" id="bidderLogsContainer">
                    <!-- Bidder log boxes will be dynamically created here -->
                </div>
                
                <div class="log-section">
                    <h3 class="log-title">🏛️ Auctioneer Console</h3>
                    <div class="log-box host" id="hostLogBox">
                        <div id="hostLogContent"></div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        let eventSource = null;
        let isRunning = false;
        let bidders = [];
        
        function executeProtocol() {
            if (isRunning) {
                alert("Protocol is already running!");
                return;
            }
            
            const bidderNames = document.getElementById('bidderNames').value.split(',').map(s => s.trim());
            const bidValues = document.getElementById('bidValues').value;
            
            // Store bidders for log routing
            bidders = bidderNames;
            
            // Clear logs and create bidder log boxes
            document.getElementById('hostLogContent').innerHTML = '';
            createBidderLogBoxes(bidderNames);
            
            // Update status
            updateStatus('running', 'Running');
            isRunning = true;
            document.getElementById('executeBtn').disabled = true;
            
            // Send POST request to execute the protocol
            fetch('/execute', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    bidderNames: bidderNames,
                    bidValues: bidValues
                })
            })
            .then(response => response.text())
            .then(data => {
                logMessage('Server response: ' + data);
                // Start listening for logs
                connectToLogStream();
            })
            .catch(error => {
                logMessage('Error: ' + error);
                updateStatus('idle', 'Idle');
                isRunning = false;
                document.getElementById('executeBtn').disabled = false;
            });
        }
        
        function connectToLogStream() {
            if (eventSource) {
                eventSource.close();
            }
            
            eventSource = new EventSource('/logs');
            
            eventSource.onmessage = function(event) {
                logMessage(event.data);
            };
            
            eventSource.onerror = function(error) {
                console.error('EventSource error:', error);
                eventSource.close();
                updateStatus('completed', 'Completed');
                isRunning = false;
                document.getElementById('executeBtn').disabled = false;
            };
        }
        
        function createBidderLogBoxes(bidderNames) {
            const container = document.getElementById('bidderLogsContainer');
            container.innerHTML = '';
            
            bidderNames.forEach(bidder => {
                const logSection = document.createElement('div');
                logSection.className = 'log-section';
                
                const title = document.createElement('h3');
                title.className = 'log-title';
                title.textContent = `📊 ${bidder}'s Log`;
                
                const pubkeyDiv = document.createElement('div');
                pubkeyDiv.className = 'bidder-pubkey';
                pubkeyDiv.id = `${bidder}PubKey`;
                pubkeyDiv.textContent = 'Public Key: (waiting for key generation...)';
                
                const logBox = document.createElement('div');
                logBox.className = 'log-box';
                logBox.id = `${bidder}LogBox`;
                
                const logContent = document.createElement('div');
                logContent.id = `${bidder}LogContent`;
                
                logBox.appendChild(logContent);
                logSection.appendChild(title);
                logSection.appendChild(pubkeyDiv);
                logSection.appendChild(logBox);
                container.appendChild(logSection);
            });
        }
        
        function extractAndDisplayPubKey(bidder, message) {
            // Extract public key from messages like "bidder X generated public key n_j = 12345..."
            const match = message.match(/generated public key n_j = (\d+)/);
            if (match) {
                const fullPubKey = match[1];
                const truncated = fullPubKey.length > 10 
                    ? `${fullPubKey.substring(0, 5)}...${fullPubKey.substring(fullPubKey.length - 5)}`
                    : fullPubKey;
                
                const pubkeyDiv = document.getElementById(`${bidder}PubKey`);
                if (pubkeyDiv) {
                    pubkeyDiv.textContent = `Public Key: ${truncated}`;
                }
            }
        }
        
        function getBidderFromLog(message) {
            // Extract bidder name from patterns like [(Alice)-...] or (Alice)
            const match = message.match(/\[\(([^)]+)\)[^\]]*\]|^[^[]*\(([^)]+)\)/);
            if (match) {
                const bidderName = match[1] || match[2];
                // Check if this is one of our bidders
                for (const bidder of bidders) {
                    if (bidderName.includes(bidder) || bidder.includes(bidderName)) {
                        return bidder;
                    }
                }
            }
            return null;
        }
        
        function logMessage(message) {
            // Determine which log box to use
            const bidder = getBidderFromLog(message);
            
            if (bidder) {
                // Route to specific bidder's log box
                const logContent = document.getElementById(`${bidder}LogContent`);
                const logBox = document.getElementById(`${bidder}LogBox`);
                if (logContent && logBox) {
                    const entry = document.createElement('div');
                    entry.className = 'log-entry bidder';
                    entry.textContent = message;
                    logContent.appendChild(entry);
                    logBox.scrollTop = logBox.scrollHeight;
                    
                    // Try to extract and display public key
                    extractAndDisplayPubKey(bidder, message);
                }
            } else if (message.includes('[(auctioneer)-host')) {
                // Route to auctioneer log box only
                const logContent = document.getElementById('hostLogContent');
                const logBox = document.getElementById('hostLogBox');
                const entry = document.createElement('div');
                
                if (message.includes('PHASE') && message.includes('===')) {
                    entry.className = 'log-entry phase';
                } else {
                    entry.className = 'log-entry host';
                }
                
                entry.textContent = message;
                logContent.appendChild(entry);
                logBox.scrollTop = logBox.scrollHeight;
            } else if (message.includes('[host') || message.includes('[WEB-SERVER]')) {
                // General host logs - replicate to ALL bidder boxes ONLY (not auctioneer)
                bidders.forEach(bidder => {
                    const logContent = document.getElementById(`${bidder}LogContent`);
                    const logBox = document.getElementById(`${bidder}LogBox`);
                    if (logContent && logBox) {
                        const entry = document.createElement('div');
                        entry.className = 'log-entry host';
                        entry.textContent = message;
                        logContent.appendChild(entry);
                        logBox.scrollTop = logBox.scrollHeight;
                    }
                });
            }
        }
        
        function clearLogs() {
            document.getElementById('hostLogContent').innerHTML = '';
            const container = document.getElementById('bidderLogsContainer');
            container.innerHTML = '';
            bidders = [];
        }
        
        function updateStatus(className, text) {
            const status = document.getElementById('status');
            status.className = 'status ' + className;
            status.textContent = text;
        }
        
        // Auto-connect to log stream on page load
        window.addEventListener('load', function() {
            const logContent = document.getElementById('hostLogContent');
            const logBox = document.getElementById('hostLogBox');
            const entry = document.createElement('div');
            entry.className = 'log-entry host';
            entry.textContent = 'Connected to server. Ready to execute protocol.';
            logContent.appendChild(entry);
        });
    </script>
</body>
</html>"#;

    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}",
        html_content.len(),
        html_content
    );
    
    stream.write_all(response.as_bytes()).unwrap();
}

fn serve_logs(stream: &mut TcpStream, log_buffer: LogBuffer) {
    // Send SSE headers
    let headers = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n";
    stream.write_all(headers.as_bytes()).unwrap();
    
    // Stream logs from buffer
    loop {
        let mut buffer = log_buffer.lock().unwrap();
        if let Some(log) = buffer.pop_front() {
            let message = format!("data: {}\n\n", log);
            if stream.write_all(message.as_bytes()).is_err() {
                break;
            }
            stream.flush().unwrap();
        }
        drop(buffer);
        
        thread::sleep(std::time::Duration::from_millis(100));
    }
}

fn execute_auction(stream: &mut TcpStream, log_buffer: LogBuffer) {
    // Send response immediately
    let response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nAuction protocol execution started";
    stream.write_all(response.as_bytes()).unwrap();
    
    // Execute the auction protocol in a separate thread
    thread::spawn(move || {
        use std::process::{Command, Stdio};
        use std::io::{BufRead, BufReader};
        
        let mut buffer = log_buffer.lock().unwrap();
        buffer.push_back("[WEB-SERVER] ==================================================================================".to_string());
        buffer.push_back("[WEB-SERVER] Starting auction protocol execution as subprocess...".to_string());
        buffer.push_back("[WEB-SERVER] Running: RISC0_DEV_MODE=true cargo run --release".to_string());
        buffer.push_back("[WEB-SERVER] This will execute Example 2 (N-Bidders) with Oscar(10000), Bob(5000), Alice(3000)".to_string());
        buffer.push_back("[WEB-SERVER] ==================================================================================".to_string());
        drop(buffer);
        
        // Execute cargo run as a subprocess to capture ALL stdout/stderr
        // Pass "2" as argument to run example 2 (N-Bidders)
        let mut child = Command::new("cargo")
            .arg("run")
            .arg("--release")
            .arg("--")
            .arg("2")  // Run example 2 (N-Bidders)
            .current_dir("/home/iskander/Projects/zk-auctions-archive")
            .env("RISC0_DEV_MODE", "true")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to start cargo run");
        
        // Capture stdout in a separate thread
        let stdout = child.stdout.take().expect("Failed to capture stdout");
        let log_buffer_clone = Arc::clone(&log_buffer);
        let stdout_thread = thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                if let Ok(line) = line {
                    let timestamp = Local::now().format("[%Y-%m-%d %H:%M:%S]");
                    let mut buffer = log_buffer_clone.lock().unwrap();
                    buffer.push_back(format!("{} {}", timestamp, line));
                }
            }
        });
        
        // Capture stderr in a separate thread
        let stderr = child.stderr.take().expect("Failed to capture stderr");
        let log_buffer_clone = Arc::clone(&log_buffer);
        let stderr_thread = thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines() {
                if let Ok(line) = line {
                    // Skip compilation output and warnings
                    if line.contains("Compiling") 
                        || line.contains("warning:") 
                        || line.contains("-->") 
                        || line.contains("|")
                        || line.contains("help:")
                        || line.contains("= note:")
                        || line.contains("Finished")
                        || line.contains("Running `target")
                        || line.trim().is_empty()
                    {
                        continue;
                    }
                    
                    let timestamp = Local::now().format("[%Y-%m-%d %H:%M:%S]");
                    let mut buffer = log_buffer_clone.lock().unwrap();
                    buffer.push_back(format!("{} {}", timestamp, line));
                }
            }
        });
        
        // Wait for the process to complete
        let status = child.wait().expect("Failed to wait for child process");
        
        // Wait for output threads to finish
        stdout_thread.join().unwrap();
        stderr_thread.join().unwrap();
        
        let mut buffer = log_buffer.lock().unwrap();
        buffer.push_back("[WEB-SERVER] ==================================================================================".to_string());
        buffer.push_back(format!("[WEB-SERVER] Protocol execution completed with status: {:?}", status));
        buffer.push_back("[WEB-SERVER] ==================================================================================".to_string());
    });
}

