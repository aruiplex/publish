package main

import (
	"bytes" // Added for capturing output
	"encoding/json"
	"errors"
	"fmt" // Added for MultiWriter (optional, but good practice)
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"

	// "path/filepath" // No longer strictly needed for validation shown
	"strings"
	"sync"
	"syscall"
	"time"
)

// Configuration
const (
	listenAddr        = ":8080"
	inactivityTimeout = 30 * time.Minute
	checkInterval     = 60 * time.Second
	configFile        = "services.json"
	// Max buffer size (e.g., 1MB) to prevent excessive memory usage. Adjust as needed.
	maxBufferSize = 1 * 1024 * 1024
)

// Structure to hold info about the managed process
type managedProcess struct {
	cmd          *exec.Cmd   // The command object
	process      *os.Process // The running process object
	startTime    time.Time
	command      string        // Command string (e.g., "python")
	args         []string      // Arguments (e.g., ["main.py"])
	outputBuffer *bytes.Buffer // Buffer to capture stdout/stderr
	bufferMutex  sync.Mutex    // Mutex specifically for the buffer (added for finer control)
}

// Configuration for each service, loaded from JSON
type serviceConfig struct {
	Path    string   `json:"path"`
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

// Global state
var (
	// Mutex for currentProcess pointer and lastActivityTime ONLY
	globalMutex      sync.Mutex
	currentProcess   *managedProcess // Pointer to the currently running process info
	lastActivityTime time.Time       // Timestamp of the last relevant request
)

// --- Main Function ---
func main() {
	log.Printf("Starting process manager server on %s", listenAddr)

	// Load and Validate Configuration
	serviceConfigs, err := loadAndValidateConfig(configFile)
	if err != nil {
		log.Fatalf("Failed to load or validate configuration from %s: %v", configFile, err)
	}
	if len(serviceConfigs) == 0 {
		log.Fatalf("No valid service configurations found in %s. Exiting.", configFile)
	}
	log.Printf("Successfully loaded %d service configurations from %s", len(serviceConfigs), configFile)

	// Register HTTP handlers dynamically
	registeredPaths := make(map[string]bool) // Keep track to avoid conflicts
	for _, config := range serviceConfigs {
		serviceConf := config // Capture loop variable

		// --- Register Handler for Starting the Service ---
		startPath := serviceConf.Path
		if registeredPaths[startPath] {
			log.Printf("Warning: Path %s already registered, skipping duplicate start handler registration.", startPath)
			continue
		}
		http.HandleFunc(startPath, func(w http.ResponseWriter, r *http.Request) {
			// Ensure we only handle the exact path, not subpaths like /service_A/logs
			if r.URL.Path != startPath {
				http.NotFound(w, r)
				return
			}
			handleServiceRequest(w, r, serviceConf)
		})
		registeredPaths[startPath] = true
		log.Printf("Registered START handler for path: %s -> Command: %s %v", startPath, serviceConf.Command, serviceConf.Args)

		// --- Register Handler for Viewing Logs ---
		logPath := serviceConf.Path + "/logs"
		if registeredPaths[logPath] {
			log.Printf("Warning: Path %s already registered, skipping duplicate log handler registration.", logPath)
			continue // Should ideally not happen if start path wasn't duplicate
		}
		http.HandleFunc(logPath, func(w http.ResponseWriter, r *http.Request) {
			handleLogRequest(w, r, serviceConf) // Pass the specific config
		})
		registeredPaths[logPath] = true
		log.Printf("Registered LOGS handler for path: %s", logPath)
	}

	// Default handler for root or other unknown paths
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Check if it's a registered path being handled by a more specific handler
		// This check might be redundant depending on ServeMux behavior but adds clarity
		if registeredPaths[r.URL.Path] {
			// Let the more specific handler take care of it (or NotFound if it's a base path request to a logs path etc.)
			// This might result in double logging for NotFound cases handled by specific handlers.
			// A better approach might involve using a router library.
			return
		}

		log.Printf("Received request on unmanaged path: %s", r.URL.Path)
		fmt.Fprintf(w, "Unknown path.\n\nAvailable service paths:\n")
		// No lock needed here as serviceConfigs is read-only after startup
		for _, cfg := range serviceConfigs {
			fmt.Fprintf(w, "- %s (start service)\n", cfg.Path)
			fmt.Fprintf(w, "- %s/logs (view logs)\n", cfg.Path)
		}
		w.WriteHeader(http.StatusNotFound)
	})

	// Start the background inactivity monitor
	go monitorInactivity()

	// Graceful shutdown handling
	setupGracefulShutdown()

	// Start the HTTP server
	log.Fatal(http.ListenAndServe(listenAddr, nil))
}

// --- Configuration Loading ---
func loadAndValidateConfig(filePath string) ([]serviceConfig, error) {
	// (Same as previous version - no changes needed here)
	log.Printf("Loading configuration from %s...", filePath)
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("could not read config file '%s': %w", filePath, err)
	}
	if len(data) == 0 {
		return nil, errors.New("config file is empty")
	}

	var configs []serviceConfig
	err = json.Unmarshal(data, &configs)
	if err != nil {
		return nil, fmt.Errorf("could not parse JSON config file '%s': %w", filePath, err)
	}

	validatedConfigs := make([]serviceConfig, 0, len(configs))
	seenPaths := make(map[string]bool)

	for i, cfg := range configs {
		cfg.Path = strings.TrimSpace(cfg.Path)
		cfg.Command = strings.TrimSpace(cfg.Command)

		if cfg.Path == "" || !strings.HasPrefix(cfg.Path, "/") || cfg.Command == "" {
			log.Printf("Validation Error: Service config #%d has invalid path ('%s') or command ('%s'). Skipping.", i+1, cfg.Path, cfg.Command)
			continue
		}
		if seenPaths[cfg.Path] || seenPaths[cfg.Path+"/logs"] { // Check potential conflicts
			log.Printf("Validation Error: Service config #%d (Path: '%s') conflicts with another path or log path. Skipping.", i+1, cfg.Path)
			continue
		}
		if cfg.Args == nil {
			cfg.Args = []string{}
		}

		seenPaths[cfg.Path] = true
		seenPaths[cfg.Path+"/logs"] = true // Reserve the log path too
		validatedConfigs = append(validatedConfigs, cfg)
		log.Printf("Validated config for Path: %s", cfg.Path)
	}

	if len(validatedConfigs) == 0 && len(configs) > 0 {
		return nil, errors.New("no valid service configurations found after validation")
	}
	return validatedConfigs, nil
}

// --- Service Request Handler ---
func handleServiceRequest(w http.ResponseWriter, r *http.Request, config serviceConfig) {
	globalMutex.Lock() // Lock global state (currentProcess, lastActivityTime)

	log.Printf("Received service start request for %s", config.Path)
	lastActivityTime = time.Now() // Update activity time

	// Check if the correct process is already running
	if currentProcess != nil && currentProcess.command == config.Command && compareStringSlices(currentProcess.args, config.Args) {
		pid := -1
		if currentProcess.process != nil {
			pid = currentProcess.process.Pid
		}
		log.Printf("Process for %s (%s %v) is already running (PID: %d). Updated activity time.",
			config.Path, config.Command, config.Args, pid)
		globalMutex.Unlock() // Unlock before writing response
		fmt.Fprintf(w, "Service %s already running (PID: %d). Activity time updated.\nView logs at %s/logs\n", config.Path, pid, config.Path)
		return
	}

	// If a *different* process is running, stop it first
	if currentProcess != nil {
		log.Printf("Different process (%s %v, PID: %d) is running. Stopping it before starting %s.",
			currentProcess.command, currentProcess.args, currentProcess.process.Pid, config.Path)
		// killCurrentProcessLocked requires globalMutex to be held, which it is.
		killCurrentProcessLocked("stopping due to new service request")
		// Allow some time? Note: killCurrentProcessLocked clears currentProcess
		// time.Sleep(500 * time.Millisecond) // Optional delay
	}

	// Start the new process
	log.Printf("Starting process for %s: %s %v", config.Path, config.Command, config.Args)
	cmd := exec.Command(config.Command, config.Args...)

	// --- Capture Output ---
	// Create a buffer with a capacity limit
	outputBuf := &bytes.Buffer{}
	// Use a custom writer to limit buffer size (optional but recommended)
	limitedWriter := &limitedBufferWriter{buf: outputBuf, maxSize: maxBufferSize}

	// Redirect both stdout and stderr to the buffer
	// Optionally, use io.MultiWriter if you ALSO want output on the manager's console:
	cmd.Stdout = io.MultiWriter(limitedWriter, os.Stdout)
	cmd.Stderr = io.MultiWriter(limitedWriter, os.Stderr)
	cmd.Stdout = limitedWriter
	cmd.Stderr = limitedWriter
	// --- End Output Capture Setup ---

	err := cmd.Start()
	if err != nil {
		log.Printf("Error starting process for %s: %v", config.Path, err)
		globalMutex.Unlock() // Unlock before writing error response
		http.Error(w, fmt.Sprintf("Failed to start service %s", config.Path), http.StatusInternalServerError)
		return
	}

	// Store process info (including the buffer)
	newProc := &managedProcess{
		cmd:          cmd,
		process:      cmd.Process,
		startTime:    time.Now(),
		command:      config.Command,
		args:         config.Args,
		outputBuffer: outputBuf, // Store the buffer
		// bufferMutex is initialized implicitly (zero value is unlocked mutex)
	}
	currentProcess = newProc      // Update global pointer
	lastActivityTime = time.Now() // Reset activity time again

	pid := -1
	if newProc.process != nil {
		pid = newProc.process.Pid
	}
	log.Printf("Successfully started process for %s (PID: %d)", config.Path, pid)
	globalMutex.Unlock() // Unlock global state

	// Respond to the client
	fmt.Fprintf(w, "Service %s started successfully (PID: %d).\nView logs at %s/logs\n", config.Path, pid, config.Path)

	// Goroutine to wait for the process exit (handles buffer access carefully)
	go func(p *managedProcess) {
		waitErr := p.cmd.Wait() // This blocks until the process exits

		globalMutex.Lock() // Lock global state to safely check/clear currentProcess
		procIsStillCurrent := currentProcess != nil && p.process != nil && currentProcess.process != nil && currentProcess.process.Pid == p.process.Pid
		pid := -1
		if p.process != nil {
			pid = p.process.Pid
		}

		if procIsStillCurrent {
			log.Printf("Process %s %v (PID: %d) exited on its own. Exit status: %v", p.command, p.args, pid, waitErr)
			// Clear global reference ONLY if it's the current one exiting naturally
			currentProcess = nil
		} else {
			log.Printf("An old process %s %v (PID: %d) finished after being replaced or stopped. Exit status: %v", p.command, p.args, pid, waitErr)
			// Don't clear currentProcess here, it was likely cleared by kill or replaced
		}
		globalMutex.Unlock() // Unlock global state

		// Final log entry from the buffer (optional)
		// p.bufferMutex.Lock()
		// finalBytes := p.outputBuffer.Bytes() // Get remaining bytes
		// if len(finalBytes) > 0 {
		// 	log.Printf("Final captured output for exited process PID %d (%s %v):\n---\n%s\n---", pid, p.command, p.args, string(finalBytes))
		// }
		// p.bufferMutex.Unlock()

	}(newProc) // Pass the new process info

}

// --- Log Request Handler ---
func handleLogRequest(w http.ResponseWriter, r *http.Request, config serviceConfig) {
	log.Printf("Received log request for service path %s", config.Path)

	globalMutex.Lock()     // Lock global state to safely access currentProcess
	proc := currentProcess // Get a local reference while holding the lock
	globalMutex.Unlock()   // Unlock global state - we have our reference (or nil)

	if proc == nil {
		log.Printf("Log request for %s: No process is currently running.", config.Path)
		http.Error(w, "No service process is currently running.", http.StatusNotFound)
		return
	}

	// Check if the running process matches the requested config path
	// (Comparing command/args provides stronger matching than just path)
	if !(proc.command == config.Command && compareStringSlices(proc.args, config.Args)) {
		log.Printf("Log request for %s: A different process (%s %v) is running.", config.Path, proc.command, proc.args)
		http.Error(w, fmt.Sprintf("Service associated with %s is not the currently running process.", config.Path), http.StatusConflict) // 409 Conflict might be suitable
		return
	}

	// Access the buffer safely using its dedicated mutex
	proc.bufferMutex.Lock()
	outputBytes := proc.outputBuffer.Bytes() // Read the buffer content
	proc.bufferMutex.Unlock()

	pid := -1
	if proc.process != nil {
		pid = proc.process.Pid
	}
	log.Printf("Serving logs for %s (PID: %d), buffer size: %d bytes", config.Path, pid, len(outputBytes))

	// Serve the logs
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, err := w.Write(outputBytes)
	if err != nil {
		log.Printf("Error writing log response for %s: %v", config.Path, err)
	}
}

// --- Inactivity Monitor ---
func monitorInactivity() {
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()
	log.Printf("Inactivity monitor started. Checking every %s for inactivity longer than %s.", checkInterval, inactivityTimeout)

	for range ticker.C {
		globalMutex.Lock() // Lock global state
		if currentProcess != nil {
			inactiveDuration := time.Since(lastActivityTime)
			if inactiveDuration >= inactivityTimeout {
				pid := -1
				if currentProcess.process != nil {
					pid = currentProcess.process.Pid
				}
				log.Printf("Process %s %v (PID: %d) inactive for %s (limit: %s). Killing...",
					currentProcess.command, currentProcess.args, pid, inactiveDuration, inactivityTimeout)
				// killCurrentProcessLocked requires globalMutex to be held
				killCurrentProcessLocked("inactivity timeout")
			}
		}
		globalMutex.Unlock() // Unlock global state
	}
}

// --- Process Killing Logic ---
// killCurrentProcessLocked kills the currently managed process. Assumes globalMutex is held.
func killCurrentProcessLocked(reason string) {
	if currentProcess == nil {
		log.Println("Attempted to kill process, but none is registered.")
		return
	}

	procToKill := currentProcess // Local reference
	currentProcess = nil         // Clear global reference immediately while holding lock

	pid := -1
	if procToKill.process != nil {
		pid = procToKill.process.Pid
	}
	commandDesc := fmt.Sprintf("'%s %v' (PID: %d)", procToKill.command, procToKill.args, pid)
	log.Printf("Attempting to kill process %s. Reason: %s", commandDesc, reason)

	// Check if process is valid before trying to signal
	if procToKill.process == nil {
		log.Printf("Cannot kill process %s: process object is nil (already exited or failed to start?).", commandDesc)
		return // Nothing more to do with this process object
	}

	// Try graceful termination first (SIGTERM)
	err := procToKill.process.Signal(syscall.SIGTERM)
	// We ignore ErrProcessDone here because the Wait goroutine will handle logging final state
	if err != nil && !errors.Is(err, os.ErrProcessDone) {
		log.Printf("Failed to send SIGTERM to process %s: %v. Attempting SIGKILL.", commandDesc, err)
		// If SIGTERM fails, force kill (SIGKILL)
		err = procToKill.process.Kill()
		if err != nil && !errors.Is(err, os.ErrProcessDone) {
			log.Printf("Failed to send SIGKILL to process %s: %v", commandDesc, err)
		} else if err == nil {
			log.Printf("Sent SIGKILL to process %s.", commandDesc)
		}
	} else if err == nil {
		log.Printf("Sent SIGTERM to process %s.", commandDesc)
	}

	log.Printf("Cleared process state reference for former PID %d after initiating kill.", pid)
	// The Wait goroutine associated with procToKill will eventually finish and log final output/status.
}

// --- Graceful Shutdown ---
func setupGracefulShutdown() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		sig := <-c
		log.Printf("Received signal: %v. Shutting down...", sig)

		globalMutex.Lock() // Lock global state
		if currentProcess != nil {
			pid := -1
			if currentProcess.process != nil {
				pid = currentProcess.process.Pid
			}
			log.Printf("Attempting to stop managed process (PID: %d) before exiting...", pid)
			// killCurrentProcessLocked requires globalMutex to be held
			killCurrentProcessLocked("shutdown signal received")
		}
		globalMutex.Unlock() // Unlock global state

		log.Println("Waiting briefly for cleanup...")
		time.Sleep(500 * time.Millisecond) // Give Wait goroutine a chance?

		log.Println("Exiting application.")
		os.Exit(0)
	}()
}

// --- Helper Functions ---

// Helper function to compare string slices
func compareStringSlices(a, b []string) bool {
	// (Same as before)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// limitedBufferWriter wraps bytes.Buffer to limit its size.
type limitedBufferWriter struct {
	buf     *bytes.Buffer
	maxSize int
	mu      sync.Mutex // Use the mutex from the managedProcess struct
}

// Write implements io.Writer, ensuring the buffer doesn't exceed maxSize.
func (w *limitedBufferWriter) Write(p []byte) (n int, err error) {
	// NOTE: This buffer writer assumes it shares the mutex
	// from the containing managedProcess struct. We don't lock here
	// directly, but expect the caller (cmd.Stdout/Stderr redirection)
	// or reader (handleLogRequest) to manage the lock.
	// A more robust implementation might embed the mutex here, but
	// it complicates access patterns slightly. Let's rely on external locking.

	// Calculate available space
	available := w.maxSize - w.buf.Len()
	if available <= 0 {
		// Buffer is full, potentially discard oldest data or just stop writing
		// Simple approach: stop writing new data
		// log.Printf("Warning: Output buffer full (%d bytes). Discarding new output.", w.maxSize) // Can be noisy
		return len(p), nil // Pretend we wrote it all, but discard
		// TODO: Implement a ring buffer logic here if needed to keep recent logs
	}

	// Decide how much to write
	writeLen := len(p)
	if writeLen > available {
		writeLen = available // Only write what fits
	}

	n, err = w.buf.Write(p[:writeLen]) // Write the allowed part

	// If we wrote less than requested because buffer filled up exactly
	if n < len(p) && err == nil {
		// log.Printf("Warning: Output buffer full (%d bytes) after partial write. Discarding remaining output.", w.maxSize) // Noisy
		// We still return len(p) to satisfy the write contract, even though some was discarded
		return len(p), nil
	}

	return n, err
}

// --- End Helper Functions ---
