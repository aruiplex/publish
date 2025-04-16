package main

import (
	"encoding/json" // Added for JSON handling
	"errors"        // Added for custom errors
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal" // Added for path validation
	"strings"   // Added for path validation
	"sync"
	"syscall"
	"time"
)

// Configuration
const (
	listenAddr        = ":8080"          // Address the HTTP server listens on
	inactivityTimeout = 5 * time.Minute  // Kill process after this duration of inactivity
	checkInterval     = 30 * time.Second // How often to check for inactivity
	configFile        = "services.json"  // Name of the configuration file
)

// Structure to hold info about the managed process
type managedProcess struct {
	cmd       *exec.Cmd   // The command object
	process   *os.Process // The running process object
	startTime time.Time
	command   string   // Command string (e.g., "python")
	args      []string // Arguments (e.g., ["main.py"])
}

// Configuration for each service, loaded from JSON
// Added json tags for unmarshalling
type serviceConfig struct {
	Path    string   `json:"path"`    // e.g., "/service_A"
	Command string   `json:"command"` // e.g., "python"
	Args    []string `json:"args"`    // e.g., ["main.py", "--port=8001"]
}

// Global state
var (
	mu               sync.Mutex      // Mutex to protect shared state
	currentProcess   *managedProcess // Pointer to the currently running process info
	lastActivityTime time.Time       // Timestamp of the last relevant request
	// serviceRegistry map[string]serviceConfig // REMOVED - Will load from file
)

func main() {
	log.Printf("Starting process manager server on %s", listenAddr)

	// --- Load and Validate Configuration ---
	serviceConfigs, err := loadAndValidateConfig(configFile)
	if err != nil {
		log.Fatalf("Failed to load or validate configuration from %s: %v", configFile, err)
	}
	if len(serviceConfigs) == 0 {
		log.Fatalf("No valid service configurations found in %s. Exiting.", configFile)
	}
	log.Printf("Successfully loaded %d service configurations from %s", len(serviceConfigs), configFile)
	// --- End Configuration Loading ---

	// Register HTTP handlers dynamically based on loaded config
	for _, config := range serviceConfigs {
		// Capture loop variables correctly for the closure
		// Need to capture by value because 'config' changes in each iteration
		serviceConf := config
		http.HandleFunc(serviceConf.Path, func(w http.ResponseWriter, r *http.Request) {
			handleServiceRequest(w, r, serviceConf) // Pass the captured config
		})
		log.Printf("Registered handler for path: %s -> Command: %s %v", serviceConf.Path, serviceConf.Command, serviceConf.Args)
	}

	// Default handler for root or unknown paths
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Received request on unmanaged path: %s", r.URL.Path)
		// Optionally list available service paths
		fmt.Fprintf(w, "Unknown path. Available service paths:\n")
		mu.Lock() // Need lock if accessing shared config, though here we use the initially loaded one
		for _, cfg := range serviceConfigs {
			fmt.Fprintf(w, "- %s\n", cfg.Path)
		}
		mu.Unlock()                        // Unlock if lock was used
		w.WriteHeader(http.StatusNotFound) // Set status after writing body
	})

	// Start the background inactivity monitor
	go monitorInactivity()

	// Graceful shutdown handling
	setupGracefulShutdown()

	// Start the HTTP server
	log.Fatal(http.ListenAndServe(listenAddr, nil))
}

// loadAndValidateConfig reads, parses, and validates the service configuration file
func loadAndValidateConfig(filePath string) ([]serviceConfig, error) {
	log.Printf("Loading configuration from %s...", filePath)
	// Read the file content
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("could not read config file '%s': %w", filePath, err)
	}

	// Check if file is empty
	if len(data) == 0 {
		return nil, errors.New("config file is empty")
	}

	// Parse the JSON data
	var configs []serviceConfig
	err = json.Unmarshal(data, &configs)
	if err != nil {
		return nil, fmt.Errorf("could not parse JSON config file '%s': %w", filePath, err)
	}

	// Validate the loaded configurations
	validatedConfigs := make([]serviceConfig, 0, len(configs))
	seenPaths := make(map[string]bool)

	for i, cfg := range configs {
		// Trim whitespace for cleaner checks
		cfg.Path = strings.TrimSpace(cfg.Path)
		cfg.Command = strings.TrimSpace(cfg.Command)

		// Basic validation
		if cfg.Path == "" {
			log.Printf("Validation Error: Service config #%d: 'path' cannot be empty. Skipping.", i+1)
			continue // Skip this entry
		}
		if !strings.HasPrefix(cfg.Path, "/") {
			log.Printf("Validation Error: Service config #%d (Path: '%s'): 'path' must start with '/'. Skipping.", i+1, cfg.Path)
			continue // Skip this entry
		}
		if cfg.Command == "" {
			log.Printf("Validation Error: Service config #%d (Path: '%s'): 'command' cannot be empty. Skipping.", i+1, cfg.Path)
			continue // Skip this entry
		}

		// Check for duplicate paths
		if seenPaths[cfg.Path] {
			log.Printf("Validation Error: Service config #%d: Duplicate 'path' found: '%s'. Skipping.", i+1, cfg.Path)
			continue // Skip this entry
		}

		// Ensure args is not nil (it's okay if it's empty)
		if cfg.Args == nil {
			cfg.Args = []string{} // Initialize to empty slice if null in JSON
		}

		// If all checks pass, add to validated list and mark path as seen
		seenPaths[cfg.Path] = true
		validatedConfigs = append(validatedConfigs, cfg)
		log.Printf("Validated config for Path: %s", cfg.Path)
	}

	if len(validatedConfigs) == 0 && len(configs) > 0 {
		return nil, errors.New("no valid service configurations found after validation")
	}

	return validatedConfigs, nil
}

// handleServiceRequest handles incoming HTTP requests for managed services
// (No changes needed in the function signature or core logic, it already receives serviceConfig)
func handleServiceRequest(w http.ResponseWriter, r *http.Request, config serviceConfig) {
	mu.Lock()
	defer mu.Unlock()

	log.Printf("Received request for %s", config.Path)

	// Update activity time regardless of process state
	lastActivityTime = time.Now()

	// Check if the correct process is already running
	if currentProcess != nil && currentProcess.command == config.Command && compareStringSlices(currentProcess.args, config.Args) {
		log.Printf("Process for %s (%s %v) is already running (PID: %d). Updated activity time.",
			config.Path, config.Command, config.Args, currentProcess.process.Pid)
		fmt.Fprintf(w, "Service %s already running (PID: %d). Activity time updated.\n", config.Path, currentProcess.process.Pid)
		return
	}

	// If a *different* process is running, stop it first
	if currentProcess != nil {
		log.Printf("Different process (%s %v, PID: %d) is running. Stopping it before starting %s.",
			currentProcess.command, currentProcess.args, currentProcess.process.Pid, config.Path)
		killCurrentProcessLocked("stopping due to new service request") // Use locked version
		// Allow some time for the old process to potentially clean up - adjust as needed
		time.Sleep(500 * time.Millisecond)
	}

	// Start the new process
	log.Printf("Starting process for %s: %s %v", config.Path, config.Command, config.Args)
	cmd := exec.Command(config.Command, config.Args...)

	// Optional: Capture stdout/stderr of the child process
	cmd.Stdout = os.Stdout // Pipe to manager's stdout
	cmd.Stderr = os.Stderr // Pipe to manager's stderr

	err := cmd.Start()
	if err != nil {
		log.Printf("Error starting process for %s: %v", config.Path, err)
		http.Error(w, fmt.Sprintf("Failed to start service %s", config.Path), http.StatusInternalServerError)
		return
	}

	// Store process info
	currentProcess = &managedProcess{
		cmd:       cmd,
		process:   cmd.Process,
		startTime: time.Now(),
		command:   config.Command,
		args:      config.Args,
	}
	lastActivityTime = time.Now() // Ensure activity time is set upon start

	log.Printf("Successfully started process for %s (PID: %d)", config.Path, currentProcess.process.Pid)

	// Respond to the client
	fmt.Fprintf(w, "Service %s started successfully (PID: %d).\n", config.Path, currentProcess.process.Pid)

	// Optional: Wait for the process in a separate goroutine to log when it exits on its own
	go func(p *managedProcess) {
		waitErr := p.cmd.Wait()
		mu.Lock()
		defer mu.Unlock()
		// Check if this is still the 'current' process before logging/clearing
		if currentProcess != nil && currentProcess.process != nil && p.process != nil && currentProcess.process.Pid == p.process.Pid {
			log.Printf("Process %s %v (PID: %d) exited on its own. Exit status: %v", p.command, p.args, p.process.Pid, waitErr)
			currentProcess = nil // Clear the state as it's no longer managed/running
		} else if p.process != nil {
			log.Printf("An old process %s %v (PID: %d) finished after being replaced or stopped.", p.command, p.args, p.process.Pid)
		} else {
			log.Printf("An old process %s %v (PID: unknown) finished after being replaced or stopped.", p.command, p.args)
		}
	}(currentProcess) // Pass the current process info to the goroutine
}

// monitorInactivity periodically checks if the process should be killed due to inactivity
// (No changes needed)
func monitorInactivity() {
	ticker := time.NewTicker(checkInterval)
	defer ticker.Stop()

	log.Printf("Inactivity monitor started. Checking every %s for inactivity longer than %s.", checkInterval, inactivityTimeout)

	for range ticker.C {
		mu.Lock()
		if currentProcess != nil && currentProcess.process != nil { // Added check for nil process
			inactiveDuration := time.Since(lastActivityTime)
			// log.Printf("Debug: Checking inactivity. Current PID: %d. Last activity: %s ago.", currentProcess.process.Pid, inactiveDuration) // Verbose Debug Line
			if inactiveDuration >= inactivityTimeout {
				log.Printf("Process %s %v (PID: %d) inactive for %s (limit: %s). Killing...",
					currentProcess.command, currentProcess.args, currentProcess.process.Pid, inactiveDuration, inactivityTimeout)
				killCurrentProcessLocked("inactivity timeout")
			}
		}
		mu.Unlock()
	}
}

// killCurrentProcessLocked kills the currently managed process. Assumes mutex is held.
// (Minor refinement to log description)
func killCurrentProcessLocked(reason string) {
	if currentProcess == nil || currentProcess.process == nil {
		log.Println("Attempted to kill process, but none is registered or process info is incomplete.")
		currentProcess = nil // Ensure state is cleared if partially invalid
		return
	}

	pid := currentProcess.process.Pid
	commandDesc := fmt.Sprintf("'%s %v' (PID: %d)", currentProcess.command, currentProcess.args, pid) // Slightly clearer desc
	log.Printf("Attempting to kill process %s. Reason: %s", commandDesc, reason)

	// Try graceful termination first (SIGTERM)
	err := currentProcess.process.Signal(syscall.SIGTERM)
	if err != nil {
		// Log differently if the process likely already exited
		if errors.Is(err, os.ErrProcessDone) {
			log.Printf("Process %s already exited before SIGTERM could be sent.", commandDesc)
		} else {
			log.Printf("Failed to send SIGTERM to process %s: %v. Attempting SIGKILL.", commandDesc, err)
			// If SIGTERM fails or isn't supported, force kill (SIGKILL)
			err = currentProcess.process.Kill()
			if err != nil && !errors.Is(err, os.ErrProcessDone) { // Don't log error again if already done
				log.Printf("Failed to send SIGKILL to process %s: %v", commandDesc, err)
			} else if err == nil {
				log.Printf("Sent SIGKILL to process %s.", commandDesc)
			}
		}
	} else {
		log.Printf("Sent SIGTERM to process %s.", commandDesc)
		// Note: cmd.Wait() is handled in the goroutine started in handleServiceRequest
	}

	// We clear currentProcess here because we initiated the kill.
	// The cmd.Wait() goroutine might log its exit later, which is fine.
	currentProcess = nil
	log.Printf("Cleared process state for former PID %d after attempting kill.", pid)
}

// setupGracefulShutdown handles Ctrl+C (SIGINT) and termination signals
// (No changes needed)
func setupGracefulShutdown() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		sig := <-c
		log.Printf("Received signal: %v. Shutting down...", sig)

		mu.Lock()
		if currentProcess != nil {
			pid := -1
			if currentProcess.process != nil {
				pid = currentProcess.process.Pid
			}
			log.Printf("Attempting to stop managed process (PID: %d) before exiting...", pid)
			killCurrentProcessLocked("shutdown signal received")
		}
		mu.Unlock()

		// Add any other cleanup logic here

		log.Println("Exiting application.")
		os.Exit(0) // Exit the main application
	}()
}

// Helper function to compare string slices
// (No changes needed)
func compareStringSlices(a, b []string) bool {
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
