# Process Manager HTTP Server

A lightweight HTTP server written in Go that manages external processes through HTTP endpoints. This server enables you to define commands and arguments in a JSON configuration file and expose them as HTTP endpoints, allowing you to trigger processes via simple HTTP requests.

## Features

- **HTTP-based Process Execution**: Trigger processes through HTTP endpoints
- **Dynamic Endpoint Configuration**: Configure services through a JSON file
- **Process Management**: Only one process runs at a time, with automatic replacement
- **Process Output Capture**: View process logs through dedicated HTTP endpoints
- **Automatic Process Cleanup**: Kill inactive processes after a configurable timeout
- **Graceful Shutdown**: Clean termination of managed processes on server shutdown

## Installation

1. Clone this repository
2. Ensure Go is installed on your system
3. Run directly or build:

```bash
# Run directly
go run main.go

# Or build and run
go build
./publish  # Name will match your go.mod module name
```

## Configuration

### Command Line Flags

The server accepts the following command line flags:

- `-addr`: Address and port to listen on (default: `:8080`)
- `-timeout`: Inactivity timeout before stopping processes (default: `30m`)
- `-check`: Interval for checking process inactivity (default: `60s`)
- `-config`: Path to services configuration file (default: `services.json`)
- `-log`: Directory to save log files (default: `log`)
- `-buffer`: Maximum output buffer size in bytes (default: `1048576` - 1MB)

Example:

```bash
./publish -addr=:9090 -timeout=10m -check=30s -config=custom-services.json
```

### Service Configuration

Services are defined in a JSON file (default: `services.json`) with the following structure:

```json
[
  {
    "path": "/endpoint-path",
    "command": "executable-name",
    "args": ["arg1", "arg2"]
  }
]
```

Example configuration:

```json
[
  {
    "path": "/echo",
    "command": "echo",
    "args": ["'Hello, World!'"]
  },
  {
    "path": "/echos",
    "command": "bash",
    "args": ["./tests/echos.sh"]
  }
]
```

## Usage

### Starting a Process

Make an HTTP GET request to the configured endpoint:

```bash
curl http://localhost:8080/echo
```

This will:

1. Start the configured process if not already running
2. Return a success message with PID and log path information
3. If a different process is already running, it will be terminated first

### Viewing Process Logs

Each endpoint has a corresponding logs endpoint:

```bash
curl http://localhost:8080/echo/logs
```

This returns the current stdout/stderr output from the running process.

### Default Page

Access the root path (`/`) to see available service endpoints:

```bash
curl http://localhost:8080/
```

## Process Lifecycle

1. **Starting**: When a request is made to a service endpoint
2. **Running**: Process runs until completion or forced termination
3. **Termination**: Processes are terminated:
   - When a new process is requested
   - After being inactive for the configured timeout (default: 30 minutes)
   - When the server receives a shutdown signal (SIGTERM/SIGINT)

## Log Files

Process output logs are saved to the configured log directory (default: `./log`) when processes exit, with filenames based on timestamps and process IDs.

## Development

The server is designed with concurrency in mind and uses mutexes to safely manage process state. Key components:

- **HTTP Server**: Handles incoming requests and routes to appropriate handlers
- **Process Manager**: Starts, monitors, and terminates processes
- **Buffer Management**: Captures and limits process output
- **Inactivity Monitor**: Background goroutine checks for inactive processes

## License

I do not care.
