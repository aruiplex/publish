# Publish: Process Manager Server

This is a simple HTTP-based process manager server written in Go that allows you to define and trigger command-line processes via HTTP endpoints.

## Overview

The server reads service configurations from a JSON file and creates HTTP endpoints for each configured service. When a request is made to a service endpoint, the server executes the corresponding command, terminates inactive processes after a timeout, and handles graceful shutdowns.

## Features

- **Dynamic Endpoint Configuration**: Services are defined in a JSON configuration file
- **Process Lifecycle Management**: Automatically starts and stops processes on request
- **Inactivity Timeout**: Kills processes after a defined period of inactivity
- **Graceful Shutdown**: Handles termination signals by cleaning up processes
- **Process Output Capture**: Captures stdout/stderr of child processes

## Configuration

Services are defined in `services.json` with the following structure:

```json
[
  {
    "path": "/endpoint-path",
    "command": "executable-name",
    "args": ["arg1", "arg2"]
  }
]
```

### Example Configuration

The default configuration includes an echo service:

```json
[
  {
    "path": "/echo",
    "command": "echo",
    "args": ["'Hello, World!'"]
  }
]
```

## Usage

### Starting the Server

```bash
go run main.go
```

The server listens on port 8080 by default.

### Making Requests

To trigger a service, make an HTTP request to its path:

```bash
curl http://localhost:8080/echo
```

This will execute the command defined for the `/echo` endpoint.

## Technical Details

- **Inactivity Timeout**: Processes are killed after 5 minutes of inactivity
- **Check Interval**: Inactivity is checked every 30 seconds
- **Configuration File**: Services are loaded from `services.json`

## Development

To modify server behavior, you can update these constants in [main.go](main.go):

- `listenAddr`: HTTP server address (default: `:8080`)
- `inactivityTimeout`: Duration before killing inactive processes
- `checkInterval`: How often to check for inactivity
- `configFile`: Name of the configuration file
