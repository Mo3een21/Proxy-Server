**Creator:** Moeen Abu Katish  
**ID:** 212307128  

## Introduction

This project is a simple proxy server implementation in C, capable of handling HTTP requests. It forwards the requests to the target server, receives the responses, and sends them back to the client. The proxy server utilizes a thread pool to manage concurrent connections efficiently. This README provides an overview of the features, usage, and design of the proxy server implementation.

## Functionality Overview

### `extract_first_line(const char *request, char *first_line)`

- Extracts the first line from the HTTP request.
- Ensures proper termination of the first line.
- Handles potential buffer overflow scenarios.

### `check_host_header(const char *request)`

- Checks if the Host header is present in the HTTP request.
- Verifies the validity of the Host header value.
- Returns 1 if the Host header is valid; otherwise, returns 0.

### `check_request_line(char *request)`

- Validates the format of the request line.
- Checks if the request line contains exactly three parts (method, path, and protocol).
- Returns 1 if the request line is valid; otherwise, returns 0.

### `check_filter(const char *url, FILE *file)`

- Checks if the requested URL is forbidden based on a filter file.
- Handles various URL formats, including IP addresses and hostnames.
- Returns 1 if the URL is forbidden; otherwise, returns 0.

### `construct_error_response(char *response, const char *error_code, const char *error_message, const char *additional_message)`

- Constructs an error response in the HTTP format.
- Populates the response with the appropriate status code, message, and additional details.
- Handles potential errors in time formatting.

### `handle_response(void* arg)`

- Handles incoming HTTP requests from clients.
- Parses the request, validates headers, and constructs proper responses.
- Forwards valid requests to the target server and relays responses back to clients.
- Handles error scenarios gracefully and sends appropriate error responses.

### `main(int argc, char* argv[])`

- Entry point of the proxy server application.
- Parses command-line arguments for port number, thread pool size, and maximum tasks.
- Initializes the thread pool with the specified number of threads.
- Sets up a listening socket and accepts incoming connections.
- Dispatches tasks to handle client requests using the thread pool.
- Gracefully destroys the thread pool and closes the socket upon termination.

## Features

- Concurrent handling of multiple client connections using a thread pool.
- Support for filtering forbidden URLs based on a configurable filter file.
- Proper validation of HTTP request headers and request line format.
- Generation of error responses for invalid requests or forbidden URLs.
- Dynamic adjustment of the thread pool size based on the workload.
- Graceful shutdown and cleanup of resources upon termination.

## Usage

Compile the `proxyServer.c` source file into an executable:

```bash
gcc -o proxyServer proxyServer.c threadpool.c -lpthread
./proxyServer <port> <num-of-tasks> <max-tasks> <filter-path>

<port>: Port number for the proxy server to listen on.
<num-of-tasks>: Number of threads in the thread pool.
<max-tasks>: Maximum number of tasks to be handled concurrently.
<filter-path>: Path to the filter file containing forbidden URLs.
==Example==
./proxyServer 8080 5 10 filter.txt
This command starts the proxy server on port 8080 with a thread pool of 5 threads. It handles up to 10 tasks concurrently and uses the filter.txt file for URL filtering.