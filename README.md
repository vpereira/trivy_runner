# Trivy Runner

## Description
Trivy Runner is a Go-based web application designed to scan Docker images using Trivy and provide vulnerability reports. This tool simplifies the process of scanning container images for security vulnerabilities by exposing a web API.

## Getting Started

### Prerequisites
- Go (version 1.19 or later)
- Docker

### Installation

To set up the Trivy Runner on your local machine, follow these steps:

1. Clone the repository:
   ```
   git clone https://github.com/vpereira/trivy_runner.git
   ```
2. Navigate to the project directory:
   ```
   cd trivy_runner
   ```
3. Build the application:
   ```
   go build -o trivy_runner ./cmd/trivy_runner
   ```

## Usage

`docker-compose build` # to build it

`docker-compose up` # to start it

Then if you want to scan a new image:

curl "http://localhost:8080/scan?image=registry.suse.com/bci/bci-busybox:latest"

Then to fetch the scan report:

curl "http://localhost:8080/report?report=registry.suse.com/bci/bci-busybox:latest"


## Features

- Scan Docker images for vulnerabilities using Trivy.
- Real-time logging of scanning process.
