# Trivy Runner

## Description
**Trivy Runner** is a Go-based web application designed to scan Docker images for vulnerabilities using [Trivy](https://github.com/aquasecurity/trivy). It simplifies the process by providing a web API that can be used to trigger vulnerability scans and retrieve detailed security reports.

## Solution Components
The solution is composed of several components that work together to provide comprehensive scanning and processing:

- **Redis**: The communication bus used by all other components to coordinate tasks.
- **WebAPI**: The main entry point, receiving commands for which images to process.
- **PullWorker**: A worker that uses Skopeo in the backend to pull images, with or without authentication.
- **ScanWorker**: A worker that uses Trivy in the backend to scan the images for vulnerabilities.
- **GetSizeWorker**: Similar to `PullWorker`, but its purpose is to retrieve the uncompressed size of the images.
- **SBOMWorker**: A worker responsible for extracting the SBOM (Software Bill of Materials) and listing the packages contained in an image.
- **PushWorker**: This worker pushes the results of previous operations back to the registry catalog or other endpoints interested in consuming the data.

## Getting Started

### Prerequisites
Before you begin, ensure you have the following installed:
- [Go](https://golang.org/doc/install) (version 1.19 or later)
- [Docker](https://docs.docker.com/get-docker/)

### Installation

To install Trivy Runner locally, follow these steps:

1. Clone the repository:
   ```bash
   git clone https://github.com/vpereira/trivy_runner.git
   ```
2. Navigate to the project directory:
   ```bash
   cd trivy_runner
   ```
3. Build the application using the Makefile:
   ```bash
   make
   ```

## Usage

To build and start Trivy Runner, use Docker Compose:

1. Build the Docker container:
   ```bash
   docker-compose build
   ```
2. Start the application:
   ```bash
   docker-compose up
   ```

Once the service is running, you can scan a Docker image by sending a request to the web API. For example:

```bash
curl "http://localhost:8080/scan?image=registry.suse.com/bci/bci-busybox:latest"
```

This command will initiate a scan of the specified image and return the results.

## How to Run it Locally in Development

To run Trivy Runner locally for development purposes, follow these steps:

1. Ensure that Redis is running:
   ```bash
   docker run -p 6379:6379 redis:latest
   ```
2. Start the WebAPI:
   ```bash
   bin/webapi
   ```
   With the WebAPI running, you can send jobs to it via `curl`. After the WebAPI submits the job to Redis, you can stop the WebAPI.

3. Run the `PullWorker`:
   ```bash
   IMAGES_APP_DIR=/tmp bin/pull_worker
   ```
4. Run the `ScanWorker`:
   ```bash
   REPORTS_APP_DIR=/tmp PUSH_TO_CATALOG="1" ./bin/scan_worker
   ```
5. Finally, push the results using the `PushWorker`:
   ```bash
   WEBHOOK_URL=http://localhost:8080/foo/bar bin/push_worker
   ```

If you have a local web server running, you'll be able to inspect the JSON being sent by the Trivy Runner.

At any time, you can inspect the Redis queues to help debug and ensure that traffic is flowing as expected.

## Integration with Registry Catalog

To test the whole process, you can use the `docker-compose-integration.yml` file to start the Trivy Runner, Registry backend and a local webserver emulating the catalog.
In the registry, we have a single image that will be scanned by the Trivy Runner and pushed back to the emulated catalog.

1. Run the integration server:
   ```bash
   make integration-server
   ```

2. You can then send commands against the Trivy Runner:
   In your local dev machine, you can use the following commands to interact with the Trivy Runner:
   To scan an image:
   ```bash
   curl "http://localhost:8080/scan?image=registry:5000/busybox:latest"
   ```
   To generate sbom:
   ```bash
    curl "http://localhost:8080/sbom?image=registry:5000/busybox:latest"
    ```
   To get the size of the image:
   ```bash
    curl "http://localhost:8080/size?image=registry:5000/busybox:latest"
    ```

## Features

- Scans Docker images for security vulnerabilities using Trivy.
- Emits Docker images uncompressed size.
- Extracts the SBOM (Software Bill of Materials) from Docker images.
- Provides real-time logging of the scanning process.
- Easily integrates with Docker registries and catalogs.
- Modular workers for pulling, scanning, and pushing images, including SBOM extraction and size calculations.
