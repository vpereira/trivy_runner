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
    make
   ```

## Usage

`docker-compose build` # to build it

`docker-compose up` # to start it

Then if you want to scan a new image:

```
curl "http://localhost:8080/scan?image=registry.suse.com/bci/bci-busybox:latest"
```

Then to fetch the scan report:

```
curl "http://localhost:8080/report?image=registry.suse.com/bci/bci-busybox:latest"

```

## Integration with registry catalog

If you want to test integration together with registry catalog

- Check/adapt the `docker-compose-integration.yml` file
- run `make integration-server`

It will run docker-compose up and set endpoint to send the scan results and flag scanworker to submit the task to pushworker

# Kubernetes Setup Using Docker and Rancher Desktop

This guide provides instructions on how to bootstrap the Kubernetes environment using Docker, Rancher Desktop, and a Makefile for automation.

## Makefile Tasks

### `k8s-deploy`

This task applies the Kubernetes configurations for the various components of the application.

To deploy the application to your Kubernetes cluster, run:

```bash
make k8s-deploy
```

This command executes the following tasks:
- Deploys a Docker Registry within the Kubernetes cluster.
- Deploys Redis server and its service.
- Creates a shared Persistent Volume Claim (PVC).
- Deploys the Web API, Scan Worker, and Pull Worker services.

### `k8s-build-images`

Builds Docker images using Docker Compose.

To build the images, run:

```bash
make k8s-build-images
```

### `k8s-tag-images`

Tags the built images for the local registry. This task depends on `k8s-build-images`.

To tag the images, run:

```bash
make k8s-tag-images
```

The images are tagged as follows:
- `trivy_runner_scanworker` as `localhost:5000/trivy_runner_scanworker:latest`
- `trivy_runner_pullworker` as `localhost:5000/trivy_runner_pullworker:latest`
- `trivy_runner_pushworker` as `localhost:5000/trivy_runner_pushworker:latest`
- `trivy_runner_webapi` as `localhost:5000/trivy_runner_webapi:latest`

### `k8s-push-images`

Pushes the tagged images to the local Docker registry. This task depends on `k8s-tag-images`.

To push the images to the local registry, run:

```bash
make k8s-push-images
```

## Usage

1. Start by building and tagging your Docker images:

   ```bash
   make k8s-build-images
   make k8s-tag-images
   ```
   
2. Deploy the application components to your Kubernetes cluster:

   ```bash
   make k8s-deploy
   ```

3. Push the images to the local Docker registry:

   ```bash
   make k8s-push-images
   ```


## Features

- Scan Docker images for vulnerabilities using Trivy.
- Real-time logging of scanning process.
