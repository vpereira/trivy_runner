package main

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/vpereira/trivy_runner/internal/logging"
)

func main() {
	http.Handle("/scan", logging.LoggingMiddleware(http.HandlerFunc(handleScan)))
	log.Println("Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	imageName := r.URL.Query().Get("image")
	if imageName == "" {
		http.Error(w, "Image name is required", http.StatusBadRequest)
		return
	}

	report, err := performScan(imageName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(report)
}

func performScan(imageName string) ([]byte, error) {
	// Compute the path for the directory to store the JSON reports
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	reportsDir := filepath.Join(cwd, "trivy-reports")

	// Create the reports directory if it doesn't exist
	os.MkdirAll(reportsDir, os.ModePerm)

	// Prepare the report file name and path
	reportFile := filepath.Base(strings.ReplaceAll(imageName, "/", "_")) + ".json"
	reportPath := filepath.Join(reportsDir, reportFile)
	containerReportPath := "/reports/" + reportFile

	// Pull the Docker image
	if err := logging.ExecuteAndStreamOutput("docker", "pull", imageName); err != nil {
		return nil, err
	}

	// Run Trivy scan inside a Docker container
	if err := logging.ExecuteAndStreamOutput("docker", "run", "--rm", "-v", reportsDir+":/reports", "aquasec/trivy", "image", "-f", "json", "-o", containerReportPath, imageName); err != nil {
		return nil, err
	}

	// Read the JSON report
	report, err := os.ReadFile(reportPath)
	if err != nil {
		return nil, err
	}

	return report, nil
}
