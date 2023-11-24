package logging

import (
	"bufio"
	"io"
	"log"
	"net/http"
	"os/exec"
	"time"
)

func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		// Log the incoming request
		log.Printf("Started %s %s", r.Method, r.URL.Path)

		next.ServeHTTP(w, r)

		// Log the time taken to process the request
		log.Printf("Completed in %v", time.Since(start))
	})
}

// streamToLog streams the output of the given reader to the logger
func streamToLog(reader io.Reader) {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		log.Println(scanner.Text())
	}
}

// executeAndStreamOutput executes the given command and streams its output to the log
func ExecuteAndStreamOutput(name string, args ...string) error {
	cmd := exec.Command(name, args...)

	// Get the stdout and stderr pipes
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	// Start the command
	if err := cmd.Start(); err != nil {
		return err
	}

	// Stream stdout and stderr to the logger
	go streamToLog(stdoutPipe)
	go streamToLog(stderrPipe)

	// Wait for the command to finish
	return cmd.Wait()
}
