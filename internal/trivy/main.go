package trivy

import "github.com/vpereira/trivy_runner/internal/util"

func GenerateTrivySBOMCmdArgs(resultFileName, target string) []string {
	cmdArgs := []string{"image"}

	// eventually we should support other formats as well
	cmdArgs = append(cmdArgs, "--format", "cyclonedx", "--output", resultFileName, "--input", target)

	return cmdArgs
}

func GenerateTrivyScanCmdArgs(resultFileName, target string) []string {
	cmdArgs := []string{"image"}

	// Check if SLOW_RUN environment variable is set to "1" and add "--slow" parameter
	timeout := util.GetEnv("SCAN_TIMEOUT", "5m")

	parallelism := util.GetEnv("SCAN_PARALLELISM", "0") // 0 means auto-detect

	if parallelism != "0" {
		cmdArgs = append(cmdArgs, "--parallel", parallelism)
	}

	cmdArgs = append(cmdArgs, "--format", "json", "--timeout", timeout, "--output", resultFileName, "--input", target)

	return cmdArgs
}
