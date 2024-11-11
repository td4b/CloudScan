package dns

import (
	"bytes"
	"context"
	"io"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

// ensure API key for providers stored at: ~/.config/subfinder/provider-config.yaml
// use config-map for this.
func FindRecords(domains []string) []string {
	// Set up the subfinder options with desired configuration
	subfinderOpts := &runner.Options{
		Threads:            10, // Controls number of threads for active enumerations
		Timeout:            30, // Timeout in seconds for sources to respond
		MaxEnumerationTime: 10, // MaxEnumerationTime in minutes to wait for enumeration
	}

	// Initialize subfinder runner
	subfinder, err := runner.NewRunner(subfinderOpts)
	if err != nil {
		gologger.Fatal().Msgf("Failed to create subfinder runner: %v", err)
	}

	// Create an io.Reader for multiple domains
	var inputBuffer bytes.Buffer
	for _, domain := range domains {
		inputBuffer.WriteString(domain + "\n")
	}

	// Set up a context with timeout to control the enumeration duration
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Buffer to capture the output
	output := &bytes.Buffer{}

	// Run subfinder on multiple domains with context
	if err := subfinder.EnumerateMultipleDomainsWithCtx(ctx, &inputBuffer, []io.Writer{output}); err != nil {
		gologger.Fatal().Msgf("Failed to enumerate multiple domains: %v", err)
	}

	// Return the results
	results := strings.Split(strings.TrimSpace(output.String()), "\n")
	return results
}
