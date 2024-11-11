package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/projectdiscovery/gologger"
	lib "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// Define a function for setting scan options
func scanOptions() lib.NucleiSDKOptions {
	return func(e *lib.NucleiEngine) error {
		// Here you can set engine configuration options if needed
		e.Options().UpdateTemplates = true
		return nil
	}
}

func Scan(targets []string) []string {
	// Define a timeout and create a context
	var results []string
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Initialize the Nuclei engine with the context and options
	engine, err := lib.NewNucleiEngineCtx(ctx, scanOptions())
	if err != nil {
		// Log error directly using JSON output
		gologger.Error().Msg(fmt.Sprintf("Error creating nuclei engine: %v", err))
	}
	defer engine.Close()

	// Define the targets and load them separately

	engine.LoadTargets(targets, false)

	// Load all templates separately after engine initialization
	if err := engine.LoadAllTemplates(); err != nil {
		gologger.Error().Msg(fmt.Sprintf("Error loading templates: %v", err))
	}

	// Define a callback function to process each output event
	callback := func(event *output.ResultEvent) {
		eventJSON, err := json.Marshal(event)
		if err != nil {
			gologger.Error().Msg(fmt.Sprintf("Error marshaling event: %v", err))
			return
		}

		// Print the JSONL result to stdout (or handle it as needed)
		results = append(results, string(eventJSON))
	}

	// Execute the scan with the provided callback function
	err = engine.ExecuteWithCallback(callback)
	if err != nil {
		gologger.Error().Msg(fmt.Sprintf("Error Executing: %v", err))
	}
	return results
}
