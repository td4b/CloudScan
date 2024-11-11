package main

import (
	"cloudscan/dns"
	"cloudscan/elastics"
	"cloudscan/scanner"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
)

func main() {
	// Set the maximum log level to Verbose
	// levels.LevelVerbose for debugging.
	gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)

	// Use a JSON formatter for structured logging
	gologger.DefaultLogger.SetFormatter(&formatter.JSON{})

	// Run indefinitely
	for {
		// Log the start of the cycle
		gologger.Info().Msg("Starting scan of Domains records.")

		// Start the Domain record enumeration
		targets := []string{"mydomain.com"}
		records := dns.FindRecords(targets)
		gologger.Info().Msg("Finished Domains record scans.")
		elastics.RecordUpload("domains-records", records)

		// Start the vulnerability scans
		gologger.Info().Msg("Starting vulnerability scans with Nuclei SDK.")
		results := scanner.Scan(records)
		elastics.RecordUpload("domains-scan", results)
		gologger.Info().Msg("Finished vulnerability scans.")

		// Log that the process will sleep for 24 hours
		gologger.Info().Msg("Sleeping for 24 hours until the next run...")
		time.Sleep(24 * time.Hour)
	}
}
