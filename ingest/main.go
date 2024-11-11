package main

import (
	"cloudscan/dns"
	"cloudscan/elastics"
	"cloudscan/scanner"
	"log"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
)

// Config holds the target hosts from the config.toml file
type Config struct {
	Settings struct {
		Targets []string `toml:"targets"`
	} `toml:"settings"`
}

func loadConfig(configPath string) (*Config, error) {
	var config Config
	if _, err := toml.DecodeFile(configPath, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

func main() {
	// Set the maximum log level to Verbose
	// levels.LevelVerbose for debugging.
	gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)

	// Use a JSON formatter for structured logging
	gologger.DefaultLogger.SetFormatter(&formatter.JSON{})

	// Load configuration from config.toml
	config, err := loadConfig("/home/cloudscan/.config/cloudscan/config.toml")
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Check health status of cluster, if it is not health exit after 10 seconds to retry.
	elastics.Healthcheck()

	// Run indefinitely
	for {
		// Log the start of the cycle
		gologger.Info().Msg("Starting scan of Domains records.")

		// Start the Domain record enumeration
		// Start the Domain record enumeration
		records := dns.FindRecords(config.Settings.Targets)
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
