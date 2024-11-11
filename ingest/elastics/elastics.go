package elastics

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"net/http"

	elastic "github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
	"github.com/projectdiscovery/gologger"
)

func RecordUpload(index string, records []string) {
	// Elasticsearch host and credentials
	host := "localhost"
	username := "elastic"
	password := "elastic"

	// Elasticsearch client configuration
	cfg := elastic.Config{
		Addresses: []string{
			fmt.Sprintf("https://%s:9200", host),
		},
		Username: username,
		Password: password,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Skips TLS certificate verification
			},
		},
	}

	es, err := elastic.NewClient(cfg)
	if err != nil {
		gologger.Error().Msg(fmt.Sprintf("Error creating Elasticsearch client: %s", err))
		return
	}

	// Check if the index exists
	res, err := es.Indices.Exists([]string{index})
	if err != nil {
		gologger.Error().Msg(fmt.Sprintf("Error checking if index exists: %s", err))
		return
	}
	defer res.Body.Close()

	// If the index doesn’t exist, create it with a timestamp mapping
	if res.StatusCode == 404 {
		indexMapping := `{
			"mappings": {
				"properties": {
					"@timestamp": {"type": "date"}
				}
			}
		}`
		createRes, err := es.Indices.Create(index, es.Indices.Create.WithBody(strings.NewReader(indexMapping)))
		if err != nil {
			gologger.Fatal().Msg(fmt.Sprintf("Error creating index: %s", err))
			return
		}
		defer createRes.Body.Close()
		if createRes.IsError() {
			gologger.Fatal().Msg(fmt.Sprintf("Error response from index creation: %s", createRes.String()))
			return
		}
		gologger.Info().Msg(fmt.Sprintf("Created index: %s with @timestamp mapping", index))
	}

	// Prepare the bulk API request body from []records
	var bulkBody strings.Builder
	for _, record := range records {
		var document map[string]interface{}
		meta := fmt.Sprintf(`{ "index" : { "_index" : "%s" } }%s`, index, "\n")

		if strings.Contains(index, "records") {
			// Process as "records" - set record as hostname with timestamp
			document = map[string]interface{}{
				"hostname":  record,
				"timestamp": time.Now().Format(time.RFC3339),
			}
			// Add timestamp if not present
			if _, ok := document["@timestamp"]; !ok {
				document["@timestamp"] = time.Now().Format(time.RFC3339)
			}
		} else if strings.Contains(index, "scan") {
			// Process as "scan" - parse each record as JSON
			if err := json.Unmarshal([]byte(record), &document); err != nil {
				gologger.Error().Msg(fmt.Sprintf("Error unmarshaling JSON for scan record: %v", err))
				continue
			}
			// Add timestamp if not present
			if _, ok := document["@timestamp"]; !ok {
				document["@timestamp"] = time.Now().Format(time.RFC3339)
			}
		}

		// Prepare the JSON data for the bulk request
		data, err := json.Marshal(document)
		if err != nil {
			gologger.Error().Msg(fmt.Sprintf("Error marshaling document: %v", err))
			continue
		}
		bulkBody.WriteString(meta)
		bulkBody.WriteString(string(data) + "\n")
	}

	// Send bulk request if there is data to ingest
	if bulkBody.Len() > 0 {
		bulkReq := esapi.BulkRequest{
			Body: strings.NewReader(bulkBody.String()),
		}
		bulkRes, err := bulkReq.Do(context.Background(), es)
		if err != nil {
			gologger.Fatal().Msg(fmt.Sprintf("Error executing bulk request: %s", err))
			return
		}
		defer bulkRes.Body.Close()

		if bulkRes.IsError() {
			gologger.Fatal().Msg(fmt.Sprintf("Bulk request error: %s", bulkRes.String()))
			return
		}

		gologger.Info().Msg(fmt.Sprintf("Elastic Data ingested successfully for Index: %v", index))
	} else {
		gologger.Info().Msg(fmt.Sprintf("No valid records to ingest for Index: %v", index))
	}
}
