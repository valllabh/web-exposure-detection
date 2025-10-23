package nuclei

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"sync"
	"time"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// NewStoredResult creates StoredResult from output.ResultEvent
func NewStoredResult(event *output.ResultEvent) *StoredResult {
	logger := GetLogger()

	result := &StoredResult{
		Host:        event.Host,
		TemplateID:  event.TemplateID,
		MatcherName: event.MatcherName,
		URL:         event.URL,
		MatchedAt:   event.Matched,
		IP:          event.IP,
	}

	// VERBOSE: Log ExtractedResults to debug
	logger.Debug().Msgf("NewStoredResult: Host=%s, TemplateID=%s, MatcherName=%s, ExtractedResults=%d items",
		event.Host, event.TemplateID, event.MatcherName, len(event.ExtractedResults))
	for i, extracted := range event.ExtractedResults {
		logger.Debug().Msgf("  ExtractedResults[%d]: %q", i, extracted)
	}

	// Parse ExtractedResults - all templates now use generic <f><k></k><vg><v></v></vg></f> format
	if len(event.ExtractedResults) == 0 {
		logger.Debug().Msg("No ExtractedResults, returning minimal result")
		return result
	}

	// Generic parsing for all templates
	findingsMap := make(map[string][]string)

	for i, extractedStr := range event.ExtractedResults {
		logger.Debug().Msgf("Processing extraction[%d]: %q", i, extractedStr)

		// Parse the <f> block
		var finding FindingXML
		if err := xml.Unmarshal([]byte(extractedStr), &finding); err != nil {
			logger.Warning().Msgf("Failed to unmarshal FindingXML[%d]: %v, raw: %q", i, err, extractedStr)
			continue
		}

		// Key is plain text (NOT base64 encoded)
		key := finding.Key

		// Decode base64 values
		var values []string
		for _, encodedVal := range finding.ValueGroup.Values {
			valBytes, err := base64.StdEncoding.DecodeString(encodedVal)
			if err != nil {
				logger.Warning().Msgf("Failed to decode value for key %q: %v", key, err)
				continue
			}
			values = append(values, string(valBytes))
		}

		// Store in map
		if len(values) > 0 {
			findingsMap[key] = values
			logger.Debug().Msgf("Decoded finding: key=%q, values=%v", key, values)
		}
	}

	result.Findings = findingsMap
	logger.Info().Msgf("Parsed %d findings for %s (template: %s)",
		len(findingsMap), event.Host, event.TemplateID)

	return result
}

// ExecuteNucleiScanWithCallback executes Nuclei scan with callback handling for results
func ExecuteNucleiScanWithCallback(ne *nuclei.NucleiEngine, opts *NucleiOptions, progress ProgressCallback) ([]*output.ResultEvent, error) {
	logger := GetLogger()

	// Open progressive results writer if configured
	var progressiveWriter *os.File
	var jsonlWriter *bufio.Writer
	var jsonlMutex sync.Mutex // Protect concurrent writes to jsonlWriter
	var jsonlWriteCount int   // Track writes for periodic flushing
	if opts.ResultsWriter != "" {
		var err error
		progressiveWriter, err = os.Create(opts.ResultsWriter)
		if err != nil {
			return nil, fmt.Errorf("failed to create progressive results file: %w", err)
		}
		defer func() {
			if err := progressiveWriter.Close(); err != nil {
				logger.Warning().Msgf("Failed to close progressive writer: %v", err)
			}
		}()
		// Use larger buffer (1MB) to reduce syscalls for large results
		jsonlWriter = bufio.NewWriterSize(progressiveWriter, 1024*1024)
		defer func() {
			if err := jsonlWriter.Flush(); err != nil {
				logger.Warning().Msgf("Failed to flush jsonl writer: %v", err)
			}
		}()
		logger.Info().Msgf("Writing progressive results to: %s", opts.ResultsWriter)
	}

	// Execute scan with progress tracking
	var results []*output.ResultEvent
	var resultsMutex sync.Mutex // Protect concurrent appends to results slice
	var testCount int
	var currentHost string
	var lastProgressUpdate int
	var hostStartTimes = make(map[string]time.Time)

	logger.Debug().Msg("Starting Nuclei execution callback handler")

	err := ne.ExecuteWithCallback(func(event *output.ResultEvent) {
		if event == nil {
			return
		}

		testCount++

		// Update current host only when it changes and notify progress
		if event.Host != currentHost {
			// Mark completion of previous host if there was one
			if currentHost != "" && progress != nil {
				if startTime, exists := hostStartTimes[currentHost]; exists {
					duration := time.Since(startTime)
					logger.Info().Msgf("Completed %s (%v)", currentHost, duration.Round(100*time.Millisecond))
				}
			}

			currentHost = event.Host
			hostStartTimes[currentHost] = time.Now()

			if progress != nil {
				logger.Info().Msgf("Testing %s", currentHost)
			}
		}

		// Notify progress callback every 50 tests to show steady progress
		if progress != nil && testCount-lastProgressUpdate >= 50 {
			progress.OnNucleiScanProgress(currentHost, testCount)
			lastProgressUpdate = testCount
		}

		// Only process actual findings (not just test executions)
		if event.TemplateID == "" {
			return
		}

		// Store native Nuclei result directly - no conversion needed
		// Protect concurrent appends from multiple goroutines
		resultsMutex.Lock()
		results = append(results, event)
		resultsMutex.Unlock()

		// Write result progressively if writer configured
		if jsonlWriter != nil {
			// Omit template encoding if requested
			if opts.OmitTemplate {
				event.TemplateEncoded = ""
			}

			// Omit response body if requested (can be very large)
			if opts.OmitResponse {
				event.Response = ""
				event.Request = ""
			}

			jsonData, err := json.Marshal(event)
			if err != nil {
				logger.Warning().Msgf("Failed to marshal result for %s: %v", event.Host, err)
				return // Skip this result
			}

			// Lock mutex to protect concurrent writes from multiple goroutines
			jsonlMutex.Lock()

			// Write JSON data
			n, err := jsonlWriter.Write(jsonData)
			if err != nil {
				jsonlMutex.Unlock()
				logger.Warning().Msgf("Failed to write result for %s: %v", event.Host, err)
				return // Skip this result
			}
			if n != len(jsonData) {
				jsonlMutex.Unlock()
				logger.Warning().Msgf("Partial write for %s (%d/%d bytes)", event.Host, n, len(jsonData))
				return // Skip this result
			}

			// Write newline
			if _, err := jsonlWriter.WriteString("\n"); err != nil {
				jsonlMutex.Unlock()
				logger.Warning().Msgf("Failed to write newline for %s: %v", event.Host, err)
				return // Skip this result
			}

			// Flush every 10 writes to balance real-time visibility with performance
			// This reduces disk I/O while maintaining reasonable update frequency
			jsonlWriteCount++
			if jsonlWriteCount%10 == 0 {
				if err := jsonlWriter.Flush(); err != nil {
					logger.Warning().Msgf("Failed to flush for %s: %v", event.Host, err)
				}
			}

			jsonlMutex.Unlock()
		}

		// Show findings as they're discovered
		if progress != nil {
			logger.Info().Msgf("Found: %s on %s", event.Info.Name, event.Host)
		}
	})

	if err != nil {
		logger.Error().Msgf("Nuclei execution failed: %v", err)
		return nil, fmt.Errorf("nuclei execution failed: %w", err)
	}

	// Mark completion of final host
	if currentHost != "" && progress != nil {
		if startTime, exists := hostStartTimes[currentHost]; exists {
			duration := time.Since(startTime)
			logger.Info().Msgf("Completed %s (%v)", currentHost, duration.Round(100*time.Millisecond))
		}
	}

	// Notify progress callback of completion
	if progress != nil {
		progress.OnNucleiScanComplete(testCount, len(results))
	}

	logger.Info().Msgf("Nuclei scan complete: %d tests performed, %d findings", testCount, len(results))

	return results, nil
}
