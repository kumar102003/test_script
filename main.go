// Multipart Secret Management Script v2 (Go version)
// This script implements a comprehensive approach for managing AWS Secrets Manager secrets.
// Features:
// - Add key-value pairs (bulk addition with full redistribution)
// - Values can be simple strings or nested escaped JSON
// - Automatic sorting of all keys alphabetically
// - Automatic redistribution across multipart secrets
// - 50KB limit per secret

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

const MaxSecretSizeBytes = 50 * 1024

func verifySecretName(secretName string) (string, error) {
	clean := strings.TrimSpace(secretName)
	parts := strings.Split(clean, "-")
	if len(parts) > 1 && isNumeric(parts[len(parts)-1]) {
		return "", fmt.Errorf("multipart secret name provided: %s. Please provide the base secret name instead", clean)
	}
	return clean, nil
}

func isNumeric(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}

func getSecretSize(data string) int {
	return len([]byte(data))
}

func addKeyValues(all map[string]interface{}, new map[string]interface{}, forceUpdate bool) error {
	for k := range new {
		_, exists := all[k]
		if forceUpdate {
			if !exists {
				return fmt.Errorf("key '%s' not found for update (use without --force_update to add new keys)", k)
			}
			fmt.Printf("Overwriting key '%s'\n", k)
		} else {
			if exists {
				return fmt.Errorf("key '%s' already exists (use --force_update to update existing keys)", k)
			}
		}
	}
	for k, v := range new {
		all[k] = v
	}
	return nil
}

// parseJSONInput parses JSON input and preserves the original structure.
// Objects, arrays, strings etc. are kept in their native types.
func parseJSONInput(jsonData string) (map[string]interface{}, error) {
	// Validate JSON syntax and unmarshal into map[string]interface{}
	var rawData map[string]interface{}
	if err := json.Unmarshal([]byte(jsonData), &rawData); err != nil {
		return nil, fmt.Errorf("invalid JSON data: %w", err)
	}

	if len(rawData) == 0 {
		return nil, fmt.Errorf("JSON data is empty")
	}

	// Return the data as-is (no conversion to strings)
	return rawData, nil
}

func chunkDataIntoSecrets(data map[string]interface{}) ([]map[string]interface{}, error) {
	// Extract and sort keys to ensure deterministic chunking
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	chunks := []map[string]interface{}{}
	current := make(map[string]interface{})
	for _, k := range keys {
		v := data[k]
		// Check if this key-value pair alone exceeds the chunk size
		testSingle := map[string]interface{}{k: v}
		jsSingle, err := json.MarshalIndent(testSingle, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("failed to marshal key '%s': %w", k, err)
		}
		if getSecretSize(string(jsSingle)) > MaxSecretSizeBytes {
			return nil, fmt.Errorf("key '%s' exceeds max chunk size (%d bytes): got %d", k, MaxSecretSizeBytes, getSecretSize(string(jsSingle)))
		}
		// Trial-based size check: test if adding new key would exceed limit
		test := make(map[string]interface{}) // Create empty temporary map
		for ck, cv := range current {        // Copy existing chunk into test
			test[ck] = cv
		}
		test[k] = v                                   // Add the new key-value to test (trial add)
		js, err := json.MarshalIndent(test, "", "  ") // Convert test map to JSON to measure size
		if err != nil {
			return nil, fmt.Errorf("failed to marshal chunk with key '%s': %w", k, err)
		}
		if getSecretSize(string(js)) > MaxSecretSizeBytes && len(current) > 0 {
			// Test exceeded limit → save current chunk and start new one with this key
			chunks = append(chunks, current)
			current = map[string]interface{}{k: v}
		} else {
			// Test fits → actually add the key to current chunk
			current[k] = v
		}
	}
	if len(current) > 0 {
		chunks = append(chunks, current)
	}
	return chunks, nil
}

func addSecretToGivenPath(all map[string]interface{}, new map[string]interface{}, jsonPath string, forceUpdate bool) error {
	parts := strings.Split(jsonPath, ".")
	current := all
	
	// Traverse to the parent of the target key
	for i := 0; i < len(parts); i++ {
		key := parts[i]
		val, exists := current[key]
		if !exists {
			return fmt.Errorf("key '%s' in path '%s' does not exist", key, jsonPath)
		}

		// If key exists, ensure it's a map
		nextMap, ok := val.(map[string]interface{})
		if !ok {
			return fmt.Errorf("key '%s' in path '%s' is not a map", key, jsonPath)
		}
		current = nextMap
	}

	// Merge new data into the target map
	for k, v := range new {
		_, exists := current[k]
		if forceUpdate {
			if !exists {
				return fmt.Errorf("key '%s' not found at path '%s' for update", k, jsonPath)
			}
			fmt.Printf("Overwriting key '%s' at path '%s'\n", k, jsonPath)
		} else {
			if exists {
				return fmt.Errorf("key '%s' already exists at path '%s'", k, jsonPath)
			}
		}
		current[k] = v
	}
	return nil
}

func main() {
	env := flag.String("env", "", "The environment (e.g., staging, prod)")
	secretName := flag.String("secret_name", "", "Base name of the secret")
	jsonData := flag.String("json_data", "", "JSON data containing key-value pairs to add")
	jsonPath := flag.String("json_path", "", "Optional JSON path (dot notation) to update nested keys (e.g., 'Cred.Db')")
	forceUpdate := flag.Bool("force_update", false, "Enable update mode. If true, updates existing keys (fails if missing). If false, adds new keys (fails if exists).")
	flag.Parse()

	if *env == "" || *secretName == "" || *jsonData == "" {
		fmt.Fprintf(os.Stderr, "ERROR: --env, --secret_name, and --json_data are required\n")
		os.Exit(1)
	}

	baseSecretName, err := verifySecretName(*secretName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: failed to load AWS config: %v\n", err)
		os.Exit(1)
	}
	client := secretsmanager.NewFromConfig(cfg)
	sm := NewSecretManager(client)

	tags := map[string]string{
		"temp:data-classification": "undefined",
		"temp:compliance":          "undefined",
		"temp:env":                 *env,
		"temp:resource":            "aws_secretsmanager_secret",
		"temp:feature":             "multipart_secrets",
	}

	newData, err := parseJSONInput(*jsonData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}

	// Check if base secret exists before proceeding
	_, err = client.DescribeSecret(context.Background(), &secretsmanager.DescribeSecretInput{
		SecretId: aws.String(baseSecretName),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Base secret '%s' does not exist. Please create the secret first before adding keys.\n", baseSecretName)
		os.Exit(1)
	}

	// Fetch multipart numbers once and reuse for both FetchAllSecretData and RedistributeSecrets
	numbers, err := sm.GetMultipartNumbers(context.Background(), baseSecretName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: failed to get multipart numbers: %v\n", err)
		os.Exit(1)
	}

	allData, err := sm.FetchAllSecretData(context.Background(), baseSecretName, numbers)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: failed to fetch existing secret data: %v\n", err)
		os.Exit(1)
	}

	if *jsonPath != "" {
		if err := addSecretToGivenPath(allData, newData, *jsonPath, *forceUpdate); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: failed to update nested keys: %v\n", err)
			os.Exit(1)
		}
	} else {
		if err := addKeyValues(allData, newData, *forceUpdate); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			os.Exit(1)
		}
	}

	chunks, err := chunkDataIntoSecrets(allData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
	if err := sm.RedistributeSecrets(context.Background(), baseSecretName, chunks, tags, numbers); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: failed to redistribute secrets: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Add operation completed successfully. Total keys: %d, Total secrets: %d\n", len(allData), len(chunks))
}