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

func cleanSecretName(secretName string) (string, error) {
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



func addKeyValues(all map[string]interface{}, new map[string]interface{}) error {
	for k := range new {
		if _, exists := all[k]; exists {
			fmt.Fprintf(os.Stderr, "ERROR: Key already exists: %s\n", k)
			return fmt.Errorf("key already exists: %s", k)
		}
	}
	for k, v := range new {
		all[k] = v
	}
	return nil
}

func sortDataAlphabetically(data map[string]interface{}) map[string]interface{} {
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	sorted := make(map[string]interface{}, len(data))
	for _, k := range keys {
		sorted[k] = data[k]
	}
	return sorted
}

// parseJSONInput parses JSON input and preserves the original structure.
// Objects, arrays, strings, numbers, and booleans are kept in their native types.
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


func chunkDataIntoSecrets(data map[string]interface{}) []map[string]interface{} {
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
			fmt.Fprintf(os.Stderr, "ERROR: Failed to marshal key '%s': %v\n", k, err)
			return nil
		}
		if getSecretSize(string(jsSingle)) > MaxSecretSizeBytes {
			fmt.Fprintf(os.Stderr, "ERROR: Key '%s' exceeds max chunk size (%d bytes): got %d\n", k, MaxSecretSizeBytes, getSecretSize(string(jsSingle)))
			return nil
		}
		// Normal chunking logic
		test := make(map[string]interface{})
		for ck, cv := range current {
			test[ck] = cv
		}
		test[k] = v
		js, err := json.MarshalIndent(test, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: Failed to marshal chunk with key '%s': %v\n", k, err)
			return nil
		}
		if getSecretSize(string(js)) > MaxSecretSizeBytes && len(current) > 0 {
			chunks = append(chunks, current)
			current = map[string]interface{}{k: v}
		} else {
			current[k] = v
		}
	}
	if len(current) > 0 {
		chunks = append(chunks, current)
	}
	return chunks
}

func main() {
	env := flag.String("env", "", "The environment (e.g., staging, prod)")
	secretName := flag.String("secret_name", "", "Base name of the secret")
	jsonData := flag.String("json_data", "", "JSON data containing key-value pairs to add")
	flag.Parse()

	if *env == "" || *secretName == "" || *jsonData == "" {
		fmt.Fprintf(os.Stderr, "ERROR: --env, --secret_name, and --json_data are required\n")
		os.Exit(1)
	}

	baseSecretName, err := cleanSecretName(*secretName)
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
		"temp:feature":             "multipart_secret_management_v2",
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

	allData, err := sm.FetchAllSecretData(context.Background(), baseSecretName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: failed to fetch existing secret data: %v\n", err)
		os.Exit(1)
	}
	if err := addKeyValues(allData, newData); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
	sortedData := sortDataAlphabetically(allData)
	chunks := chunkDataIntoSecrets(sortedData)
	if chunks == nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to chunk data into secrets. One or more keys may exceed the maximum secret size.\n")
		os.Exit(1)
	}
	if err := sm.RedistributeSecrets(context.Background(), baseSecretName, chunks, tags); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: failed to redistribute secrets: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Add operation completed successfully. Total keys: %d, Total secrets: %d\n", len(sortedData), len(chunks))
}