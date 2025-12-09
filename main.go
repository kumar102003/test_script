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
	"regexp"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/tidwall/gjson"
)

const MaxSecretSizeBytes = 50 * 1024

var (
	multipartSuffix = regexp.MustCompile(-[1-5]$)
)

func verifySecretName(secretName string) (string, error) {
	clean := strings.TrimSpace(secretName)
	if multipartSuffix.MatchString(clean) {
		return "", fmt.Errorf("multipart secret name provided: %s. Please provide the base secret name instead", clean)
	}
	return clean, nil
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

// findKey searches for a key in multipart secrets and returns which one contains it
// fullPath is dot-notation path like "Db.Cred.Username" or just "username"
func findKey(ctx context.Context, sm *SecretManager, base string, numbers []int, fullPath string) error {
	// Build list of secret names to fetch
	secretNames := make([]string, 0, len(numbers))
	for _, n := range numbers {
		if n == 0 {
			secretNames = append(secretNames, base)
		} else {
			secretNames = append(secretNames, fmt.Sprintf("%s-%d", base, n))
		}
	}

	// Fetch all secrets in a single batch call
	secretsData, err := sm.GetSecretsData(ctx, secretNames)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to fetch secrets: %v\n", err)
		return err
	}

	// Search for the key in each secret
	for _, secretName := range secretNames {
		secretValue, exists := secretsData[secretName]
		if !exists {
			return fmt.Errorf("secret '%s' not found in batch response. ", secretName)
		}

		// Use gjson to check if the path exists
		result := gjson.Get(secretValue, fullPath)
		if result.Exists() {
			fmt.Printf("✅ Key '%s' found in: %s\n", fullPath, secretName)
			return nil
		}
	}

	fmt.Printf("❌ Key '%s' not found\n", fullPath)
	return nil
}

func main() {
	env := flag.String("env", "", "The environment (e.g., staging, prod)")
	secretName := flag.String("secret_name", "", "Base name of the secret")
	jsonData := flag.String("json_data", "", "JSON data containing key-value pairs to add")
	jsonPath := flag.String("json_path", "", "Dot notation path for operations (e.g., 'Cred.Db.Username' for find, 'Cred.Db' for add nested). For add/update: path to nested object. For find: full path to key.")
	forceUpdate := flag.Bool("force_update", false, "Enable update mode. If true, updates existing keys (fails if missing). If false, adds new keys (fails if exists).")
	findKeyMode := flag.Bool("find-key", false, "Find mode: Search for key specified in --json_path across multipart secrets")
	flag.Parse()

	// Validate required flags
	if *env == "" || *secretName == "" || (*jsonData == "" && !*findKeyMode) || (*jsonData != "" && *findKeyMode) || (*findKeyMode && *jsonPath == "") {
		if *env == "" || *secretName == "" {
			fmt.Fprintf(os.Stderr, "ERROR: --env and --secret_name are required\n")
		} else if *jsonData == "" && !*findKeyMode {
			fmt.Fprintf(os.Stderr, "ERROR: Either --json_data (for add/update) or --find-key (for find mode) is required\n")
		} else if *jsonData != "" && *findKeyMode {
			fmt.Fprintf(os.Stderr, "ERROR: Cannot use both --json_data and --find-key together\n")
		} else if *findKeyMode && *jsonPath == "" {
			fmt.Fprintf(os.Stderr, "ERROR: --json_path is required in find-key mode (e.g., 'username' or 'Db.Cred.Username')\n")
		}
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
		"temp:env":     *env,
		"temp:feature": "multipart_secrets",
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

	// Find-key mode
	if *findKeyMode {
		if err := findKey(context.Background(), sm, baseSecretName, numbers, *jsonPath); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	newData, err := parseJSONInput(*jsonData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}

	// It returns combined Map containing all keys from  Multipart secrtes .
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