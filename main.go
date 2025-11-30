

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
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
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

func getMultipartNumbers(client *secretsmanager.Client, base string) ([]int, error) {
	var numbers []int
	input := &secretsmanager.ListSecretsInput{}
	var nextToken *string

	for {
		input.NextToken = nextToken
		resp, err := client.ListSecrets(context.Background(), input)
		if err != nil {
			return nil, err
		}
		for _, secret := range resp.SecretList {
			name := aws.ToString(secret.Name)
			if name == base {
				numbers = append(numbers, 0)
			} else if strings.HasPrefix(name, base+"-") {
				part := strings.TrimPrefix(name, base+"-")
				if isNumeric(part) {
					num := 0
					fmt.Sscanf(part, "%d", &num)
					numbers = append(numbers, num)
				}
			}
		}
		if resp.NextToken == nil {
			break
		}
		nextToken = resp.NextToken
	}
	return numbers, nil
}

func getSecretData(client *secretsmanager.Client, name string) (map[string]string, error) {
	input := &secretsmanager.GetSecretValueInput{SecretId: aws.String(name)}
	resp, err := client.GetSecretValue(context.Background(), input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to get secret '%s': %v\n", name, err)
		return nil, err
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(aws.ToString(resp.SecretString)), &m); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to unmarshal secret '%s': %v\n", name, err)
		return nil, err
	}
	return m, nil
}

func fetchAllSecretData(client *secretsmanager.Client, base string) (map[string]string, error) {
	all := make(map[string]string)
	numbers, err := getMultipartNumbers(client, base)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to get multipart numbers for '%s': %v\n", base, err)
		return nil, err
	}
	sort.Ints(numbers)
	for _, n := range numbers {
		var name string
		if n == 0 {
			name = base
		} else {
			name = fmt.Sprintf("%s-%d", base, n)
		}
		data, err := getSecretData(client, name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: Failed to get secret data for '%s': %v\n", name, err)
			return nil, err
		}
		if data != nil {
			for k, v := range data {
				all[k] = v
			}
		}
	}
	return all, nil
}

func addKeyValues(all map[string]string, new map[string]string) error {
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

func sortDataAlphabetically(data map[string]string) map[string]string {
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	sorted := make(map[string]string, len(data))
	for _, k := range keys {
		sorted[k] = data[k]
	}
	return sorted
}

// parseJSONInput parses JSON input and converts all values to strings.
// Nested objects, arrays, numbers, and booleans are automatically marshaled to JSON strings.
func parseJSONInput(jsonData string) (map[string]string, error) {
	// Step 1: Validate JSON syntax (like 'jq') and accept any valid JSON structure
	var rawData map[string]interface{}
	if err := json.Unmarshal([]byte(jsonData), &rawData); err != nil {
		return nil, fmt.Errorf("invalid JSON data: %w", err)
	}

	if len(rawData) == 0 {
		return nil, fmt.Errorf("JSON data is empty")
	}

	// Step 2: Convert to map[string]string for internal processing
	result := make(map[string]string)
	for k, v := range rawData {
		switch val := v.(type) {
		case string:
			result[k] = val
		default:
			// If the value is an object, array, number, or bool, marshal it to a string
			js, err := json.Marshal(val)
			if err != nil {
				return nil, fmt.Errorf("failed to convert value for key '%s' to string: %w", k, err)
			}
			result[k] = string(js)
		}
	}

	return result, nil
}


func chunkDataIntoSecrets(data map[string]string) []map[string]string {
	// Extract and sort keys to ensure deterministic chunking
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	chunks := []map[string]string{}
	current := make(map[string]string)
	for _, k := range keys {
		v := data[k]
		// Check if this key-value pair alone exceeds the chunk size
		testSingle := map[string]string{k: v}
		jsSingle, err := json.Marshal(testSingle)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: Failed to marshal single key-value: %v\n", err)
			continue
		}
		if getSecretSize(string(jsSingle)) > MaxSecretSizeBytes {
			fmt.Fprintf(os.Stderr, "ERROR: Key '%s' exceeds max chunk size (%d bytes): got %d\n", k, MaxSecretSizeBytes, getSecretSize(string(jsSingle)))
			return nil
		}
		// Normal chunking logic
		test := make(map[string]string)
		for ck, cv := range current {
			test[ck] = cv
		}
		test[k] = v
		js, err := json.Marshal(test)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: Failed to marshal chunk: %v\n", err)
			continue
		}
		if getSecretSize(string(js)) > MaxSecretSizeBytes && len(current) > 0 {
			chunks = append(chunks, current)
			current = map[string]string{k: v}
		} else {
			current[k] = v
		}
	}
	if len(current) > 0 {
		chunks = append(chunks, current)
	}
	return chunks
}

func createOrModifySecret(client *secretsmanager.Client, name string, data map[string]string, tags map[string]string) error {
	js, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal secret data: %w", err)
	}
	input := &secretsmanager.DescribeSecretInput{SecretId: aws.String(name)}
	_, err = client.DescribeSecret(context.Background(), input)
	if err == nil {
		_, err = client.UpdateSecret(context.Background(), &secretsmanager.UpdateSecretInput{
			SecretId:     aws.String(name),
			SecretString: aws.String(string(js)),
		})
		return err
	}
	tagsList := []types.Tag{}
	for k, v := range tags {
		tagsList = append(tagsList, types.Tag{Key: aws.String(k), Value: aws.String(v)})
	}
	_, err = client.CreateSecret(context.Background(), &secretsmanager.CreateSecretInput{
		Name:         aws.String(name),
		SecretString: aws.String(string(js)),
		Tags:         tagsList,
	})
	return err
}

func redistributeSecrets(client *secretsmanager.Client, base string, chunks []map[string]string, tags map[string]string) error {
	numbers, err := getMultipartNumbers(client, base)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to get multipart numbers for redistribution: %v\n", err)
		return err
	}
	sort.Ints(numbers)

	if len(chunks) < len(numbers) {
		return fmt.Errorf("number of new chunks (%d) is less than existing multipart secrets (%d). This would leave duplicated keys in extra secrets.", len(chunks), len(numbers))
	}

	maxNum := -1
	if len(numbers) > 0 {
		maxNum = numbers[len(numbers)-1]
	}

	for i, chunk := range chunks {
		var name string
		if i < len(numbers) {
			if numbers[i] == 0 {
				name = base
			} else {
				name = fmt.Sprintf("%s-%d", base, numbers[i])
			}
		} else {
			// Use max(numbers) + (i - len(numbers) + 1) to ensure sequential numbering
			// and to start with -1 if only base exists (maxNum=0 -> next is 1)
			nextNum := maxNum + (i - len(numbers) + 1)
			if nextNum == 0 {
				name = base
			} else {
				name = fmt.Sprintf("%s-%d", base, nextNum)
			}
		}
		err := createOrModifySecret(client, name, chunk, tags)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: Failed to create/modify secret '%s': %v\n", name, err)
			return err
		}
	}
	return nil
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

	// Check if base secret exists
	_, err = client.DescribeSecret(context.Background(), &secretsmanager.DescribeSecretInput{
		SecretId: aws.String(baseSecretName),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Base secret '%s' does not exist or cannot be accessed: %v\n", baseSecretName, err)
		os.Exit(1)
	}

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


	allData, err := fetchAllSecretData(client, baseSecretName)
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
	if err := redistributeSecrets(client, baseSecretName, chunks, tags); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: failed to redistribute secrets: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Add operation completed successfully. Total keys: %d, Total secrets: %d\n", len(sortedData), len(chunks))
}