//go:generate mockgen -destination=mocks/mocks.go -package=mocks -source=secrets_manager.go SecretsManagerClient
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

// SecretsManagerClient interface for AWS Secrets Manager operations
// This allows us to mock the client for testing
type SecretsManagerClient interface {
	ListSecrets(ctx context.Context, params *secretsmanager.ListSecretsInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error)
	GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
	DescribeSecret(ctx context.Context, params *secretsmanager.DescribeSecretInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.DescribeSecretOutput, error)
	CreateSecret(ctx context.Context, params *secretsmanager.CreateSecretInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error)
	UpdateSecret(ctx context.Context, params *secretsmanager.UpdateSecretInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.UpdateSecretOutput, error)
}

// SecretManager wraps the client and provides business logic methods
type SecretManager struct {
	client SecretsManagerClient
}

// NewSecretManager creates a new SecretManager instance
func NewSecretManager(client SecretsManagerClient) *SecretManager {
	return &SecretManager{client: client}
}

// GetMultipartNumbers retrieves all part numbers for a base secret name
func (sm *SecretManager) GetMultipartNumbers(ctx context.Context, base string) ([]int, error) {
	var numbers []int
	input := &secretsmanager.ListSecretsInput{}
	var nextToken *string

	for {
		input.NextToken = nextToken
		resp, err := sm.client.ListSecrets(ctx, input)
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
					_, err := fmt.Sscanf(part, "%d", &num)
					if err != nil {
						return nil, fmt.Errorf("failed to parse part number from secret '%s': %w", name, err)
					}
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

// GetSecretData retrieves secret data by name
func (sm *SecretManager) GetSecretData(ctx context.Context, name string) (map[string]interface{}, error) {
	input := &secretsmanager.GetSecretValueInput{SecretId: aws.String(name)}
	resp, err := sm.client.GetSecretValue(ctx, input)
	if err != nil {
		return nil, err
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(aws.ToString(resp.SecretString)), &m); err != nil {
		return nil, err
	}
	return m, nil
}

// FetchAllSecretData fetches all secret data across multipart secrets
// numbers: pre-fetched list of multipart numbers (0 = base secret, 1 = base-1, etc.)
func (sm *SecretManager) FetchAllSecretData(ctx context.Context, base string, numbers []int) (map[string]interface{}, error) {
	all := make(map[string]interface{})
	sort.Ints(numbers)
	for _, n := range numbers {
		var name string
		if n == 0 {
			name = base
		} else {
			name = fmt.Sprintf("%s-%d", base, n)
		}
		data, err := sm.GetSecretData(ctx, name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: Failed to get secret data for '%s': %v\n", name, err)
			return nil, err
		}
		if data != nil {
			for k, v := range data {
				if _, exists := all[k]; exists {
					return nil, fmt.Errorf("duplicate key '%s' found in secret part '%s'", k, name)
				}
				all[k] = v
			}
		}
	}
	return all, nil
}

// CreateOrModifySecret creates or updates a secret
func (sm *SecretManager) CreateOrModifySecret(ctx context.Context, name string, data map[string]interface{}, tags map[string]string) error {
	js, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal secret data: %w", err)
	}
	input := &secretsmanager.DescribeSecretInput{SecretId: aws.String(name)}
	_, err = sm.client.DescribeSecret(ctx, input)
	if err == nil {
		_, err = sm.client.UpdateSecret(ctx, &secretsmanager.UpdateSecretInput{
			SecretId:     aws.String(name),
			SecretString: aws.String(string(js)),
		})
		return err
	}
	tagsList := make([]types.Tag, 0, len(tags))
	for k, v := range tags {
		tagsList = append(tagsList, types.Tag{Key: aws.String(k), Value: aws.String(v)})
	}
	_, err = sm.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
		Name:         aws.String(name),
		SecretString: aws.String(string(js)),
		Tags:         tagsList,
	})
	return err
}

// RedistributeSecrets redistributes chunks across multipart secrets
// numbers: pre-fetched list of multipart numbers (0 = base secret, 1 = base-1, etc.)
func (sm *SecretManager) RedistributeSecrets(ctx context.Context, base string, chunks []map[string]interface{}, tags map[string]string, numbers []int) error {
	sort.Ints(numbers)
	if len(chunks) < len(numbers) {
		return fmt.Errorf("number of new chunks (%d) is less than existing multipart secrets (%d). This would leave duplicated keys in extra secrets. Please manually delete extra secrets or check your input", len(chunks), len(numbers))
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
			// Create new secrets sequentially after the highest existing number
			nextNum := maxNum + 1
			name = fmt.Sprintf("%s-%d", base, nextNum)
			maxNum = nextNum
		}
		err := sm.CreateOrModifySecret(ctx, name, chunk, tags)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: Failed to create/modify secret '%s': %v\n", name, err)
			return err
		}
	}
	return nil
}