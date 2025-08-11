package utils

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func GetProviderName(devOrgDON string) (string, error) {
	// Find the value after last /
	lastSlashIndex := strings.LastIndex(devOrgDON, "/")
	if lastSlashIndex > 0 {
		devOrgDON = devOrgDON[lastSlashIndex+1:]
		return fmt.Sprintf("local:%s", devOrgDON), nil
	}
	return "", fmt.Errorf("invalid Dev org DON format: %s", devOrgDON)
}

func GetDek(
	ctx context.Context,
	providerName string,
	keyVaultNamespace string) (
	dataKey *primitive.Binary, kmsProviders map[string]map[string]interface{}, err error,
) {
	uri := os.Getenv("MONGODB_URI")
	if uri == "" {
		return nil, nil, fmt.Errorf("MONGODB_URI environment variable is not set")
	}

	// Load or create the local master key from the file system.
	localMasterKey, err := LoadOrCreateMasterKey(providerName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load or create master key: %v", err)
	}

	// Construct the KMS providers map.
	kmsProviders = map[string]map[string]interface{}{
		providerName: {"key": localMasterKey},
	}

	// Create a regular MongoDB client for key operations.
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		return nil, nil, fmt.Errorf("keyvault client connect error: %v", err)
	}
	defer client.Disconnect(ctx)

	// This is used for key management operations.
	clientEnc, err := mongo.NewClientEncryption(client,
		options.ClientEncryption().
			SetKeyVaultNamespace(keyVaultNamespace).
			SetKmsProviders(kmsProviders),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create client encryption: %v", err)
	}
	defer clientEnc.Close(ctx)

	keyAltName := fmt.Sprintf("dek-%s", providerName)
	singleResult := clientEnc.GetKeyByAltName(ctx, keyAltName)

	var dekDoc bson.D
	err = singleResult.Decode(&dekDoc)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			fmt.Printf("DEK with alt name '%s' not found, creating a new one.\n", keyAltName)
			opts := options.DataKey().SetKeyAltNames([]string{keyAltName})
			newDekResult, err := clientEnc.CreateDataKey(ctx, providerName, opts)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to create DEK: %v", err)
			}
			return &newDekResult, kmsProviders, nil
		}
		return nil, nil, fmt.Errorf("failed to decode DEK lookup result: %w", err)
	}

	fmt.Printf("Found existing DEK with alt name: %s\n", keyAltName)

	idVal, ok := dekDoc.Map()["_id"]
	if !ok {
		return nil, nil, fmt.Errorf("DEK document missing _id field")
	}
	id, ok := idVal.(primitive.Binary)
	if !ok {
		return nil, nil, fmt.Errorf("DEK _id field is not of type primitive.Binary")
	}
	return &id, kmsProviders, nil
}

func NewEncClient(
	ctx context.Context,
	keyVaultNamespace string,
	schemaMap bson.M,
	kmsProviders map[string]map[string]interface{},
	bypassAutoEncryption bool,
) (*mongo.Client, error) {
	uri := os.Getenv("MONGODB_URI")
	if uri == "" {
		return nil, fmt.Errorf("MONGODB_URI environment variable is not set")
	}

	autoEncryptionOpts := options.AutoEncryption().
		SetKeyVaultNamespace(keyVaultNamespace).
		SetKmsProviders(kmsProviders).
		// Provide the schema map for automatic encryption/decryption.
		SetSchemaMap(schemaMap).
		SetBypassAutoEncryption(bypassAutoEncryption)

	client, err := mongo.Connect(ctx, options.Client().
		ApplyURI(uri).
		SetAutoEncryptionOptions(autoEncryptionOpts),
	)
	if err != nil {
		return nil, fmt.Errorf("encryption client failed to connect: %w", err)
	}
	return client, nil
}

func LoadOrCreateMasterKey(providerName string) ([]byte, error) {
	const (
		keySize                 = 96
		masterKeyDirPermissions = 0700
		masterKeyDir            = "keys"
	)

	key := make([]byte, keySize)

	// Construct the file path within the _masterKeyDir
	filePath := filepath.Join(masterKeyDir, fmt.Sprintf("%s_master_key.bin", providerName))

	// Ensure the directory exists
	if err := os.MkdirAll(masterKeyDir, masterKeyDirPermissions); err != nil {
		return nil, fmt.Errorf("failed to create master key directory '%s': %w", masterKeyDir, err)
	}

	// Check if the file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		// File does not exist, generate a new key and save it
		_, err := rand.Read(key)
		if err != nil {
			return nil, fmt.Errorf("failed to generate new master key: %w", err)
		}

		file, err := os.Create(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to create master key file '%s': %w", filePath, err)
		}
		defer file.Close()

		_, err = file.Write(key)
		if err != nil {
			return nil, fmt.Errorf("failed to write master key to file '%s': %w", filePath, err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("error checking master key file status '%s': %w", filePath, err)
	} else {
		// File exists, read the key from it.
		file, err := os.Open(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to open master key file '%s': %w", filePath, err)
		}
		defer file.Close()

		n, err := file.Read(key)
		if err != nil {
			return nil, fmt.Errorf("failed to read master key from file '%s': %w", filePath, err)
		}
		if n != keySize {
			return nil, fmt.Errorf(
				"master key file '%s' has incorrect size: expected %d bytes, got %d", filePath, keySize, n,
			)
		}
	}
	return key, nil
}
