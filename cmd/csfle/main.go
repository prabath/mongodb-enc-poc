package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/devrev/experimental/prabath/go/enc/utils"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// This is where the encrypted Data Encryption Keys (DEKs) will be stored in Atlas.
const _keyVaultNamespace = "csfle_keyvault.datakeys"

// Database and collection names for user data.
const _databaseName = "csfle_db"
const _collectionName = "users"

func main() {
	ctx := context.Background()

	// Get the provider name based on the Dev org ID.
	providerName, err := utils.GetProviderName("don:identity:dvrv-us-1:devo/100")
	if err != nil {
		log.Fatalf("Failed to get provider name: %v", err)
	}

	// We need a DEK and the corresponding KMS provider to initialize a MongoDB client, which
	// supports encryption. This adds complexity in a multi-tenant scenario, which is discussed in
	// a following comment.
	//
	// First we do a lookup in the server (MongoDB Atlas) to see if a DEK exists by the alt name;
	// if it does, we use the existing DEK. If not, the MongoDB driver generates a DEK, encrypts
	// it with the KMS provider, and stores it in the specified collection in the server.
	// The driver will cache the DEK against the ID, with the corresponding MongoDB connection. The
	// cache is maintained per MongoDB client connection. During the read operations, if the
	// corresponding DEK is not in the cache, the driver will look it up in the server
	// and cache it for future use. Need to see how this works with connection pooling.
	//
	// When a field is encrypted, the resulting BinData in MongoDB includes the _id (UUID) of the
	// DEK that was used for encryption. When the driver attempts to decrypt data, it looks at this
	// _id and loads the corresponding DEK. However, when a encrypted field is used in a filter
	// during a read, the driver consults its configured schemaMap and kmsProviders to find the
	// corresponding DEK and encrypts the field in the filter before sending it to the server.
	dek, kmsProviders, err := utils.GetDek(ctx, providerName, _keyVaultNamespace)
	if err != nil {
		log.Fatalf("Failed to initialize the data key: %v", err)
	}
	fmt.Printf("DEK created/retrieved for the tenant: %s\n", providerName)

	// Initialize the client configured for automatic encryption/decryption.
	//
	// We cannot re-configure auto-encryption options on an already connected client; so we need to
	// create a new one. When creating a new client, we provide the schemaMap that defines how
	// fields should be encrypted; and the DEK to use for encryption/decryption. The client will
	// automatically encrypt the fields based on the schemaMap.
	//
	// bson.M{
	// 		"bsonType": "object",
	// 		"properties": bson.M{
	// 			"ssn": bson.M{
	// 				"encrypt": bson.M{
	// 					// keyId expects an array of DEK UUIDs
	// 					"keyId":    bson.A{dek},
	// 					"bsonType": "string",
	// 					// Deterministic for equality queries
	// 					"algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic",
	// 				},
	// 			},
	// 			// "email" and "name" are not encrypted
	// 		},
	// 	},
	//
	// One limitation with this approach is; since every client needs to be configured with a DEK
	// against the coordinating field, we need to initialize a MongoDB client for each tenant;
	// effectively creating a separate connection pool by tenant. While it consumes more resources
	// (one connection pool per tenant), it provides strong tenant isolation.
	//
	// The other option is to use a single client with a schemaMap that includes all DEKs,
	// but that would require a more complex schemaMap and is not as flexible for multi-tenant
	// scenarios.
	//
	// During the read operations, the driver can decrypt based on the BinData metadata if it has
	// access to the DEK and KMS; however when we have an encrypted field in the filter, the
	// schemaMap explicitly tells the driver which fields are encrypted and how they are encrypted.
	//
	// Bypass auto encryption is set to false, so the driver will automatically encrypt the fields
	encClient, err := utils.NewEncClient(
		ctx, _keyVaultNamespace, getSchemaMap(*dek), kmsProviders, false,
	)
	if err != nil {
		log.Fatalf("Failed to init encrypted write client: %v", err)
	}
	defer encClient.Disconnect(ctx)

	ssn, err := generateRandomSSN()
	if err != nil {
		log.Fatalf("Failed to generate random SSN: %v", err)
	}

	email := fmt.Sprintf("%s@example.com", ssn)

	// Write with encryption. The driver will automatically encrypt the 'ssn' field based on the
	// schemaMap.
	doc := bson.M{"name": "Bob", "email": email, "ssn": ssn}
	if err := insertUser(ctx, encClient, doc); err != nil {
		log.Fatalf("Insert failed: %v", err)
	}

	fmt.Println("Inserted user with encrypted SSN (automatic encryption by driver).")

	// Read with the encrypted client. The driver will automatically decrypt the 'ssn' field used
	// in the filter based on the schemaMap; and any encrypted fields in the result, will be
	// automatically decrypted.
	filter := bson.M{"ssn": ssn}
	if rs, err := readUser(ctx, encClient, filter); err != nil {
		log.Fatalf("Read failed: %v", err)
	} else {
		fmt.Printf("Read by %s and the decrypted result: %v\n", ssn, rs)
	}

	// Read with a regular client. The driver will not automatically decrypt the 'ssn' field,
	// so it will return the encrypted value.
	client, err := newClient(ctx)
	if err != nil {
		log.Fatalf("Failed to create regular client: %v", err)
	}
	defer client.Disconnect(ctx)

	// Using a regular client to read the encrypted data with a cleartext filter. This will return
	// the encrypted fields as it is. This is similar to how a downstream service would get the
	// data via CDC.
	filter = bson.M{"email": email}
	if rs, err := readUser(ctx, client, filter); err != nil {
		log.Fatalf("Read failed: %v", err)
	} else {
		fmt.Printf("Read by %s and the results: %v\n", email, rs)
		// CSFLE does not natively add document-level metadata to indicate which fields are
		// encrypted. This means we need to look at each field to determine if it is encrypted or
		// keep some metadata outside the document.
		//
		// This is a deliberate design choice, rooted in the "client-side" nature of CSFLE. The
		// MongoDB server is designed to be "encryption-agnostic" with CSFLE. It receives and stores
		// BinData blobs without knowing or caring that they are encrypted. Adding explicit metadata
		// on the document would break this principle and give the server knowledge about the
		// encryption scheme.
		ssnEncrypted := rs["ssn"].(primitive.Binary)
		fmt.Printf("SSN (encrypted): %v\n", ssnEncrypted)

		// We need to explicitly decrypt the 'ssn' field in the results. To decrypt the SSN we need
		// access to the KMS and the Atlas collection which stores the DEKs. This can be wrapped by
		// the Cellarman service, so the downstream services do not need access to MongoDB or the KMS
		// providers.
		decryptedSSN, err := decryptBinaryValue(ctx, client, kmsProviders, ssnEncrypted)
		if err != nil {
			log.Fatalf("Failed to decrypt SSN: %v", err)
		}
		fmt.Printf("SSN (decrypted): %v\n", decryptedSSN)
	}

	// Read with an encrypted client with no schemaMap. A schemaMap is not required here for the
	// read, because there are no encrypted fields in the filter.
	encClientWithNoSchema, err := newClientWithAutoEncryptionWithNoSchemaMap(ctx, kmsProviders)
	if err != nil {
		log.Fatalf("Failed to create regular client: %v", err)
	}
	defer encClientWithNoSchema.Disconnect(ctx)

	// Using an encrypted client with no schemaMap to read the encrypted data with a cleartext
	// filter. This will return the encrypted fields in cleartext with automatic decryption.
	filter = bson.M{"email": email}
	if rs, err := readUser(ctx, encClientWithNoSchema, filter); err != nil {
		log.Fatalf("Read failed: %v", err)
	} else {
		fmt.Printf("Read by %s and the decrypted result: %v\n", email, rs)
	}

	// No schemaMap and encrypted field as part of the filter. This will not work as the
	// driver does not know how to encrypt the 'ssn' field without a schemaMap. The look up will
	// happen with the encrypted value itself, and will not find any matching documents.
	filter = bson.M{"ssn": ssn}
	if rs, err := readUser(ctx, encClientWithNoSchema, filter); err != nil {
		log.Fatalf("Read failed: %v", err)
	} else {
		fmt.Printf("Read by %s and the decrypted result: %v\n", ssn, rs)
	}
}

func decryptBinaryValue(
	ctx context.Context,
	keyVaultClient *mongo.Client,
	providers map[string]map[string]interface{},
	encryptedValue primitive.Binary,
) (interface{}, error) {
	if len(encryptedValue.Data) == 0 {
		return nil, errors.New("encrypted value is empty or nil")
	}

	clientEnc, err := mongo.NewClientEncryption(keyVaultClient,
		options.ClientEncryption().
			SetKeyVaultNamespace(_keyVaultNamespace).
			SetKmsProviders(providers),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create client encryption: %v", err)
	}
	defer clientEnc.Close(ctx)

	// The ClientEncryption.Decrypt method automatically handles looking up the DEK
	// based on the metadata embedded within the primitive.Binary (BinData) value. The driver will
	// use a per-connection cache to avoid repeated lookups.
	decryptedValue, err := clientEnc.Decrypt(ctx, encryptedValue)
	if err != nil {
		return nil, fmt.Errorf("failed to explicitly decrypt the value: %w", err)
	}
	return decryptedValue, nil
}

func getSchemaMap(dek primitive.Binary) bson.M {
	// Define the JSON Schema for automatic encryption. The 'ssn' field will be deterministically
	// encrypted using the provided DEK.
	return bson.M{
		_databaseName + "." + _collectionName: bson.M{
			"bsonType": "object",
			"properties": bson.M{
				"ssn": bson.M{
					"encrypt": bson.M{
						// keyId expects an array of DEK UUIDs
						"keyId":    bson.A{dek},
						"bsonType": "string",
						// Deterministic for equality queries
						"algorithm": "AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic",
					},
				},
				// "email" and "name" are not encrypted
			},
		},
	}
}

func newClient(ctx context.Context) (*mongo.Client, error) {
	uri := os.Getenv("MONGODB_URI")
	if uri == "" {
		return nil, fmt.Errorf("MONGODB_URI environment variable is not set")
	}
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		return nil, fmt.Errorf("client failed to connect: %w", err)
	}
	return client, nil
}

func newClientWithAutoEncryptionWithNoSchemaMap(
	ctx context.Context, providers map[string]map[string]interface{},
) (*mongo.Client, error) {
	uri := os.Getenv("MONGODB_URI")
	if uri == "" {
		return nil, fmt.Errorf("MONGODB_URI environment variable is not set")
	}
	autoEncryptionOpts := options.AutoEncryption().
		SetKeyVaultNamespace(_keyVaultNamespace).
		SetKmsProviders(providers)

	return mongo.Connect(ctx, options.Client().
		ApplyURI(uri).
		SetAutoEncryptionOptions(autoEncryptionOpts),
	)
}

func insertUser(ctx context.Context, client *mongo.Client, doc bson.M) error {
	users := client.Database(_databaseName).Collection(_collectionName)
	_, err := users.InsertOne(ctx, doc)
	return err
}

func readUser(ctx context.Context, client *mongo.Client, filter bson.M) (bson.M, error) {
	users := client.Database(_databaseName).Collection(_collectionName)
	var result bson.M
	if err := users.FindOne(ctx, filter).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

func generateRandomSSN() (string, error) {
	var ssnBytes [3]byte
	if _, err := rand.Read(ssnBytes[:]); err != nil {
		return "", fmt.Errorf("failed to generate random SSN bytes: %w", err)
	}

	area := 100 + int(ssnBytes[0])%900 // 100–999 (avoid 000)
	group := 10 + int(ssnBytes[1])%90  // 10–99  (avoid 00)
	serial := int(ssnBytes[2]) % 10000 // 0000–9999

	return fmt.Sprintf("%03d-%02d-%04d", area, group, serial), nil
}
