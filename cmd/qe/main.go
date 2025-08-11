package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/devrev/experimental/prabath/go/enc/utils"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	// This is where the encrypted Data Encryption Keys (DEKs) will be stored in Atlas.
	_keyVaultNamespace = "qe_keyvault.datakeys"
	_databaseName      = "qe_db"
	_collectionName    = "users"
)

func main() {
	ctx := context.Background()

	devOrgID := "don:identity:dvrv-us-1:devo/10"
	providerName, err := utils.GetProviderName(devOrgID)
	if err != nil {
		log.Fatalf("Failed to get provider name for %s: %v", devOrgID, err)
	}

	// Load or create the local master key from the file system.
	localMasterKey, err := utils.LoadOrCreateMasterKey(providerName)
	if err != nil {
		log.Fatalf("Failed to load or create master key for %s: %v", providerName, err)
	}

	// Construct the KMS providers map.
	kmsProviders := map[string]map[string]interface{}{
		providerName: {"key": localMasterKey},
	}

	autoEncryptionOptions := options.AutoEncryption().
		SetKeyVaultNamespace(_keyVaultNamespace).
		SetKmsProviders(kmsProviders)

	uri := os.Getenv("MONGODB_URI")
	if uri == "" {
		log.Fatalf("MONGODB_URI environment variable is not set")
	}

	encryptedClient, err := mongo.Connect(
		ctx,
		options.Client().ApplyURI(uri).SetAutoEncryptionOptions(autoEncryptionOptions),
	)
	if err != nil {
		log.Fatalf("Failed to create encrypted client: %v", err)
	}

	defer encryptedClient.Disconnect(ctx)

	opts := options.ClientEncryption().
		SetKeyVaultNamespace(_keyVaultNamespace).
		SetKmsProviders(kmsProviders)
	clientEncryption, err := mongo.NewClientEncryption(encryptedClient, opts)
	if err != nil {
		log.Fatalf("Failed to create client encryption: %v", err)
	}

	database := encryptedClient.Database(_databaseName)
	filter := bson.D{{Key: "name", Value: _collectionName}}
	collectionNames, err := database.ListCollectionNames(ctx, filter)
	if err != nil {
		log.Fatalf("Failed to list collections: %v", err)
	}

	if len(collectionNames) == 0 {
		encryptedFieldsMap := bson.M{
			"fields": []bson.M{
				{
					"keyId":    nil,
					"path":     "ssn",
					"bsonType": "string",
					"queries": []bson.M{
						{
							"queryType": "equality",
						},
					},
				},
				{
					"keyId":    nil,
					"path":     "age",
					"bsonType": "int",
					"queries": []bson.M{
						{
							"queryType": "range",
							"min":       0,
							"max":       120,
						},
					},
				},
				{
					"keyId":    nil,
					"path":     "email",
					"bsonType": "string",
				},
			},
		}
		createCollectionOptions := options.CreateCollection().SetEncryptedFields(encryptedFieldsMap)
		_, _, err =
			clientEncryption.CreateEncryptedCollection(
				ctx,
				encryptedClient.Database(_databaseName),
				_collectionName,
				createCollectionOptions,
				providerName,
				nil,
			)
		if err != nil {
			log.Fatalf("Failed to create the encrypted collection: %v", err)
		}
	}

	coll := encryptedClient.Database(_databaseName).Collection(_collectionName)

	doc := bson.M{"name": "Bob", "email": "prabath@devrev.ai", "ssn": "987-65-4320", "age": 30}
	_, err = coll.InsertOne(context.TODO(), doc)
	if err != nil {
		log.Fatalf("Unable to insert document: %+v", err)
	}

	var resultEq bson.M
	err = coll.FindOne(ctx, bson.M{"ssn": "987-65-4320"}).Decode(&resultEq)
	if err != nil {
		log.Fatalf("Unable to find the document: %s", err)
	}
	fmt.Printf("Decrypted result for the equality query: %+v\n", resultEq)

	var resultRange bson.M
	err = coll.FindOne(
		ctx,
		bson.M{"age": bson.M{"$gte": 25, "$lte": 35}}).Decode(&resultRange)

	if err != nil {
		log.Fatalf("Unable to find the document: %s", err)
	}

	fmt.Printf("Decrypted result for the range query: %+v\n", resultRange)
}
