package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq" // PostgreSQL

	"github.com/gammazero/deque"

	"github.com/rabbitmq/amqp091-go"
	amqp "github.com/rabbitmq/amqp091-go"
)

// Move these to a separate package
const (
	driverName       = "postgres"
	dbHost           = "localhost"
	dbPort           = 5432
	dbUser           = "devdatta"
	dbPassword       = "your-password"
	recordsTableName = "records"
	dbName           = "record_signing"
	queueName        = "record_signing"
	batchSize        = 500
	numKeys          = 100
	numRecords       = 1000
	exchangeName     = "signExchange"
)

var logger *log.Logger

// PostgreSQL Database related code
func connectToDatabase() (*sql.DB, error) {
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s "+
		"password=%s dbname=%s sslmode=disable",
		dbHost, dbPort, dbUser, dbPassword, dbName)

	db, err := sql.Open(driverName, psqlInfo)

	if err != nil {
		return nil, err
	}

	return db, nil
}

// Queue is not concurrency safe, so make it safe
type SafeDeque struct {
	queue *deque.Deque[*ecdsa.PrivateKey]
	mutex sync.Mutex
}

func newSafeDeque() *SafeDeque {
	return &SafeDeque{
		queue: deque.New[*ecdsa.PrivateKey](),
	}
}

func (sd *SafeDeque) PushBack(key *ecdsa.PrivateKey) {
	sd.mutex.Lock()
	defer sd.mutex.Unlock()
	sd.queue.PushBack(key)
	//logger.Printf("PushBack qlen: %d", sd.queue.Len())
}

func (sd *SafeDeque) PopFront() (*ecdsa.PrivateKey, error) {
	sd.mutex.Lock()
	defer sd.mutex.Unlock()
	//logger.Printf("PopFront qlen: %d", sd.queue.Len())

	if sd.queue.Len() == 0 {
		return nil, errors.New("queue is empty")
	}
	key := sd.queue.PopFront()
	return key, nil
}

// Private key generation
func generatePrivateKeys(numKeys uint32) ([]*ecdsa.PrivateKey, error) {
	keys := make([]*ecdsa.PrivateKey, numKeys)

	seed := time.Now().UnixNano()
	rng := rand.New(rand.NewSource(seed))
	curve := elliptic.P256()

	for i := 0; i < len(keys); i++ {
		key, err := ecdsa.GenerateKey(curve, rng)
		if err != nil {
			return nil, err
		}
		keys[i] = key
	}

	return keys, nil
}

func storePrivateKeys(keys []*ecdsa.PrivateKey) (*SafeDeque, error) {
	queue := newSafeDeque()

	for _, key := range keys {
		queue.PushBack(key)
	}

	return queue, nil
}

func popPrivateKey(queue *SafeDeque) (*ecdsa.PrivateKey, error) {
	return queue.PopFront()
}

func pushPrivateKey(queue *SafeDeque, key *ecdsa.PrivateKey) {
	queue.PushBack(key)
}

func verifySignature(publicKey *ecdsa.PublicKey, r, s []byte, message []byte) error {
	rInt := big.Int{}
	sInt := big.Int{}
	rInt.SetBytes(r)
	sInt.SetBytes(s)

	hash := sha256.Sum256(message)

	if !ecdsa.Verify(publicKey, hash[:], &rInt, &sInt) {
		return errors.New("signature verification failed")
	}

	return nil
}

func signRecordData(privateKey *ecdsa.PrivateKey, data []byte) ([]byte, []byte, error) {
	seed := time.Now().UnixNano()
	rng := rand.New(rand.NewSource(seed))

	hash := sha256.Sum256(data)

	r, s, err := ecdsa.Sign(rng, privateKey, hash[:])
	if err != nil {
		return nil, nil, err
	}

	return r.Bytes(), s.Bytes(), nil
}

func testSignature(sk *ecdsa.PrivateKey) {
	// Convert "hello world" to recordData
	recordData := []byte("hello world")
	logger.Printf("Signing Message: %s \n", recordData)

	// Sign the record data
	r, s, err := signRecordData(sk, recordData)
	if err != nil {
		panic(err)
	}
	logger.Printf("Signature: r:'%x' s:'%x' \n", r, s)

	// Generate the public key from the private key
	pk, err := generatePublicKey(sk)
	if err != nil {
		panic(err)
	}

	// Verify the signature
	err = verifySignature(pk, r, s, recordData)

	if err != nil {
		panic(err)
	}

	logger.Println("Signature verified successfully!")
}

func isNonZero(r, s []byte) bool {
	zero := make([]byte, len(r))
	return !bytes.Equal(r, zero) || !bytes.Equal(s, zero)
}

func consumeRecordSigningRequests(delivery amqp091.Delivery, db *sql.DB, queue *SafeDeque, startIndex, endIndex int) {

	key, err := popPrivateKey(queue)
	if err != nil {
		panic(err)
	}

	var wgSign sync.WaitGroup
	for index := startIndex; index < endIndex; index++ {
		wgSign.Add(1)

		go func(index int) {
			defer wgSign.Done()
			//logger.Printf("Signing: index: %v key:%v", index, key)

			record, err := getRecordByID(db, recordsTableName, index)
			if err != nil {
				panic(err)
			}

			if isNonZero(record.R, record.S) {
				logger.Printf("ALREADY signed index: %v r:%x s:%x", index, record.R, record.S)
				return
			}
			r, s, err := signRecordData(key, record.Data)
			if err != nil {
				panic(err)
			}
			//logger.Printf("Signed index:%d Signature: r:'%x' s:'%x \n", index, r, s)
			logger.Printf("Signed index:%v", index)

			/*
				pk, err := generatePublicKey(key)
				if err != nil {
					panic(err)
				}

				err = verifySignature(pk, r, s, record.Data)
				if err != nil {
					panic(err)
				}
			*/
			// Store the signature in the database.
			stmt, err := db.Prepare(fmt.Sprintf("INSERT INTO %s (id, r, s) VALUES ($1, $2, $3) ON CONFLICT (id) DO UPDATE SET r = EXCLUDED.r, s = EXCLUDED.s", recordsTableName))
			if err != nil {
				panic(err)
			}
			defer stmt.Close()

			recordID := index

			_, err = stmt.Exec(recordID, r, s)
			if err != nil {
				panic(err)
			}
		}(index)
	}

	logger.Printf("consumeRecordSigningRequests: waiting for wgSign startIndex: %v endIndex: %v", startIndex, endIndex)

	wgSign.Wait()

	logger.Printf("DONE consumeRecordSigningRequests: wgSign startIndex: %v endIndex: %v", startIndex, endIndex)

	pushPrivateKey(queue, key)

	// Acknowledge the delivery.
	//delivery.Ack(false)
}

func generatePublicKey(privateKey *ecdsa.PrivateKey) (*ecdsa.PublicKey, error) {
	pubKey, ok := privateKey.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("failed to convert public key to *ecdsa.PublicKey")
	}
	return pubKey, nil
}

func printDatabaseRecords(db *sql.DB, recordsTableName string) {
	rows, err := db.Query(fmt.Sprintf("SELECT id, data, r, s FROM %s", recordsTableName))
	if err != nil {
		panic(err)
	}
	defer rows.Close()

	for rows.Next() {
		var id int
		var data, r, s []byte

		err := rows.Scan(&id, &data, &r, &s)
		if err != nil {
			panic(err)
		}

		logger.Printf("record ID: %d", id)
		//logger.Printf("Data: %x", data)
		logger.Printf("R: %x", r)
		logger.Printf("S: %x", s)
	}

	err = rows.Err()
	if err != nil {
		panic(err)
	}
}

type Record struct {
	ID   int
	Data []byte
	R    []byte
	S    []byte
}

func getRecordByID(db *sql.DB, recordsTableName string, id int) (*Record, error) {
	query := fmt.Sprintf("SELECT id, data, r, s FROM %s WHERE id = $1", recordsTableName)

	row := db.QueryRow(query, id)

	var record Record
	err := row.Scan(&record.ID, &record.Data, &record.R, &record.S)
	if err != nil {
		if err == sql.ErrNoRows {
			// Handle the case where the record with the specified ID is not found
			return nil, fmt.Errorf("record not found")
		}
		return nil, err
	}

	return &record, nil
}

// deserializeBatchIndices deserializes the byte array into start and end indices
func deserializeBatchIndices(byteArr []byte) (int, int) {
	batchIndices := strings.Split(string(byteArr), ":")
	startIndex, _ := strconv.Atoi(batchIndices[0])
	endIndex, _ := strconv.Atoi(batchIndices[1])

	return startIndex, endIndex
}

func main() {

	// Define a CLI flag for enabling or disabling logging
	enableLogging := flag.Bool("log", true, "Enable logging")
	flag.Parse()

	// Create a logger based on the CLI flag
	if *enableLogging {
		logger = log.New(os.Stdout, "", log.LstdFlags)
	} else {
		logger = log.New(ioutil.Discard, "", 0)
	}

	if numKeys*batchSize < numRecords {
		log.Fatalf("Keys will get rolled : numKeys:%d * batchSize:%d < numRecords:%d", numKeys, batchSize, numRecords)
	}

	keys, err := generatePrivateKeys(numKeys)
	if err != nil {
		panic(err)
	}

	queue, err := storePrivateKeys(keys)
	if err != nil {
		panic(err)
	}

	db, err := connectToDatabase()
	if err != nil {
		panic(err)
	}

	// Create a new RabbitMQ connection.
	conn, err := amqp.Dial("amqp://localhost:5672")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// Create a new RabbitMQ channel.
	ch, err := conn.Channel()
	if err != nil {
		panic(err)
	}
	defer ch.Close()

	// Declare the exchange
	err = ch.ExchangeDeclare(
		exchangeName, // exchange name
		"direct",     // exchange type
		true,         // durable
		false,        // auto-delete
		false,        // internal
		false,        // no-wait
		nil,          // arguments
	)
	if err != nil {
		logger.Fatalf("Failed to declare the exchange: %v", err)
	}

	// Create a queue for the record signing requests.
	_, err = ch.QueueDeclare(queueName,
		false, // Durable
		false, // Delete when unused
		false, // Exclusive
		false, // No-wait
		nil,   // Arguments
	)

	if err != nil {
		panic(err)
	} else {
		logger.Println("Queue declared successfully")
	}

	// Bind the queue to the exchange
	err = ch.QueueBind(
		queueName,    // queue name
		queueName,    // routing key
		exchangeName, // exchange name
		false,        // no-wait
		nil,          // arguments
	)
	if err != nil {
		logger.Fatalf("Failed to bind the queue to the exchange: %v", err)
	} else {
		logger.Println("Queue bound successfully")
	}

	// Create a consumer for the record signing requests.
	deliveryChannel, err := ch.Consume(queueName, "",
		true,         // autoAck
		false,        // exclusive
		false,        // noLocal
		false,        // noWait
		amqp.Table{}, // args (empty amqp.Table)
	)

	if err != nil {
		panic(err)
	} else {
		logger.Println("Consumer created successfully")
	}

	//printDatabaseRecords(db, recordsTableName)
	//time.Sleep(1000000)

	logger.Printf("start deliveryChannel\n")

	for {
		var signWG sync.WaitGroup
		var deliveryWG sync.WaitGroup

		totalRecords := 0
		numDelivery := 0

		callback := func(delivery amqp091.Delivery) {
			numDelivery++

			startIndex, endIndex := deserializeBatchIndices(delivery.Body)
			//logger.Printf("startIndex: %v endIndex: %v", startIndex, endIndex)

			signWG.Add(1)
			go func(delivery amqp091.Delivery) {
				defer signWG.Done()
				consumeRecordSigningRequests(delivery, db, queue, startIndex, endIndex)
			}(delivery)

			totalRecords += endIndex - startIndex
			logger.Printf("DONE Delivery# %v totalRecords: %v startIndex: %v endIndex: %v", numDelivery, totalRecords, startIndex, endIndex)
		}

		deliveryWG.Add(1)
		go func() {
			defer deliveryWG.Done()

			for delivery := range deliveryChannel {
				go callback(delivery)
			}

		}()

		//printDatabaseRecords(db, recordsTableName)
		logger.Printf("------- BLOCK deliveryWG %v", totalRecords)
		deliveryWG.Wait()

		if totalRecords == 0 {
			break
		}
		logger.Printf("========= DONE deliveryWG %v", totalRecords)
	}

}
