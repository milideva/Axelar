package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"strconv"
	"strings"

	_ "github.com/lib/pq"

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
	signatureTable   = "signatures"
	dbName           = "record_signing"
	queueName        = "record_signing"
	batchSize        = 500
	numKeys          = 100
	numRecords       = 1000
	exchangeName     = "signExchange"
)

var logger *log.Logger

func printData64(data []byte) {
	for i := 0; i < len(data); i += 64 {
		logger.Printf("printData64[%d]:%x\n", i, data[i:i+64])
	}
}

func randomData() []byte {
	data := make([]byte, 1024)
	rand.Read(data)
	return data
}

// Inserts random data into the database table
func seedDatabaseRecords(db *sql.DB, recordsTableName string) {
	r := []byte{0} // Convert integer 0 to []byte
	s := []byte{0} // Convert integer 0 to []byte
	for i := 1; i <= numRecords; i++ {
		data := randomData()
		//printData64(data)
		_, err := db.Exec(fmt.Sprintf("INSERT INTO %s (id, data, r, s) VALUES ($1, $2, $3, $4)", recordsTableName), i, data, r, s)

		if err != nil {
			panic(err)
		}
	}
}

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

func createRecordsTable(db *sql.DB, recordsTableName string) error {

	query := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
		id SERIAL PRIMARY KEY,
		data BYTEA,
		r BYTEA,
		s BYTEA
	)`, recordsTableName)

	_, err := db.Exec(query)
	if err != nil {
		return err
	}

	return nil
}

func truncateTable(db *sql.DB, tableName string) error {
	_, err := db.Exec(fmt.Sprintf("TRUNCATE TABLE %s", tableName))
	return err
}

func deleteDatabase(db *sql.DB, databaseName string) error {
	_, err := db.Exec(fmt.Sprintf("DROP DATABASE IF EXISTS %s", databaseName))
	return err
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

// serializeBatchIndices serializes the start and end indices into a byte array
func serializeBatchIndices(startIndex, endIndex int) []byte {
	startIndexBytes := []byte(strconv.Itoa(startIndex))
	endIndexBytes := []byte(strconv.Itoa(endIndex))

	return append(startIndexBytes, append([]byte{':'}, endIndexBytes...)...)
}

// deserializeBatchIndices deserializes the byte array into start and end indices
func deserializeBatchIndices(byteArr []byte) (int, int) {
	batchIndices := strings.Split(string(byteArr), ":")
	startIndex, _ := strconv.Atoi(batchIndices[0])
	endIndex, _ := strconv.Atoi(batchIndices[1])

	return startIndex, endIndex
}

func main() {

	if numKeys*batchSize < numRecords {
		log.Fatalf("Keys will get rolled : numKeys:%d * batchSize:%d < numRecords:%d", numKeys, batchSize, numRecords)
	}

	// Define a CLI flag for enabling or disabling logging
	enableLogging := flag.Bool("log", true, "Enable logging")
	flag.Parse()

	// Create a logger based on the CLI flag
	if *enableLogging {
		logger = log.New(os.Stdout, "", log.LstdFlags)
	} else {
		logger = log.New(ioutil.Discard, "", 0)
	}

	db, err := connectToDatabase()
	if err != nil {
		panic(err)
	}
	defer db.Close()

	// Clean up Database for testing
	err = deleteDatabase(db, recordsTableName)
	if err != nil {
		panic(err)
	}

	// Clean up records Table from previous run
	err = truncateTable(db, recordsTableName)
	if err != nil {
		panic(err)
	}

	err = createRecordsTable(db, recordsTableName)
	if err != nil {
		panic(err)
	}

	// Seed the records in the Database
	seedDatabaseRecords(db, recordsTableName)

	//printDatabaseRecords(db, recordsTableName)

	// Create a new RabbitMQ connection.
	conn, err := amqp.Dial("amqp://localhost:5672")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// Create a new channel.
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
		log.Fatalf("Failed to declare the exchange: %v", err)
	}

	_, err = ch.QueueDelete(queueName, false, false, false)
	if err != nil {
		log.Fatalf("Failed to delete queue: %v", err)
	} else {
		//log.Println("Queue deleted successfully")
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
		log.Fatalf("Failed to bind the queue to the exchange: %v", err)
	}

	numBatches := (numRecords + batchSize - 1) / batchSize

	for i := 0; i < numBatches; i++ {
		startIndex := i*batchSize + 1
		endIndex := (i+1)*batchSize + 1
		if (i+1)*batchSize > numRecords {
			endIndex = numRecords
		}
		logger.Printf("Sending batch#%d startIndex: %d endIndex: %d\n", i, startIndex, endIndex)

		err = ch.PublishWithContext(
			context.Background(),
			exchangeName, // exchange name
			queueName,    // routing key
			false,        // mandatory
			false,        // immediate
			amqp.Publishing{
				ContentType: "text/plain",
				Body:        serializeBatchIndices(startIndex, endIndex),
			},
		)
		if err != nil {
			log.Fatalf("Failed to publish message: %v", err)
		}
	}
	log.Printf("#Records:%d #Batches:%d sent to the exchange, batchSize:%d", numRecords, numBatches, batchSize)
}
