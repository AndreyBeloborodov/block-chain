package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
)

type Block struct {
	Index         int    `json:"index"`
	Timestamp     string `json:"timestamp"`
	Data          string `json:"data"`
	DataSignature string `json:"data_signature"`
	PrevHash      string `json:"prev_hash"`
	Hash          string `json:"hash"`
	HashSignature string `json:"hash_signature"`
}

var db *sql.DB
var privateKey *ecdsa.PrivateKey
var publicKey ecdsa.PublicKey

func initKeys() {
	var err error
	privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal("Error generating private key:", err)
	}
	publicKey = privateKey.PublicKey
}

func signData(data string) string {
	h := sha256.Sum256([]byte(data))
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, h[:])
	if err != nil {
		log.Fatal("Error signing data:", err)
	}
	sig := append(r.Bytes(), s.Bytes()...)
	return hex.EncodeToString(sig)
}

func calculateHash(block Block) string {
	record := fmt.Sprintf("%d%s%s%s%s", block.Index, block.Timestamp, block.Data, block.DataSignature, block.PrevHash)
	h := sha256.Sum256([]byte(record))
	return hex.EncodeToString(h[:])
}

func signHash(hash string) string {
	hashBytes, err := hex.DecodeString(hash)
	if err != nil {
		log.Fatal("Error decoding hash before signing:", err)
	}

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashBytes)
	if err != nil {
		log.Fatal("Error signing hash:", err)
	}

	sig := append(r.Bytes(), s.Bytes()...)
	return hex.EncodeToString(sig)
}

func verifySignature(data, signature string, isHash bool) bool {
	log.Println("Verifying data:", data)

	sigBytes, err := hex.DecodeString(signature)
	if err != nil {
		log.Println("Error decoding signature:", err)
		return false
	}

	if len(sigBytes) != 64 {
		log.Println("Invalid signature length:", len(sigBytes))
		return false
	}

	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])

	var dataBytes []byte
	if isHash {
		dataBytes, err = hex.DecodeString(data)
		if err != nil {
			log.Println("Error decoding hash data before verification:", err)
			return false
		}
	} else {
		h := sha256.Sum256([]byte(data))
		dataBytes = h[:]
	}

	valid := ecdsa.Verify(&publicKey, dataBytes, r, s)
	if !valid {
		log.Println("Signature verification failed for data:", data)
	}
	return valid
}

func createBlock(prevBlock Block, data string) Block {
	dataSignature := signData(data)
	newBlock := Block{
		Index:         prevBlock.Index + 1,
		Timestamp:     time.Now().String(),
		Data:          data,
		DataSignature: dataSignature,
		PrevHash:      prevBlock.Hash,
	}
	newBlock.Hash = calculateHash(newBlock)
	newBlock.HashSignature = signHash(newBlock.Hash)
	return newBlock
}

func initializeDB() {
	var err error
	db, err = sql.Open("postgres", "user=postgres password=0000 dbname=blockchain-db sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS blocks (
		index SERIAL PRIMARY KEY,
		timestamp TEXT,
		data TEXT,
		data_signature TEXT,
		prev_hash TEXT,
		hash TEXT UNIQUE,
		hash_signature TEXT
	)`)
	if err != nil {
		log.Fatal(err)
	}
}

func addBlockToDB(block Block) {
	_, err := db.Exec("INSERT INTO blocks (timestamp, data, data_signature, prev_hash, hash, hash_signature) VALUES ($1, $2, $3, $4, $5, $6)", block.Timestamp, block.Data, block.DataSignature, block.PrevHash, block.Hash, block.HashSignature)
	if err != nil {
		log.Fatal(err)
	}
}

func getLastBlock() (Block, error) {
	var block Block
	row := db.QueryRow("SELECT index, timestamp, data, data_signature, prev_hash, hash, hash_signature FROM blocks ORDER BY index DESC LIMIT 1")
	err := row.Scan(&block.Index, &block.Timestamp, &block.Data, &block.DataSignature, &block.PrevHash, &block.Hash, &block.HashSignature)
	if errors.Is(err, sql.ErrNoRows) {
		return Block{Index: -1}, nil
	}
	return block, err
}

func getBlockchain(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT index, timestamp, data, data_signature, prev_hash, hash, hash_signature FROM blocks ORDER BY index")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var blockchain []Block
	for rows.Next() {
		var block Block
		if err := rows.Scan(&block.Index, &block.Timestamp, &block.Data, &block.DataSignature, &block.PrevHash, &block.Hash, &block.HashSignature); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		blockchain = append(blockchain, block)
	}

	json.NewEncoder(w).Encode(blockchain)
}

func getBlockByIndex(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	index := vars["index"]
	var block Block
	row := db.QueryRow("SELECT index, timestamp, data, data_signature, prev_hash, hash, hash_signature FROM blocks WHERE index = $1", index)
	if err := row.Scan(&block.Index, &block.Timestamp, &block.Data, &block.DataSignature, &block.PrevHash, &block.Hash, &block.HashSignature); err != nil {
		http.Error(w, "Block not found", http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(block)
}

func addBlock(w http.ResponseWriter, r *http.Request) {
	var requestData struct {
		Data string `json:"data"`
	}
	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	prevBlock, err := getLastBlock()
	if err != nil {
		http.Error(w, "Failed to retrieve last block", http.StatusInternalServerError)
		return
	}

	if prevBlock.Index == -1 {
		prevBlock = Block{Index: 1, Timestamp: time.Now().String(), Data: "Block 1", PrevHash: ""}
		prevBlock.DataSignature = signData(prevBlock.Data)
		prevBlock.Hash = calculateHash(prevBlock)
		prevBlock.HashSignature = signHash(prevBlock.Hash)
		addBlockToDB(prevBlock)
	}

	newBlock := createBlock(prevBlock, requestData.Data)
	addBlockToDB(newBlock)

	json.NewEncoder(w).Encode(newBlock)
}

func verifyBlockchain(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT index, timestamp, data, data_signature, prev_hash, hash, hash_signature FROM blocks ORDER BY index")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var prevHash string
	for rows.Next() {
		var block Block
		if err := rows.Scan(&block.Index, &block.Timestamp, &block.Data, &block.DataSignature, &block.PrevHash, &block.Hash, &block.HashSignature); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if block.PrevHash != prevHash && block.Index > 0 {
			http.Error(w, fmt.Sprintf("Blockchain integrity error at block %d", block.Index), http.StatusInternalServerError)
			return
		}
		if !verifySignature(block.Data, block.DataSignature, false) {
			http.Error(w, fmt.Sprintf("Invalid data signature at block %d", block.Index), http.StatusInternalServerError)
			return
		}
		if !verifySignature(block.Hash, block.HashSignature, true) {
			http.Error(w, fmt.Sprintf("Invalid hash signature at block %d", block.Index), http.StatusInternalServerError)
			return
		}

		prevHash = block.Hash
	}
	w.Write([]byte("Blockchain is valid"))
}

func verifyBlock(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	index := vars["index"]
	var block Block
	row := db.QueryRow("SELECT index, timestamp, data, data_signature, prev_hash, hash, hash_signature FROM blocks WHERE index = $1", index)
	if err := row.Scan(&block.Index, &block.Timestamp, &block.Data, &block.DataSignature, &block.PrevHash, &block.Hash, &block.HashSignature); err != nil {
		http.Error(w, "Block not found", http.StatusNotFound)
		return
	}

	if !verifySignature(block.Hash, block.HashSignature, true) {
		http.Error(w, "Invalid hash signature", http.StatusInternalServerError)
		return
	}
	if !verifySignature(block.Data, block.DataSignature, false) {
		http.Error(w, "Invalid data signature", http.StatusInternalServerError)
		return
	}

	w.Write([]byte("Block is valid"))
}

func main() {
	initKeys()
	initializeDB()
	r := mux.NewRouter()
	r.HandleFunc("/blocks", getBlockchain).Methods("GET")
	r.HandleFunc("/blocks", addBlock).Methods("POST")
	r.HandleFunc("/blocks/{index}", getBlockByIndex).Methods("GET")
	r.HandleFunc("/blocks/{index}/verify", verifyBlock).Methods("GET")
	r.HandleFunc("/verify", verifyBlockchain).Methods("GET")

	log.Println("Server running on port 8080")
	http.ListenAndServe(":8080", r)
}
