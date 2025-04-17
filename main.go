package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
)

type Block struct {
	Index         int    `json:"index"`
	Timestamp     string `json:"timestamp"`
	Data1         string `json:"data1"`
	Data2         string `json:"data2"`
	Data3         string `json:"data3"`
	Sig1          string `json:"sig1"`
	Sig2          string `json:"sig2"`
	Sig3          string `json:"sig3"`
	PrevHash      string `json:"prev_hash"`
	Hash          string `json:"hash"`
	HashSignature string `json:"hash_signature"`
}

var db *sql.DB
var privateKey *ecdsa.PrivateKey
var publicKey ecdsa.PublicKey

func saveKeys() {
	privBytes, _ := x509.MarshalECPrivateKey(privateKey)
	_ = os.WriteFile("private.pem", privBytes, 0600)

	pubBytes, _ := x509.MarshalPKIXPublicKey(&publicKey)
	_ = os.WriteFile("public.pem", pubBytes, 0644)
}

func loadKeys() error {
	privData, err := os.ReadFile("private.pem")
	if err != nil {
		return err
	}
	privKey, err := x509.ParseECPrivateKey(privData)
	if err != nil {
		return err
	}
	privateKey = privKey
	publicKey = privateKey.PublicKey
	return nil
}

func initKeys() {
	if err := loadKeys(); err == nil {
		return
	}
	var err error
	privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal("Error generating key:", err)
	}
	publicKey = privateKey.PublicKey
	saveKeys()
}

func signData(data string) string {
	h := sha256.Sum256([]byte(data))
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, h[:])
	if err != nil {
		log.Fatal("Sign error:", err)
	}
	sig := append(r.Bytes(), s.Bytes()...)
	return hex.EncodeToString(sig)
}

func verifySignature(data, signature string, isHash bool) bool {
	sigBytes, err := hex.DecodeString(signature)
	if err != nil || len(sigBytes) != 64 {
		return false
	}
	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])
	var dataHash []byte
	if isHash {
		dataHash, _ = hex.DecodeString(data)
	} else {
		h := sha256.Sum256([]byte(data))
		dataHash = h[:]
	}
	return ecdsa.Verify(&publicKey, dataHash, r, s)
}

func signHash(hash string) string {
	hashBytes, _ := hex.DecodeString(hash)
	r, s, _ := ecdsa.Sign(rand.Reader, privateKey, hashBytes)
	sig := append(r.Bytes(), s.Bytes()...)
	return hex.EncodeToString(sig)
}

func calculateHash(b Block) string {
	record := fmt.Sprintf("%d%s%s%s%s%s%s%s%s",
		b.Index, b.Timestamp,
		b.Data1, b.Sig1,
		b.Data2, b.Sig2,
		b.Data3, b.Sig3,
		b.PrevHash,
	)
	h := sha256.Sum256([]byte(record))
	return hex.EncodeToString(h[:])
}

func createBlock(prev Block, d1, d2, d3 string) Block {
	sig1 := signData(d1)
	sig2 := signData(d2)
	sig3 := signData(d3)

	b := Block{
		Index:     prev.Index + 1,
		Timestamp: time.Now().Format(time.RFC3339),
		Data1:     d1,
		Data2:     d2,
		Data3:     d3,
		Sig1:      sig1,
		Sig2:      sig2,
		Sig3:      sig3,
		PrevHash:  prev.Hash,
	}
	b.Hash = calculateHash(b)
	b.HashSignature = signHash(b.Hash)
	return b
}

func initializeDB() {
	var err error
	db, err = sql.Open("postgres", "user=postgres password=0000 dbname=blockchain-db sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS blocks (
			index SERIAL PRIMARY KEY,
			timestamp TEXT,
			data1 TEXT, data2 TEXT, data3 TEXT,
			sig1 TEXT, sig2 TEXT, sig3 TEXT,
			prev_hash TEXT, hash TEXT UNIQUE, hash_signature TEXT
		)
	`)
	if err != nil {
		log.Fatal(err)
	}
}

func addBlockToDB(b Block) {
	_, err := db.Exec(`INSERT INTO blocks (timestamp, data1, data2, data3, sig1, sig2, sig3, prev_hash, hash, hash_signature)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		b.Timestamp, b.Data1, b.Data2, b.Data3, b.Sig1, b.Sig2, b.Sig3, b.PrevHash, b.Hash, b.HashSignature)
	if err != nil {
		log.Fatal(err)
	}
}

func getLastBlock() (Block, error) {
	var b Block
	row := db.QueryRow("SELECT index, timestamp, data1, data2, data3, sig1, sig2, sig3, prev_hash, hash, hash_signature FROM blocks ORDER BY index DESC LIMIT 1")
	err := row.Scan(&b.Index, &b.Timestamp, &b.Data1, &b.Data2, &b.Data3, &b.Sig1, &b.Sig2, &b.Sig3, &b.PrevHash, &b.Hash, &b.HashSignature)
	if errors.Is(err, sql.ErrNoRows) {
		return Block{Index: -1}, nil
	}
	return b, err
}

func addBlock(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Data1 string `json:"data1"`
		Data2 string `json:"data2"`
		Data3 string `json:"data3"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	prev, err := getLastBlock()
	if err != nil {
		http.Error(w, "Can't get last block", 500)
		return
	}
	if prev.Index == -1 {
		prev = createBlock(Block{Index: 0}, "Init1", "Init2", "Init3")
		addBlockToDB(prev)
	}
	block := createBlock(prev, req.Data1, req.Data2, req.Data3)
	addBlockToDB(block)
	json.NewEncoder(w).Encode(block)
}

func getBlockchain(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT index, timestamp, data1, data2, data3, sig1, sig2, sig3, prev_hash, hash, hash_signature FROM blocks ORDER BY index")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()
	var chain []Block
	for rows.Next() {
		var b Block
		rows.Scan(&b.Index, &b.Timestamp, &b.Data1, &b.Data2, &b.Data3, &b.Sig1, &b.Sig2, &b.Sig3, &b.PrevHash, &b.Hash, &b.HashSignature)
		chain = append(chain, b)
	}
	json.NewEncoder(w).Encode(chain)
}

func verifyBlockchain(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT index, timestamp, data1, data2, data3, sig1, sig2, sig3, prev_hash, hash, hash_signature FROM blocks ORDER BY index")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()
	var prevHash string
	for rows.Next() {
		var b Block
		err := rows.Scan(&b.Index, &b.Timestamp, &b.Data1, &b.Data2, &b.Data3, &b.Sig1, &b.Sig2, &b.Sig3, &b.PrevHash, &b.Hash, &b.HashSignature)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if b.PrevHash != prevHash && b.Index != 0 {
			http.Error(w, fmt.Sprintf("Invalid prev_hash at block %d", b.Index), 500)
			return
		}
		if !verifySignature(b.Data1, b.Sig1, false) || !verifySignature(b.Data2, b.Sig2, false) || !verifySignature(b.Data3, b.Sig3, false) {
			http.Error(w, fmt.Sprintf("Invalid data signature at block %d", b.Index), 500)
			return
		}
		if !verifySignature(b.Hash, b.HashSignature, true) {
			http.Error(w, fmt.Sprintf("Invalid hash signature at block %d", b.Index), 500)
			return
		}
		prevHash = b.Hash
	}
	w.Write([]byte("Blockchain is valid"))
}

func getBlockByIndex(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	index := vars["index"]
	var block Block
	row := db.QueryRow("SELECT index, timestamp, data1, data2, data3, sig1, sig2, sig3, prev_hash, hash, hash_signature FROM blocks WHERE index = $1", index)
	if err := row.Scan(&block.Index, &block.Timestamp, &block.Data1, &block.Data2, &block.Data3, &block.Sig1, &block.Sig2, &block.Sig3, &block.PrevHash, &block.Hash, &block.HashSignature); err != nil {
		http.Error(w, "Block not found", http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(block)
}

func verifyBlock(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	index := vars["index"]
	var block Block
	row := db.QueryRow("SELECT index, timestamp, data1, data2, data3, sig1, sig2, sig3, prev_hash, hash, hash_signature FROM blocks WHERE index = $1", index)
	if err := row.Scan(&block.Index, &block.Timestamp, &block.Data1, &block.Data2, &block.Data3, &block.Sig1, &block.Sig2, &block.Sig3, &block.PrevHash, &block.Hash, &block.HashSignature); err != nil {
		http.Error(w, "Block not found", http.StatusNotFound)
		return
	}

	if !verifySignature(block.Data1, block.Sig1, false) {
		http.Error(w, "Invalid Data1 signature", http.StatusInternalServerError)
		return
	}
	if !verifySignature(block.Data2, block.Sig2, false) {
		http.Error(w, "Invalid Data2 signature", http.StatusInternalServerError)
		return
	}
	if !verifySignature(block.Data3, block.Sig3, false) {
		http.Error(w, "Invalid Data3 signature", http.StatusInternalServerError)
		return
	}
	if !verifySignature(block.Hash, block.HashSignature, true) {
		http.Error(w, "Invalid hash signature", http.StatusInternalServerError)
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
	r.HandleFunc("/verify", verifyBlockchain).Methods("GET")
	r.HandleFunc("/blocks/{index}", getBlockByIndex).Methods("GET")
	r.HandleFunc("/blocks/{index}/verify", verifyBlock).Methods("GET")
	log.Println("Server started at :8080")
	http.ListenAndServe(":8080", r)
}
