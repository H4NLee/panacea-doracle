package service

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"

	"github.com/btcsuite/btcd/btcec"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"github.com/medibloc/panacea-doracle/crypto"
	"github.com/medibloc/panacea-doracle/validation"
)

type SellDataReq struct {
	SellerAddress string `json:"seller_address"`
	DealID        uint64 `json:"deal_id"`
	VerifiableCID string `json:"verifiable_cid"`
	DataHash      string `json:"data_hash"`
}

type SellDataResp struct {
	DeliveredCID    string `json:"delivered_cid"`
	SignatureBase64 string `json:"signature_base64"`
}

type Msg struct {
	SellerAddress string `json:"seller_address"`
	DealID        uint64 `json:"deal_id"`
	VerifiableCID string `json:"verifiable_cid"`
	DataHash      string `json:"data_hash"`
	DeliveredCID  string `json:"delivered_cid"`
}

func (s *Service) ValidateData(w http.ResponseWriter, r *http.Request) {
	// ***************** 1. validate data *****************
	var reqBody SellDataReq

	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
	defer r.Body.Close()

	queryClient := s.QueryClient()

	deal, err := queryClient.GetDeal(reqBody.DealID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}

	encryptedDataBz, err := s.Ipfs().Get(reqBody.VerifiableCID)
	if err != nil {
		http.Error(w, "wrong cid", http.StatusBadRequest)
	}

	sellerAcc, err := queryClient.GetAccount(reqBody.SellerAddress)
	if err != nil {
		http.Error(w, "wrong seller address", http.StatusBadRequest)
	}
	sellerPubKeyBytes := sellerAcc.GetPubKey().Bytes()

	oraclePrivKey := s.OraclePrivKey()

	sellerPubKey, err := btcec.ParsePubKey(sellerPubKeyBytes, btcec.S256())
	if err != nil {
		http.Error(w, "wrong seller pub key", http.StatusBadRequest)
	}

	decryptSharedKey := crypto.DeriveSharedKey(oraclePrivKey, sellerPubKey, crypto.KDFSHA256)

	decryptedData, err := crypto.DecryptWithAES256(decryptSharedKey, deal.Nonce, encryptedDataBz)
	if err != nil {
		http.Error(w, "fail to decrypt", http.StatusBadRequest)
	}

	if !compareDataHash(reqBody.DataHash, decryptedData) {
		http.Error(w, "hash mismatch", http.StatusBadRequest)
	}

	if err := validation.ValidateJSONSchemata(decryptedData, deal.DataSchema); err != nil {
		http.Error(w, "invalid data schema", http.StatusBadRequest)
	}

	// ***************** 2. re-encrypt data *****************

	buyerAccount, err := queryClient.GetAccount(deal.BuyerAddress)
	if err != nil {
		http.Error(w, "wrong buyer", http.StatusInternalServerError)
	}

	buyerPubKeyBytes := buyerAccount.GetPubKey().Bytes()
	buyerPubKey, err := btcec.ParsePubKey(buyerPubKeyBytes, btcec.S256())
	if err != nil {
		http.Error(w, "wrong buyer pub key", http.StatusInternalServerError)
	}

	encryptSharedKey := crypto.DeriveSharedKey(oraclePrivKey, buyerPubKey, crypto.KDFSHA256)

	encryptDataWithBuyerKey, err := crypto.EncryptWithAES256(encryptSharedKey, deal.Nonce, decryptedData)
	if err != nil {
		http.Error(w, "failed to encrypt data", http.StatusInternalServerError)
	}

	// ipfs.add (decrypted data) & get CID
	deliveredCid, err := s.Ipfs().Add(encryptDataWithBuyerKey)
	if err != nil {
		http.Error(w, "failed to store data", http.StatusInternalServerError)
	}

	// ***************** 3. sign *****************
	msg := &Msg{
		SellerAddress: reqBody.SellerAddress,
		DealID:        reqBody.DealID,
		VerifiableCID: reqBody.VerifiableCID,
		DataHash:      reqBody.DataHash,
		DeliveredCID:  deliveredCid,
	}

	key := secp256k1.PrivKey{
		Key: oraclePrivKey.Serialize(),
	}

	marshaledDataDeliveryVote, err := json.Marshal(msg)
	if err != nil {
		http.Error(w, "fail to marshal msg", http.StatusInternalServerError)
	}

	sig, err := key.Sign(marshaledDataDeliveryVote)
	if err != nil {
		http.Error(w, "fail to sign", http.StatusInternalServerError)
	}

	payload := SellDataResp{
		DeliveredCID:    deliveredCid,
		SignatureBase64: base64.StdEncoding.EncodeToString(sig),
	}

	marshaledPayload, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, "fail to marshal payload", http.StatusInternalServerError)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write(marshaledPayload)
}

func compareDataHash(dataHash string, decryptedData []byte) bool {
	decryptedDataHash := sha256.Sum256(decryptedData)
	decryptedDataHashStr := hex.EncodeToString(decryptedDataHash[:])

	return decryptedDataHashStr == dataHash
}
