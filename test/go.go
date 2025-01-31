package main

import "github.com/ethereum/go-ethereum/core/types"
import "github.com/ethereum/go-ethereum/common"
import "github.com/ethereum/go-ethereum/crypto"
import (
	"math/big"
	"crypto/ecdsa"
	"fmt"
	"encoding/hex"
	"encoding/json"
)
func main(){
	b := []byte("gogo")
	SignTxn("", "", b, 10, 1, 10, 10, )
}

func SignTxn(from string, _to string, data []byte, nonce uint64, value int64, gas *big.Int, gasPrice *big.Int, privkey *ecdsa.PrivateKey) (*GethTxn, error) {

  var parsed_tx = new(GethTxn)
  var amount = big.NewInt(value)
  var bytesto [20]byte
  _bytesto, _ := hex.DecodeString(_to[2:])
  copy(bytesto[:], _bytesto)
  to := common.Address([20]byte(bytesto))

  signer := types.NewEIP155Signer(nil)
  tx := types.NewTransaction(nonce, to, amount, gas, gasPrice, data)
  signature, _ := crypto.Sign(tx.SigHash(signer).Bytes(), privkey)
  signed_tx, _ := tx.WithSignature(signer, signature)

  json_tx, _ := signed_tx.MarshalJSON()
  _ = json.Unmarshal(json_tx, parsed_tx)
  parsed_tx.From = from
  fmt.Println("data", parsed_tx.Data)
  return parsed_tx, nil
}

type GethTxn struct {
  To   string     `json:"to"`
  From string     `json:"from"`
  Gas string      `json:"gas"`
  GasPrice string `json:"gasPrice"`
  Value string    `json:"value"`
  Data string     `json:"input"`
}


