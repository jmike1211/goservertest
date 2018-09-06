package httpModel

import (
	"iMediCS/crypto"
	"net/http"
)

func Test(res http.ResponseWriter, req *http.Request){
	res.Header().Add("Access-Control-Allow-Origin","*")
	res.Write([]byte("123"))
}

func KeyStoreProduct(res http.ResponseWriter, req *http.Request){
	res.Header().Add("Access-Control-Allow-Origin","*")
	res.Write([]byte(crypto.KeyStoreOut()))
}

