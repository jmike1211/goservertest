package httpRouter

import (
	"net/http"
	"iMediCS/httpModel"
)

func Router(){
	http.HandleFunc("/keyStore", httpModel.KeyStoreProduct)
	http.HandleFunc("/test", httpModel.Test)
}
