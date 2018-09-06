package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
        "fmt"
	//"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"crypto/rand"
	"crypto/cipher"
	"io"
	"io/ioutil"
        "golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/pbkdf2"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/sha3"
        "github.com/ethereum/go-ethereum/crypto/randentropy"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/common"
	"github.com/pborman/uuid"

)

var (
	ErrDecrypt = errors.New("could not decrypt key with given passphrase")
)

const (
	version = 3
)

/*
func main(){
	key, err:= newKey(rand.Reader)
        //fmt.Println(sa("123", key))
	//if(err != nil){fmt.Println(err)}
	//x,err := readFile("go")
	if err != nil{
		fmt.Println(err.Error())
	}
	fmt.Println(hex.EncodeToString(key.Address[:]))
	fmt.Println(hex.EncodeToString(crypto.FromECDSA(key.PrivateKey)))
	//a,b := DecryptKey(key, "123")
	//fmt.Println(a.PrivateKey.PublicKey)
	//fmt.Println(hex.EncodeToString(a.Address[:]),b)
	//fmt.Println(hex.EncodeToString(crypto.FromECDSA(a.PrivateKey)))
	//d,err := GetBytes(a)
	//m := make(map[string]interface{})

	//if err := json.Unmarshal(d, &m); err != nil {
	//	fmt.Println("err")
	//}
	//fmt.Println(m)
	//sa("123", key)
}
*/


func readFile(filename string) ([]byte, error) {
    bytes, err := ioutil.ReadFile(filename)
	if(err != nil){fmt.Println(err)}
    return bytes, nil
}

func KeyStoreOut()(string){
	key, err:= newKey(rand.Reader)
	if(err != nil){fmt.Println(err)}
	return sa("123", key)
}


const (
	keyHeaderVersion = "1"
	keyHeaderKDF = "scrypt"
	scryptN = 262144
	scryptr = 8
	scryptp = 1
	scryptdklen = 32
)

func sa(auth string, key *Key)(string){
	authArray := []byte(auth)
        salt := randentropy.GetEntropyCSPRNG(32)
        dk, err := scrypt.Key(authArray, salt, 262144, 8, 1, 32)
        if(err != nil){fmt.Println(err)}
	encryptKey := dk[:16]
	keyBytes := math.PaddedBigBytes(key.PrivateKey.D, 32)
	iv := randentropy.GetEntropyCSPRNG(aes.BlockSize)
	cipherText, err := aesCTRXOR(encryptKey, keyBytes, iv)
	mac := crypto.Keccak256(dk[16:32], cipherText)
	scryptParamsJson := scryptParamsJson{
		N: scryptN,
		R: scryptr,
		P: scryptp,
		DkLen: scryptdklen,
		Salt: hex.EncodeToString(salt),
	}
	cipherParamsJson := cipherParamsJson{
		Iv: hex.EncodeToString(iv),

		}
	crytoStructure := crytoStructure{
		Cipher:"aes-128-ctr",
		CipherText:	hex.EncodeToString(cipherText),
		cipherParamsJson:	cipherParamsJson,
		KDF:		"scrypt",
		scryptParamsJson:	scryptParamsJson,
		Mac:		hex.EncodeToString(mac),
	}
	keyStoreStructure := keyStoreStructure{
		Address: hex.EncodeToString(key.Address[:]),
		crytoStructure:crytoStructure,
		Id:key.Id.String(),
		Version:	3,	
	}
	keyResult,err := json.Marshal(keyStoreStructure)
	return string(keyResult)

}

func DecryptKey(keyjson []byte, auth string) (*Key, error) {
	// Parse the json into a simple map to fetch the key version
	m := make(map[string]interface{})
	if err := json.Unmarshal(keyjson, &m); err != nil {
		return nil, err
	}
	// Depending on the version try to parse one way or another
	var (
		keyBytes, keyId []byte
		err             error
	)
	if version, ok := m["version"].(string); ok && version == "1" {
		k := new(encryptedKeyJSONV1)
		if err := json.Unmarshal(keyjson, k); err != nil {
			return nil, err
		}
		//keyBytes, keyId, err = decryptKeyV1(k, auth)
	} else {
		k := new(encryptedKeyJSONV3)
		if err := json.Unmarshal(keyjson, k); err != nil {
			return nil, err
		}
		keyBytes, keyId, err = decryptKeyV3(k, auth)
	}
	// Handle any decryption errors and return the key
	if err != nil {
		return nil, err
	}
	key := crypto.ToECDSAUnsafe(keyBytes)

	return &Key{
		Id:         uuid.UUID(keyId),
		Address:    crypto.PubkeyToAddress(key.PublicKey),
		PrivateKey: key,
	}, nil
}

func decryptKeyV3(keyProtected *encryptedKeyJSONV3, auth string) (keyBytes []byte, keyId []byte, err error) {
	if keyProtected.Version != version {
		return nil, nil, fmt.Errorf("Version not supported: %v", keyProtected.Version)
	}

	if keyProtected.Crypto.Cipher != "aes-128-ctr" {
		return nil, nil, fmt.Errorf("Cipher not supported: %v", keyProtected.Crypto.Cipher)
	}

	keyId = uuid.Parse(keyProtected.Id)
	mac, err := hex.DecodeString(keyProtected.Crypto.MAC)
	if err != nil {
		return nil, nil, err
	}

	iv, err := hex.DecodeString(keyProtected.Crypto.CipherParams.IV)
	if err != nil {
		return nil, nil, err
	}

	cipherText, err := hex.DecodeString(keyProtected.Crypto.CipherText)
	if err != nil {
		return nil, nil, err
	}

	derivedKey, err := getKDFKey(keyProtected.Crypto, auth)
	if err != nil {
		return nil, nil, err
	}

	calculatedMAC := crypto.Keccak256(derivedKey[16:32], cipherText)
	if !bytes.Equal(calculatedMAC, mac) {
		return nil, nil, ErrDecrypt
	}

	plainText, err := aesCTRXOR(derivedKey[:16], cipherText, iv)
	if err != nil {
		return nil, nil, err
	}
	return plainText, keyId, err
}

func ensureInt(x interface{}) int {
	res, ok := x.(int)
	if !ok {
		res = int(x.(float64))
	}
	return res
}

func getKDFKey(cryptoJSON cryptoJSON, auth string) ([]byte, error) {
	authArray := []byte(auth)
	salt, err := hex.DecodeString(cryptoJSON.KDFParams["salt"].(string))
	if err != nil {
		return nil, err
	}
	dkLen := ensureInt(cryptoJSON.KDFParams["dklen"])

	if cryptoJSON.KDF == keyHeaderKDF {
		n := ensureInt(cryptoJSON.KDFParams["n"])
		r := ensureInt(cryptoJSON.KDFParams["r"])
		p := ensureInt(cryptoJSON.KDFParams["p"])
		return scrypt.Key(authArray, salt, n, r, p, dkLen)

	} else if cryptoJSON.KDF == "pbkdf2" {
		c := ensureInt(cryptoJSON.KDFParams["c"])
		prf := cryptoJSON.KDFParams["prf"].(string)
		if prf != "hmac-sha256" {
			return nil, fmt.Errorf("Unsupported PBKDF2 PRF: %s", prf)
		}
		key := pbkdf2.Key(authArray, salt, c, dkLen, sha256.New)
		return key, nil
	}

	return nil, fmt.Errorf("Unsupported KDF: %s", cryptoJSON.KDF)
}
/*
func decryptKeyV1(keyProtected *encryptedKeyJSONV1, auth string) (keyBytes []byte, keyId []byte, err error) {
	keyId = uuid.Parse(keyProtected.Id)
	mac, err := hex.DecodeString(keyProtected.Crypto.MAC)
	if err != nil {
		return nil, nil, err
	}

	iv, err := hex.DecodeString(keyProtected.Crypto.CipherParams.IV)
	if err != nil {
		return nil, nil, err
	}

	cipherText, err := hex.DecodeString(keyProtected.Crypto.CipherText)
	if err != nil {
		return nil, nil, err
	}

	derivedKey, err := getKDFKey(keyProtected.Crypto, auth)
	if err != nil {
		return nil, nil, err
	}

	calculatedMAC := crypto.Keccak256(derivedKey[16:32], cipherText)
	if !bytes.Equal(calculatedMAC, mac) {
		return nil, nil, ErrDecrypt
	}

	plainText, err := aesCBCDecrypt(crypto.Keccak256(derivedKey[:16])[:16], cipherText, iv)
	if err != nil {
		return nil, nil, err
	}
	return plainText, keyId, err
}
*/
///
type cryptoJSON struct {
	Cipher       string                 `json:"cipher"`
	CipherText   string                 `json:"ciphertext"`
	CipherParams cipherparamsJSON       `json:"cipherparams"`
	KDF          string                 `json:"kdf"`
	KDFParams    map[string]interface{} `json:"kdfparams"`
	MAC          string                 `json:"mac"`
}


type encryptedKeyJSONV3 struct {
	Address string     `json:"address"`
	Crypto  cryptoJSON `json:"crypto"`
	Id      string     `json:"id"`
	Version int        `json:"version"`
}

type encryptedKeyJSONV1 struct {
	Address string     `json:"address"`
	Crypto  cryptoJSON `json:"crypto"`
	Id      string     `json:"id"`
	Version string     `json:"version"`
}

type cipherparamsJSON struct {
	IV string `json:"iv"`
}

///

type keyStoreStructure struct{
	Address string `json:"address"`
	crytoStructure `json:"crypto"`
	Version int `json:"version"`
	Id string `json:"id"`

}
type crytoStructure struct{
	Cipher string `json:"cipher"`
	CipherText string `json:"ciphertext"`
	cipherParamsJson `json:"cipherparams"`
	KDF string `json:"kdf"`
	scryptParamsJson `json:"kdfparams"`
	Mac string `json:"mac"`
}

type cipherParamsJson struct{
	Iv string `json:"iv"`

}

type scryptParamsJson struct{
	N int `json:"n"`
	R int `json:"r"`
	P int `json:"p"`
	DkLen int `json:"dklen"`
	Salt string `json:"salt"`
}

func Sha3(data ...[]byte) []byte {
	d := sha3.NewKeccak256()
	for _, b := range data {
		d.Write(b)
	}
	return d.Sum(nil)
}


func PKCS7Pad(in []byte) []byte {
	padding := 16 - (len(in) % 16)
	if padding == 0 {
		padding = 16
	}
	for i := 0; i < padding; i++ {
		in = append(in, byte(padding))
	}
	return in
}

func FromECDSA(priv *ecdsa.PrivateKey) []byte {
	if priv == nil {
		return nil
	}
	return math.PaddedBigBytes(priv.D, priv.Params().BitSize/8)
}

func S256() elliptic.Curve {
	return secp256k1.S256()
}

func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(crypto.S256(), rand.Reader)
}

type Key struct {
	Id uuid.UUID 
	Address common.Address
	PrivateKey *ecdsa.PrivateKey

}

func aesCTRXOR(key, inText, iv []byte)([]byte, error){
	aesBlock, err := aes.NewCipher(key)
	if err != nil{
		return nil, err
	}
	stream := cipher.NewCTR(aesBlock, iv)
	outText := make([]byte, len(inText))
	stream.XORKeyStream(outText, inText)
	return outText, err
}

func newKeyFromECDSA(privateKeyECDSA *ecdsa.PrivateKey) *Key {
	id := uuid.NewRandom()
	key := &Key{
		Id:         id,
		Address:    crypto.PubkeyToAddress(privateKeyECDSA.PublicKey),
		PrivateKey: privateKeyECDSA,
	}
	return key
}


func newKey(rand io.Reader) (*Key, error) {
	privateKeyECDSA, err := ecdsa.GenerateKey(crypto.S256(), rand)
	if err != nil {
		return nil, err
	}
	return newKeyFromECDSA(privateKeyECDSA), nil
}




