package main

import (
	"encoding/json"
	"fmt"

	"log"
	"net/http"
	"strings"
	"time"

	"github.com/codegangsta/negroni"
	"github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"

	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
)

var (
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
)

type UserCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type UserInfo struct {
	Name string `json:"name"`
	Role string `json:"role"`
}

type CustomClaims struct {
	Foo      string `json:"foo"`
	UserInfo UserInfo
	jwt.StandardClaims
}

type Response struct {
	Data string `json:"data"`
}

type Token struct {
	Token string `json:"token"`
}

func main() {

	InitKeys()
	SaveKeys()
	LogPublicKey()
	StartServer()

}

func InitKeys() {

	var err error

	//PrivateKey = LoadRSAPrivateKeyFromDisk("")
	//PublicKey = LoadRSAPublicKeyFromDisk("")

	PrivateKey, err = rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		log.Fatal("Error reading private key")
		return
	}

	PublicKey = &PrivateKey.PublicKey
	
}

func StartServer() {

	// PUBLIC ENDPOINTS
	http.HandleFunc("/login", LoginHandler)

	// ROTECTED ENDPOINTS
	http.Handle("/api/", negroni.New(
		negroni.HandlerFunc(ValidateTokenMiddleware),
		negroni.Wrap(http.HandlerFunc(ApiHandler)),
	))

	http.ListenAndServe(":8080", nil)
}

func ApiHandler(w http.ResponseWriter, r *http.Request) {

	response := Response{"Access granted."}
	JsonResponse(response, w)

}

func LoginHandler(w http.ResponseWriter, r *http.Request) {

	var userCredentials UserCredentials

	// decode request into UserCredentials struct
	err := json.NewDecoder(r.Body).Decode(&userCredentials)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "Error in request")
		return
	}

	fmt.Println(userCredentials.Username, userCredentials.Password)

	// validate user credentials
	if strings.ToLower(userCredentials.Username) != "damin" {
		if userCredentials.Password != "admin" {
			w.WriteHeader(http.StatusForbidden)
			fmt.Println("Error logging in")
			fmt.Fprint(w, "Invalid credentials")
			return
		}
	}

	// create the Claims
	claims := CustomClaims{
		"bar",
		UserInfo{userCredentials.Username, "Member"},
		jwt.StandardClaims{
			Audience:  "Friends",
			Id:        "sampleId",
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: time.Now().Add(time.Minute * 2).Unix(),
			Issuer:    "Mike Großman",
			Subject:   "testing",
			//NotBefore: time.Now().Add(time.Minute * 2).Unix(),
		},
	}

	// generate token
	token := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), claims)

	tokenString, err := token.SignedString(PrivateKey)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Error while signing the token")
		log.Printf("Error signing token: %v\n", err)
	}

	// create a token instance using the token string
	response := Token{tokenString}
	JsonResponse(response, w)

}

func ValidateTokenMiddleware(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {

	// validate token
	token, err := request.ParseFromRequest(r, request.AuthorizationHeaderExtractor, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		/*
			// Look up key
			key, err := lookupPublicKey(token.Header["kid"])
			if err != nil {
				return nil, err
			}

			// Unpack key from PEM encoded PKCS8
			return jwt.ParseRSAPublicKeyFromPEM(key)
		*/

		return PublicKey, nil
	})

	if err == nil {
		if token.Valid {
			next(w, r)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "Token is not valid")
		}
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "Unauthorised access to this resource - ", err)
	}

}

//HELPER FUNCTIONS

func JsonResponse(response interface{}, w http.ResponseWriter) {

	jsonString, err := json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonString)
}

func SaveKeys() {

	// save private key
	privateKeyFile, err := os.Create("server.rsa")

	if err != nil {
		fmt.Println(err)
		return
	}

	// http://golang.org/pkg/encoding/pem/#Block
	var priv = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(PrivateKey)}

	err = pem.Encode(privateKeyFile, priv)

	if err != nil {
		fmt.Println(err)
		return
	}

	privateKeyFile.Close()

	// save public key
	publicKeyFile, err := os.Create("server.rsa.pub")

	if err != nil {
		fmt.Println(err)
		return
	}

	pubASN1, err := x509.MarshalPKIXPublicKey(PublicKey)
	if err != nil {
		// do something about it
	}

	// http://golang.org/pkg/encoding/pem/#Block
	var pub = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1}

	err = pem.Encode(publicKeyFile, pub)

	if err != nil {
		fmt.Println(err)
		return
	}

	publicKeyFile.Close()
}

func LogPublicKey() {

	pubASN1, err := x509.MarshalPKIXPublicKey(PublicKey)
	if err != nil {
		// do something about it
	}

	pub := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})

	fmt.Println("RSA PublicKey for this session:")
	fmt.Print(string(pub))
}

func LoadRSAPrivateKeyFromDisk(location string) *rsa.PrivateKey {
	keyData, e := ioutil.ReadFile(location)
	if e != nil {
		panic(e.Error())
	}
	key, e := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if e != nil {
		panic(e.Error())
	}
	return key
}

func LoadRSAPublicKeyFromDisk(location string) *rsa.PublicKey {
	keyData, e := ioutil.ReadFile(location)
	if e != nil {
		panic(e.Error())
	}
	key, e := jwt.ParseRSAPublicKeyFromPEM(keyData)
	if e != nil {
		panic(e.Error())
	}
	return key
}
