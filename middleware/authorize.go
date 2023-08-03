package middleware

import (
	"encoding/json"
	"net/http"
	"github.com/dgrijalva/jwt-go"
	"mux-mongo-api/responses"
	"fmt"
)

var SECRET_KEY = []byte("mysecretkey")

func IsAuthorized(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		if r.Header["Token"] == nil {
			w.WriteHeader(http.StatusInternalServerError)
			response := responses.UserResponse{Status: http.StatusInternalServerError, Message: "No Token Found", Data: map[string]interface{}{"data": nil }}
			json.NewEncoder(w).Encode(response)
			return
		}

		var mySigningKey = []byte(SECRET_KEY)

		_, err := jwt.Parse(r.Header["Token"][0], func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("There was an error in parsing token.")
			}
			return mySigningKey, nil
		})

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			response := responses.UserResponse{Status: http.StatusInternalServerError, Message: "Your Token has been expired.", Data: map[string]interface{}{"data": err.Error()}}
			json.NewEncoder(w).Encode(response)
			return
		}
		handler.ServeHTTP(w, r)
	}
}