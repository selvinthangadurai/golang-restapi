package controllers

import (
	"context"
	"encoding/json"
	"mux-mongo-api/configs"
	"mux-mongo-api/models"
	"mux-mongo-api/responses"
	"net/http"
	"time"
	"log"
	"fmt"

	"github.com/go-playground/validator/v10"
	"github.com/gorilla/mux"
	"github.com/dgrijalva/jwt-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

var userCollection *mongo.Collection = configs.GetCollection(configs.DB, "users")
var roleCollection *mongo.Collection = configs.GetCollection(configs.DB, "roles")
var SECRET_KEY = []byte("mysecretkey")
var validate = validator.New()

func UserSignUp() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		var user models.User
		defer cancel()

		//validate the request body
		if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
			rw.WriteHeader(http.StatusBadRequest)
			response := responses.UserResponse{Status: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"data": err.Error()}}
			json.NewEncoder(rw).Encode(response)
			return
		}

		//use the validator library to validate required fields
		if validationErr := validate.Struct(&user); validationErr != nil {
			rw.WriteHeader(http.StatusBadRequest)
			response := responses.UserResponse{Status: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"data": validationErr.Error()}}
			json.NewEncoder(rw).Encode(response)
			return
		}

		newUser := models.User{
			Id:       primitive.NewObjectID(),
			Name:     user.Name,
			Location: user.Location,
			Title:    user.Title,
			Email:	  user.Email,
			Password:  getHash([]byte(user.Password)),
		}

		result, err := userCollection.InsertOne(ctx, newUser)
		fmt.Println(result.InsertedID)
		if(result.InsertedID !=nil ){
			newRole := models.Role{
				Id:       primitive.NewObjectID(),
				UserId:   result.InsertedID.(primitive.ObjectID),
				Name:      "Admin",
				Description:    "All permissions are applicable",
			}
			_, err := roleCollection.InsertOne(ctx,newRole)
			if err != nil {
				return
			}
		}
		if err != nil {
			rw.WriteHeader(http.StatusInternalServerError)
			response := responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: map[string]interface{}{"data": err.Error()}}
			json.NewEncoder(rw).Encode(response)
			return
		}

		rw.WriteHeader(http.StatusCreated)
		response := responses.UserResponse{Status: http.StatusCreated, Message: "success", Data: map[string]interface{}{"data": result}}
		json.NewEncoder(rw).Encode(response)
	}
}

func GetAUser() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		params := mux.Vars(r)
		userId := params["userId"]
		var user models.User
		defer cancel()

		objId, _ := primitive.ObjectIDFromHex(userId)

		err := userCollection.FindOne(ctx, bson.M{"id": objId}).Decode(&user)

		if err != nil {
			rw.WriteHeader(http.StatusInternalServerError)
			response := responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: map[string]interface{}{"data": err.Error()}}
			json.NewEncoder(rw).Encode(response)
			return
		}

		rw.WriteHeader(http.StatusOK)
		response := responses.UserResponse{Status: http.StatusOK, Message: "success", Data: map[string]interface{}{"data": user}}
		json.NewEncoder(rw).Encode(response)
	}
}

func EditAUser() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		params := mux.Vars(r)
		userId := params["userId"]
		var user models.User
		defer cancel()

		objId, _ := primitive.ObjectIDFromHex(userId)

		//validate the request body
		if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
			rw.WriteHeader(http.StatusBadRequest)
			response := responses.UserResponse{Status: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"data": err.Error()}}
			json.NewEncoder(rw).Encode(response)
			return
		}

		//use the validator library to validate required fields
		if validationErr := validate.Struct(&user); validationErr != nil {
			rw.WriteHeader(http.StatusBadRequest)
			response := responses.UserResponse{Status: http.StatusBadRequest, Message: "error", Data: map[string]interface{}{"data": validationErr.Error()}}
			json.NewEncoder(rw).Encode(response)
			return
		}

		update := bson.M{"name": user.Name, "location": user.Location, "title": user.Title}

		result, err := userCollection.UpdateOne(ctx, bson.M{"id": objId}, bson.M{"$set": update})

		if err != nil {
			rw.WriteHeader(http.StatusInternalServerError)
			response := responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: map[string]interface{}{"data": err.Error()}}
			json.NewEncoder(rw).Encode(response)
			return
		}

		//get updated user details
		var updatedUser models.User
		if result.MatchedCount == 1 {
			err := userCollection.FindOne(ctx, bson.M{"id": objId}).Decode(&updatedUser)

			if err != nil {
				rw.WriteHeader(http.StatusInternalServerError)
				response := responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: map[string]interface{}{"data": err.Error()}}
				json.NewEncoder(rw).Encode(response)
				return
			}
		}

		rw.WriteHeader(http.StatusOK)
		response := responses.UserResponse{Status: http.StatusOK, Message: "success", Data: map[string]interface{}{"data": updatedUser}}
		json.NewEncoder(rw).Encode(response)
	}
}

func DeleteAUser() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		params := mux.Vars(r)
		userId := params["userId"]
		defer cancel()

		objId, _ := primitive.ObjectIDFromHex(userId)

		result, err := userCollection.DeleteOne(ctx, bson.M{"id": objId})

		if err != nil {
			rw.WriteHeader(http.StatusInternalServerError)
			response := responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: map[string]interface{}{"data": err.Error()}}
			json.NewEncoder(rw).Encode(response)
			return
		}

		if result.DeletedCount < 1 {
			rw.WriteHeader(http.StatusNotFound)
			response := responses.UserResponse{Status: http.StatusNotFound, Message: "error", Data: map[string]interface{}{"data": "User with specified ID not found!"}}
			json.NewEncoder(rw).Encode(response)
			return
		}

		rw.WriteHeader(http.StatusOK)
		response := responses.UserResponse{Status: http.StatusOK, Message: "success", Data: map[string]interface{}{"data": "User successfully deleted!"}}
		json.NewEncoder(rw).Encode(response)
	}
}

func GetAllUser() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		var users []models.User
		defer cancel()

		results, err := userCollection.Find(ctx, bson.M{})

		if err != nil {
			rw.WriteHeader(http.StatusInternalServerError)
			response := responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: map[string]interface{}{"data": err.Error()}}
			json.NewEncoder(rw).Encode(response)
			return
		}

		//reading from the db in an optimal way
		defer results.Close(ctx)
		for results.Next(ctx) {
			var singleUser models.User
			if err = results.Decode(&singleUser); err != nil {
				rw.WriteHeader(http.StatusInternalServerError)
				response := responses.UserResponse{Status: http.StatusInternalServerError, Message: "error", Data: map[string]interface{}{"data": err.Error()}}
				json.NewEncoder(rw).Encode(response)
			}

			users = append(users, singleUser)
		}

		rw.WriteHeader(http.StatusOK)
		response := responses.UserResponse{Status: http.StatusOK, Message: "success", Data: map[string]interface{}{"data": users}}

		fmt.Println(users)
		json.NewEncoder(rw).Encode(response)
	}
}


func getHash(pwd []byte) string {
    hash, err := bcrypt.GenerateFromPassword(pwd, bcrypt.MinCost)
    if err != nil {
        log.Println(err)
    }
    return string(hash)
}

func GenerateJWT(email string) (tokenString string, err error) {
	expirationTime := time.Now().Add(1 * time.Hour)
	claims:= &models.JWTClaim{
		Email: email,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err = token.SignedString(SECRET_KEY)
	return
}


func UserLogin() http.HandlerFunc {
	return func(response http.ResponseWriter, request *http.Request) {   
		response.Header().Set("Content-Type","application/json")  
		var user models.User 
		var dbUser models.User  
		json.NewDecoder(request.Body).Decode(&user)  
		ctx,cancel :=context.WithTimeout(context.Background(),10*time.Second)      
		defer cancel()
		err:=userCollection.FindOne(ctx,bson.M{"email":user.Email}).Decode(&dbUser)
		if err!=nil{      
		   response.WriteHeader(http.StatusInternalServerError)     
		   response.Write([]byte(`{"message":"`+err.Error()+`"}`))    
		   return
		}
		userPass:= []byte(user.Password)
		dbPass:= []byte(dbUser.Password)
		passErr:= bcrypt.CompareHashAndPassword(dbPass, userPass)
		if passErr != nil{
		   log.Println(passErr)    
		   response.Write([]byte(`{"response":"Wrong Password!"}`))    
		   return
		}
		jwtToken, err := GenerateJWT(user.Email)
		if err != nil{   
		response.WriteHeader(http.StatusInternalServerError)  
		response.Write([]byte(`{"message":"`+err.Error()+`"}`))
		return
		}
		expirationTime := time.Now().Add(1 * time.Hour)
		cookie := &http.Cookie{
			Name:    "token",
			Value:   jwtToken,
			Expires: expirationTime,
		}
		http.SetCookie(response, cookie)
	}
}

func Logout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request){
		c := http.Cookie{
			Name:   "token",
			MaxAge: -1}
		http.SetCookie(w, &c)
		w.Write([]byte("Old cookie deleted. Logged out!\n"))
}
}

