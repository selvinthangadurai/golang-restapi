package routes

import (
	"mux-mongo-api/controllers"
	"mux-mongo-api/middleware"

	"github.com/gorilla/mux"
)

func UserRoute(router *mux.Router) {
	router.HandleFunc("/user", controllers.UserSignUp()).Methods("POST")
	router.HandleFunc("/user/login", controllers.UserLogin()).Methods("POST")
	router.HandleFunc("/user/logout", controllers.Logout()).Methods("GET")
	router.HandleFunc("/user/{userId}", middleware.IsAuthorized(controllers.GetAUser())).Methods("GET")
	router.HandleFunc("/user/{userId}", middleware.IsAuthorized(controllers.EditAUser())).Methods("PUT")
	router.HandleFunc("/user/{userId}", middleware.IsAuthorized(controllers.DeleteAUser())).Methods("DELETE")
	router.HandleFunc("/users",middleware.IsAuthorized(controllers.GetAllUser())).Methods("GET")
}
