package models

import "go.mongodb.org/mongo-driver/bson/primitive"

type Role struct {
	Id       primitive.ObjectID `json:"id,omitempty"`
	UserId   primitive.ObjectID `json:"userid,omitempty" validate:"required"`
	Name string             `json:"name,omitempty" validate:"required"`
	Description string 		`json:"description,omitempty"`
}

