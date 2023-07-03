package model

import (
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	First_name     string
	Last_name      string
	Email          string `gorm:"unique"`
	Phone 		   string
	Password       string
	Available_time string
	User_type      string
	Alerts_and_Updates string
}


