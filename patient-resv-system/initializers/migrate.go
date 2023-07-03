package initializers

import "github.com/Shaheer25/patient-resv-system/model"

func MigrateFiles() {
	DB.AutoMigrate(&model.User{})
}