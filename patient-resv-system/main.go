package main

import (
	controllers "github.com/Shaheer25/patient-resv-system/controller"
	"github.com/Shaheer25/patient-resv-system/initializers"
	"github.com/Shaheer25/patient-resv-system/middleware"
	"github.com/gin-gonic/gin"
)

func init() {
	initializers.LoadEnvVariables()
	initializers.ConnectToDB()
	initializers.MigrateFiles()
}

func main() {
	r := gin.Default()
	r.POST("/Signup", controllers.Signup)
	r.POST("/Login", controllers.Login)
	r.GET("/Validate", middleware.RequiredAuth, controllers.Validate)
	r.GET("/GetUser", middleware.RequiredAuth, controllers.GetUsersLoggedIn)
	r.PUT("/UpadteAvailableTime/:id",  controllers.UpdateAvailabeTime)
	r.PUT("/Alerts_and_Updates/:id",  controllers.Alerts_and_Updates)
	r.PUT("/UpdateProfile/:id",  controllers.ProfileUpdate)
	r.DELETE("/DeleteUser",  controllers.DeleteUser)
	r.POST("/FindEmailByPhone",controllers.FindEmailByPhone)
	r.PATCH("/ChangePassword/:id",controllers.ChangePassword)
	r.Run()
}