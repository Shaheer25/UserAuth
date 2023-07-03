package controllers

import (
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/Shaheer25/patient-resv-system/initializers"
	"github.com/Shaheer25/patient-resv-system/model"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func Signup(c *gin.Context) {
	// Get the email and password
	var body struct {
		First_name         string
		Last_name          string
		Email              string
		Phone              string
		Password           string
		Available_time     string
		User_type          string
		Alerts_and_Updates string
	}

	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Failed to Signup",
		})

		return
	}

	// Hash the password
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 10)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to Hash the Password",
		})
		return
	}

	// Create the user with hashed password
	user := model.User{
		First_name:         body.First_name,
		Last_name:          body.Last_name,
		Email:              body.Email,
		Phone:              body.Phone,
		Password:           string(hash),
		Available_time:     body.Available_time,
		User_type:          body.User_type,
		Alerts_and_Updates: body.Alerts_and_Updates,
	}

	// Save the user in the database
	result := initializers.DB.Create(&user)

	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to Create the User",
		})
		return
	}

	// Respond with success message
	c.JSON(http.StatusOK, gin.H{
		"message": "Successfully Created an Account",
	})
}

func Login(c *gin.Context) {
	// Take user email and password
	var body struct {
		Email    string
		Password string
	}

	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Failed to add Email and Password",
		})

		return
	}

	// Look up the requested user
	var user model.User
	initializers.DB.First(&user, "email = ?", body.Email)

	if user.ID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Email and Password Didn't match",
		})
		return
	}

	// Check whether the email and password match
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))
	if err != nil {
		if user.ID == 0 {
			c.JSON(http.StatusBadRequest, gin.H{
				"message": "Password and Email Didn't match",
			})
		}
		return
	}

	// Generate JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(time.Hour * 24 * 30).Unix(),
	})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString([]byte(os.Getenv("SECRET")))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
				"message": "Invalid Token",
		})
	}
	
	// Set the JWT token as a cookie
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("Authorization", tokenString, 3600*24*30*12, "", "", false, true)

	c.JSON(http.StatusOK, gin.H{})
}

func Validate(c *gin.Context) {
	c.Get("user")
	c.JSON(http.StatusOK, gin.H{
		"message": "Logged in successfully",
	})
}

func GetUsersLoggedIn(c *gin.Context) {
	user, _ := c.Get("user")
	c.JSON(http.StatusOK, gin.H{
		"message": user,
	})
}

func UpdateAvailabeTime(c *gin.Context) {
	id := c.Param("id")

	var body struct {
		Available_time string
	}
	c.Bind(&body)

	var post model.User
	initializers.DB.First(&post, id)

	initializers.DB.Model(&post).Updates(model.User{
		Available_time: body.Available_time,
	})

	c.Get("user")
	c.JSON(200, gin.H{
		"message": "Available Time Updated Successfully",
	})
}

func Alerts_and_Updates(c *gin.Context) {
	id := c.Param("id")

	var body struct {
		Alerts_and_Updates string
	}
	c.Bind(&body)

	var post model.User
	initializers.DB.First(&post, id)

	initializers.DB.Model(&post).Updates(model.User{
		Alerts_and_Updates: body.Alerts_and_Updates,
	})

	c.Get("user")
	c.JSON(200, gin.H{
		"message": "Saved Successfully",
	})
}

func ProfileUpdate(c *gin.Context) {
	id := c.Param("id")

	var body struct {
		First_name         string
		Last_name          string
		Email              string
		Phone              string
		Password           string
		Available_time     string
		User_type          string
		Alerts_and_Updates string
	}
	c.Bind(&body)

	var user model.User
	if err := initializers.DB.First(&user, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "User not found",
		})
		return
	}

	updates := model.User{
		First_name:         body.First_name,
		Last_name:          body.Last_name,
		Email:              body.Email,
		Phone:              body.Phone,
		Password:           body.Password,
		Available_time:     body.Available_time,
		User_type:          body.User_type,
		Alerts_and_Updates: body.Alerts_and_Updates,
	}

	if err := initializers.DB.Model(&user).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to update user profile",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Updated Successfully",
		"user":    user,
	})
}

func DeleteUser(c *gin.Context) {
	var user model.User

	var body struct {
		Email    string
		Password string
	}

	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request",
		})
		return
	}

	// Find the user by email
	if err := initializers.DB.Where("email = ?", body.Email).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "User not found",
			})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to find user",
			})
		}
		return
	}

	// Check if the provided password matches the stored password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Incorrect password",
		})
		return
	}

	// Delete the user from the database
	if err := initializers.DB.Delete(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to delete user",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "User deleted successfully",
	})
}

func ChangePassword(c *gin.Context) {
	id := c.Param("id")

	var body struct {
		CurrentPassword    string // Current password
		NewPassword        string // New password
		ConfirmNewPassword string // Confirm new password
	}
	c.Bind(&body)

	var user model.User
	if err := initializers.DB.First(&user, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "User not found",
		})
		return
	}

	// Check if the current password matches the stored password
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.CurrentPassword))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Incorrect current password",
		})
		return
	}

	// Check if the new password and confirm new password match
	if body.NewPassword != body.ConfirmNewPassword {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "New password and confirm new password do not match",
		})
		return
	}

	// Hash the new password
	newPasswordHash, err := bcrypt.GenerateFromPassword([]byte(body.NewPassword), 10)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to hash the new password",
		})
		return
	}

	// Update the user's password
	user.Password = string(newPasswordHash)

	if err := initializers.DB.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to update password",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Password updated successfully",
	})
}

func FindEmailByPhone(c *gin.Context) {
	var body struct {
		Phone string
	}
	c.Bind(&body)

	var user model.User
	if err := initializers.DB.Where("phone = ?", body.Phone).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "Email not found",
			})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to find Email",
			})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"email": user.Email,
	})
}
