package middleware

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/Shaheer25/patient-resv-system/initializers"
	"github.com/Shaheer25/patient-resv-system/model"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

func RequiredAuth(c *gin.Context) {
	// get the cookie of request

	tokenString, err := c.Cookie("Authorization")

	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
	}

	// Decode and Validate

	// Parse takes the token string and a function for looking up the key. The latter is especially
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte(os.Getenv("SECRET")), nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {

		//Check the Expiration
		if float64(time.Now().Unix()) > claims["exp"].(float64){
			c.AbortWithStatus(http.StatusUnauthorized)
		}

		//Find User with Token
		var user model.User
		initializers.DB.First(&user, claims["sub"])

		if user.ID == 0 {
			c.AbortWithStatus(http.StatusUnauthorized)
		}

		//Attach the Req

		c.Set("user",user)


		//Continue

		c.Next()
		
	} else {
		c.AbortWithStatus(http.StatusUnauthorized)
	}
}
