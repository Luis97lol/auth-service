package redis

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/Luis97lol/auth-service/auth"
	"github.com/go-redis/redis/v8"
)

var redisClient *redis.Client
var once sync.Once

func GetInstance() *redis.Client {
	once.Do(func() {
		redisClient = redis.NewClient(&redis.Options{
			Addr:     os.Getenv("REDIS_ADDR"),     // Dirección del servidor Redis
			Password: os.Getenv("REDIS_PASSWORD"), // Contraseña (si es necesario)
			DB:       0,                           // Número de base de datos
		})
	})
	return redisClient
}

func GenerateToken(userId string) (string, error) {
	token := fmt.Sprintf("token:%s", auth.GenerateJWT(auth.User{Id: userId}))
	err := GetInstance().Set(context.Background(), token, userId, 5*time.Minute).Err()
	if err != nil {
		return "", err
	}
	return token, nil
}

func ValidateToken(token string) (string, error) {
	val, err := GetInstance().Get(context.Background(), token).Result()
	if err == redis.Nil {
		return "", fmt.Errorf("token not found")
	} else if err != nil {
		return "", err
	}
	return val, nil
}
