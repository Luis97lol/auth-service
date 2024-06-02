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
	token := auth.GenerateJWT(auth.User{Id: userId})
	err := GetInstance().Set(context.Background(), fmt.Sprintf("auth_token:%s", token), userId, 5*time.Minute).Err()
	if err != nil {
		return "", err
	}
	err2 := GetInstance().Set(context.Background(), fmt.Sprintf("auth_user:%s", userId), token, 5*time.Minute).Err()
	if err2 != nil {
		GetInstance().Del(context.Background(), fmt.Sprintf("auth_token:%s", token))
		return "", err2
	}
	return token, nil
}

func ValidateToken(token string) (string, error) {
	val, err := GetInstance().Get(context.Background(), fmt.Sprintf("auth_token:%s", token)).Result()
	if err == redis.Nil {
		println("Token not Found")
		return "", fmt.Errorf("token not found")
	} else if err != nil {
		println("Error validating with Redis: ", err.Error())
		return "", err
	}
	return val, nil
}
