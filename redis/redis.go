package redis

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/go-redis/redis/v8"
)

var redisClient *redis.Client

func InitRedis() {
	redisClient = redis.NewClient(&redis.Options{
		Addr:     os.Getenv("REDIS_ADDR"),
		Password: os.Getenv("REDIS_PASSWORD"),
		DB:       0,
	})
}

func GenerateToken(username string) (string, error) {
	token := fmt.Sprintf("token:%s", username)
	err := redisClient.Set(context.Background(), token, username, 5*time.Minute).Err()
	if err != nil {
		return "", err
	}
	return token, nil
}

func ValidateToken(token string) (string, error) {
	val, err := redisClient.Get(context.Background(), token).Result()
	if err == redis.Nil {
		return "", fmt.Errorf("token not found")
	} else if err != nil {
		return "", err
	}
	return val, nil
}
