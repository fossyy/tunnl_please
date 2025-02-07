package utils

import (
	"github.com/joho/godotenv"
	"log"
	"math/rand"
	"os"
	"strings"
	"sync"
	"time"
)

type Env struct {
	value map[string]string
	mu    sync.Mutex
}

var env *Env

func init() {
	env = &Env{value: map[string]string{}}
}

func GenerateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz"
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano() + int64(rand.Intn(9999))))
	var result strings.Builder
	for i := 0; i < length; i++ {
		randomIndex := seededRand.Intn(len(charset))
		result.WriteString(string(charset[randomIndex]))
	}
	return result.String()
}

func Getenv(key string) string {
	env.mu.Lock()
	defer env.mu.Unlock()
	if val, ok := env.value[key]; ok {
		return val
	}

	if os.Getenv("HOSTNAME") == "" {
		err := godotenv.Load(".env")
		if err != nil {
			log.Fatalf("Error loading .env file: %s", err)
		}
	}

	val := os.Getenv(key)
	env.value[key] = val

	if val == "" {
		panic("Asking for env: " + key + " but got nothing, please set your environment first")
	}

	return val
}
