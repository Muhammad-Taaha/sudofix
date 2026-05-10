package main
import "os"
func main() {
    password := os.Getenv("DB_PASSWORD")   // SAFE
}
