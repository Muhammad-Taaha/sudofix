package main
import "crypto/sha256"
func main() {
    hash := sha256.Sum256([]byte("secret"))
    _ = hash
}
