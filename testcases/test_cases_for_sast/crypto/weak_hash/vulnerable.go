package main
import "crypto/md5"
func main() {
    hash := md5.Sum([]byte("secret"))
    _ = hash
}
