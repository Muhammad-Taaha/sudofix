package main
import "crypto/md5"
hash := md5.Sum([]byte("secret"))   // DANGEROUS
