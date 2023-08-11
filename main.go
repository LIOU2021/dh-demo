package main

import (
	"crypto/md5"
	"fmt"
)

func main() {
	data := "https://www.google.com"
	has := md5.Sum([]byte(data))
	// hex.EncodeToString(has)
	mdtStr := fmt.Sprintf("%x", has)
	fmt.Println(mdtStr)
	fmt.Println(len(mdtStr))
}
