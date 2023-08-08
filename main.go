// ref
// https://asecuritysite.com/encryption/gorsa
// https://stackoverflow.com/questions/44230634/how-to-read-an-rsa-key-from-file
// https://golangdocs.com/rsa-encryption-decryption-in-golang

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
)

type rsaConfig struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

var myRsa = &rsaConfig{}

// 使用公钥加密
func (r *rsaConfig) RSA_OAEP_Encrypt(secretMessage string) (ciphertext string, err error) {
	label := []byte("OAEP Encrypted")
	rng := rand.Reader
	b, err := rsa.EncryptOAEP(sha256.New(), rng, r.publicKey, []byte(secretMessage), label)
	if err != nil {
		return
	}
	ciphertext = base64.StdEncoding.EncodeToString(b)
	return
}

// 使用私钥解密
func (r *rsaConfig) RSA_OAEP_Decrypt(cipherText string) (data string, err error) {
	ct, _ := base64.StdEncoding.DecodeString(cipherText)
	label := []byte("OAEP Encrypted")
	rng := rand.Reader
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rng, r.privateKey, ct, label)
	if err != nil {
		return
	}
	data = string(plaintext)
	return
}

// 使用pkg自己产密钥对
func (r *rsaConfig) GenerateKey() (err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048) // here 2048 is the number of bits for RSA
	// 1024 - 4096 supported

	if err != nil {
		return
	}

	r.publicKey = &privateKey.PublicKey
	r.privateKey = privateKey

	return
}

// 将公钥产出string，放在ooxx.pem档案时的内容
func (r *rsaConfig) ExportPublicKeyAsPemStr() string {
	pubkey_pem := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(r.publicKey)}))
	return pubkey_pem
}

// 将私钥产出string，放在ooxx.pem档案时的内容
func (r *rsaConfig) ExportPrivateKeyAsPemStr() string {
	privatekey_pem := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(r.privateKey)}))
	return privatekey_pem
}

// 这只是一段测试sample，将讯息内容也转成pem格式
func ExportMsgAsPemStr(msg []byte) string {
	msg_pem := string(pem.EncodeToMemory(&pem.Block{Type: "MESSAGE", Bytes: msg}))
	return msg_pem
}

// 直接给私钥文本string载入
func (r *rsaConfig) LoadPrivateKey(pemString string) {
	block, _ := pem.Decode([]byte(pemString))
	key, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	r.privateKey = key
}

// 直接给公钥文本string载入
func (r *rsaConfig) LoadPublicKey(pemString string) {
	block, _ := pem.Decode([]byte(pemString))
	key, _ := x509.ParsePKCS1PublicKey(block.Bytes)
	r.publicKey = key
}

func main() {
	err := myRsa.GenerateKey()
	if err != nil {
		log.Fatalf("generate key err = %v", err)
	}

	content := "hello world"

	cipherText, err := myRsa.RSA_OAEP_Encrypt(content)
	if err != nil {
		log.Fatalf("encrypt err = %v", err)
	}

	fmt.Printf("encrypt result : %s\n", cipherText)

	plainText, err := myRsa.RSA_OAEP_Decrypt(cipherText)
	if err != nil {
		log.Fatalf("decrypt err = %v", err)
	}
	fmt.Printf("decrypt result : %s\n", plainText)
	if plainText != content {
		log.Fatalf("plainText not equal content. plainText: %s", plainText)
	}

	fmt.Println("========================================================================")

	publicKeyText := myRsa.ExportPublicKeyAsPemStr()
	privateKeyText := myRsa.ExportPrivateKeyAsPemStr()

	// 存在文本时的样产出
	fmt.Printf("publicKeyText: %s\n", publicKeyText)
	fmt.Printf("privateKeyText: %s\n", privateKeyText)
	fmt.Printf("ExportMsgAsPemStr: %s\n", ExportMsgAsPemStr([]byte(content)))

	// 将108-109行产出的文本再重新用一个接口传回myRsa设置密钥对，并检查再次执行105-106行的内容是否一样，
	myRsa2 := &rsaConfig{}
	myRsa2.LoadPrivateKey(privateKeyText)
	myRsa2.LoadPublicKey(publicKeyText)

	if myRsa2.ExportPrivateKeyAsPemStr() != privateKeyText {
		log.Fatal("load key : private key incorrect")
	}

	if myRsa2.ExportPublicKeyAsPemStr() != publicKeyText {
		log.Fatal("load key : public key incorrect")
	}
	fmt.Println("========================================================================")
	fmt.Println("==myRsa2==")
	cipherText, err = myRsa2.RSA_OAEP_Encrypt(content)
	if err != nil {
		log.Fatalf("encrypt err = %v", err)
	}

	fmt.Printf("encrypt result : %s\n", cipherText)

	plainText, err = myRsa2.RSA_OAEP_Decrypt(cipherText)
	if err != nil {
		log.Fatalf("decrypt err = %v", err)
	}
	fmt.Printf("decrypt result : %s\n", plainText)
	if plainText != content {
		log.Fatalf("plainText not equal content. plainText: %s", plainText)
	}
}
