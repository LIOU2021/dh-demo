// ref
// https://asecuritysite.com/encryption/gorsa

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

	fmt.Println("========================================================================")

	publicKeyText := myRsa.ExportPublicKeyAsPemStr()
	privateKeyText := myRsa.ExportPrivateKeyAsPemStr()

	// 存在文本时的样产出
	fmt.Printf("publicKeyText: %s\n", publicKeyText)
	fmt.Printf("privateKeyText: %s\n", privateKeyText)
	fmt.Printf("ExportMsgAsPemStr: %s\n", ExportMsgAsPemStr([]byte(content)))

}
