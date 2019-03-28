package main

import (
	"crypto"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
)

// 已知公钥私钥做加密解密

// 可通过openssl产生
//openssl genrsa -out rsa_private_key.pem 1024
var privateKey = []byte(`  
-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDfw1/P15GQzGGYvNwVmXIGGxea8Pb2wJcF7ZW7tmFdLSjOItn9
kvUsbQgS5yxx+f2sAv1ocxbPTsFdRc6yUTJdeQolDOkEzNP0B8XKm+Lxy4giwwR5
LJQTANkqe4w/d9u129bRhTu/SUzSUIr65zZ/s6TUGQD6QzKY1Y8xS+FoQQIDAQAB
AoGAbSNg7wHomORm0dWDzvEpwTqjl8nh2tZyksyf1I+PC6BEH8613k04UfPYFUg1
0F2rUaOfr7s6q+BwxaqPtz+NPUotMjeVrEmmYM4rrYkrnd0lRiAxmkQUBlLrCBiF
u+bluDkHXF7+TUfJm4AZAvbtR2wO5DUAOZ244FfJueYyZHECQQD+V5/WrgKkBlYy
XhioQBXff7TLCrmMlUziJcQ295kIn8n1GaKzunJkhreoMbiRe0hpIIgPYb9E57tT
/mP/MoYtAkEA4Ti6XiOXgxzV5gcB+fhJyb8PJCVkgP2wg0OQp2DKPp+5xsmRuUXv
720oExv92jv6X65x631VGjDmfJNb99wq5QJBAMSHUKrBqqizfMdOjh7z5fLc6wY5
M0a91rqoFAWlLErNrXAGbwIRf3LN5fvA76z6ZelViczY6sKDjOxKFVqL38ECQG0S
pxdOT2M9BM45GJjxyPJ+qBuOTGU391Mq1pRpCKlZe4QtPHioyTGAAMd4Z/FX2MKb
3in48c0UX5t3VjPsmY0CQQCc1jmEoB83JmTHYByvDpc8kzsD8+GmiPVrausrjj4p
y2DQpGmUic2zqCxl6qXMpBGtFEhrUbKhOiVOJbRNGvWW
-----END RSA PRIVATE KEY-----
`)

//openssl
//openssl rsa -in rsa_private_key.pem -pubout -out rsa_public_key.pem
var publicKey = []byte(`  
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDfw1/P15GQzGGYvNwVmXIGGxea
8Pb2wJcF7ZW7tmFdLSjOItn9kvUsbQgS5yxx+f2sAv1ocxbPTsFdRc6yUTJdeQol
DOkEzNP0B8XKm+Lxy4giwwR5LJQTANkqe4w/d9u129bRhTu/SUzSUIr65zZ/s6TU
GQD6QzKY1Y8xS+FoQQIDAQAB
-----END PUBLIC KEY-----    
`)

// 加密
func RsaEncrypt(origData []byte) ([]byte, error) {
	//解码pem格式的公钥，得到公钥的载体block
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, errors.New("public key error")
	}
	// 解析得到公钥
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	// 接口类型断言
	pub := pubInterface.(*rsa.PublicKey)
	//加密
	return rsa.EncryptPKCS1v15(rand.Reader, pub, origData)
}

// 解密
func RsaDecrypt(ciphertext []byte) ([]byte, error) {
	//解码pem格式的私钥，得到公钥的载体block
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("private key error!")
	}
	//解析得到PKCS1格式的私钥
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	// 解密
	return rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)
}

func main() {
	//使用已有签名加密解密
	data, _ := RsaEncrypt([]byte("hello world"))
	fmt.Println(base64.StdEncoding.EncodeToString(data))
	origData, _ := RsaDecrypt(data)
	fmt.Println(string(origData))

	//创建公钥私钥对加密解密 签名验签

	//通过RSA实现加密和解密
	//利用RSA的方法生成私钥对
	//RSA首先生成的是私钥，然后根据私钥生成公钥
	//生成1024位私钥
	pri, _ := rsa.GenerateKey(rand.Reader, 2048)
	//根据私钥产生公钥
	pub := &pri.PublicKey
	fmt.Println("私钥", pri)
	fmt.Println("公钥", pub)
	//定义明文
	plaintext := []byte("hello china")
	//加密成密文,OAEP补码
	ciphertext, _ := rsa.EncryptOAEP(md5.New(), rand.Reader, pub, plaintext, nil)
	fmt.Println(base64.StdEncoding.EncodeToString(ciphertext))

	//解密
	plaintext, _ = rsa.DecryptOAEP(md5.New(), rand.Reader, pri, ciphertext, nil)
	fmt.Println(string(plaintext))

	//RSA实现签名和验签
	//给明文做哈希散列
	//定义明文
	txt := []byte("txt")
	h := md5.New()
	h.Write(txt)
	hashed := h.Sum(nil)
	//签名
	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.MD5}
	sign, _ := rsa.SignPSS(rand.Reader, pri, crypto.MD5, hashed, opts)

	//认证
	e := rsa.VerifyPSS(pub, crypto.MD5, hashed, sign, opts)
	if e == nil {
		fmt.Println("验证成功")
	} else {
		fmt.Println("验证失败")
	}

}
