package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

// 椭圆曲线  ecdsa 签名验签
func main() {
	//明文
	message := []byte("Hello world")

	//获取私钥
	key, err := NewSigningKey()
	if err != nil {
		return
	}

	//用私钥对明文进行签名
	signature, err := Sign(message, key)

	fmt.Printf("签名后：%x\n", signature)
	if err != nil {
		return
	}

	//用公钥对签名进行验证，确认签名是否是对当前明文的有效
	if !Verify(message, signature, &key.PublicKey) {
		fmt.Println("验证失败！")
		return
	} else {
		fmt.Println("验证成功！")
	}

}

func NewSigningKey() (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return key, err
}

// 用私钥对明文进行签名
func Sign(data []byte, privkey *ecdsa.PrivateKey) ([]byte, error) {
	// 对明文进行sha256散列，生成一个长度为32的字节数组
	digest := sha256.Sum256(data)

	// 通过椭圆曲线方法对散列后的明文进行签名，返回两个big.int类型的大数
	r, s, err := ecdsa.Sign(rand.Reader, privkey, digest[:])
	if err != nil {
		return nil, err
	}
	//将大数转换成字节数组，并拼接起来，形成签名
	signature := append(r.Bytes(), s.Bytes()...)
	return signature, nil
}

// 通过公钥验证签名
func Verify(data, signature []byte, pubkey *ecdsa.PublicKey) bool {
	// 将明文转换成字节数组
	digest := sha256.Sum256(data)

	//声明两个大数r，s
	r := big.Int{}
	s := big.Int{}
	//将签名平均分割成两部分切片，并将切片转换成*big.int类型
	sigLen := len(signature)
	r.SetBytes(signature[:(sigLen / 2)])
	s.SetBytes(signature[(sigLen / 2):])

	//通过公钥对得到的r，s进行验证
	return ecdsa.Verify(pubkey, digest[:], &r, &s)
}
