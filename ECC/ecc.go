package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto/ecies"
)

// ecc 加密解密  椭圆曲线算法
func main() {
	msg := "hello world"
	//调用以太坊的曲线加密包下的方法产生私钥 prv,_:=ecies.GenerateKey(rand.Reader,elliptic.P256(),nil )
	//私钥产生公钥
	prv, _ := ecies.GenerateKey(rand.Reader, elliptic.P256(), nil)
	pub := prv.PublicKey

	//调用加密方法对明文进行加密
	ct, _ := ecies.Encrypt(rand.Reader, &pub, []byte(msg), nil, nil)
	scrt := hex.EncodeToString(ct)
	fmt.Println(scrt)
	//对密文进行解密
	ms, _ := prv.Decrypt(ct, nil, nil)
	fmt.Println(string(ms))

}
