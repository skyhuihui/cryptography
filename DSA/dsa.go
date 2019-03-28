package main

import (
	"crypto/dsa"
	"crypto/rand"
	"fmt"
)

//作用1 确保传递数据的完整性 2 确保数据的来源
func main() {
	//DSA专业做签名和验签
	var param dsa.Parameters //结构体里有三个很大很大的数bigInt
	//结构体实例化
	dsa.GenerateParameters(&param, rand.Reader, dsa.L1024N160) //L是1024，N是160，这里的L是私钥，N是公钥初始参数
	//通过上边参数生成param结构体，里面有三个很大很大的数

	//生成私钥
	var priv dsa.PrivateKey //privatekey是个结构体，里面有publickey结构体，该结构体里有Parameters字段
	priv.Parameters = param
	//通过随机读数与param一些关系生成私钥
	dsa.GenerateKey(&priv, rand.Reader)

	//通过私钥生成公钥
	pub := priv.PublicKey
	message := []byte("hello world")
	//r,s是两个整数,通过私钥给message签名,得到两个随机整数r，s
	r, s, _ := dsa.Sign(rand.Reader, &priv, message)

	//利用公钥验签，验证r，s
	b := dsa.Verify(&pub, message, r, s)
	if b == true {
		fmt.Println("验签成功")
	} else {
		fmt.Println("验证失败")
	}
}
