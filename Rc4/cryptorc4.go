package main

import (
	"crypto/rc4"
	"fmt"
)

func main() {
	var key []byte = []byte("fd6cde7c2124574845454389jkfdsafdsaf4913f22297c948dd530c84") //初始化用于加密的KEY
	rc4obj, _ := rc4.NewCipher(key)                                                      //返回 Cipher

	str := []byte("helloworld")         //需要加密的字符串
	plaintext := make([]byte, len(str)) //
	rc4obj.XORKeyStream(plaintext, str)
	//XORKeyStream方法将src的数据与秘钥生成的伪随机位流取XOR并写入dst。
	//plaintext就是你加密的返回过来的结果了，注意：plaintext为base-16 编码的字符串，每个字节使用2个字符表示 必须格式化成字符串

	stringinf := fmt.Sprintf("%x\n", plaintext) //转换字符串
	fmt.Println(stringinf)
}
