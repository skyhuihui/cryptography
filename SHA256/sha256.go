package main

import (
	//"github.com/nebulasio/go-nebulas/crypto/hash"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

func main() {

	a := "helloworld"

	////方法1：一个方法直接输出
	//hash:=hash.Sha256([]byte(a))
	//fmt.Println(hex.EncodeToString(hash))
	//
	//sha256.New()

	//方法2：按步骤一步步输出
	h := sha256.New()   //创建sha256算法
	h.Write([]byte(a))  //用sha256算法对参数a进行加密，得到8个变量
	hash1 := h.Sum(nil) //将8个变量相加得到最终hash

	fmt.Println(hex.EncodeToString(hash1))

}
