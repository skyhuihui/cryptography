package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func main() {
	str := []byte("helloworld")
	key := []byte("12345678qwertyui")
	encrypt := AesCTR_Encrypt(str, key)
	fmt.Printf("%x\n", encrypt)
	decrypt := AesCTR_Decrypt(encrypt, key)
	fmt.Println(string(decrypt))
}

//加密
func AesCTR_Encrypt(plainText, key []byte) []byte {
	//判断用户传过来的key是否符合16字节，如果不符合16字节加以处理
	keylen := len(key)
	if keylen == 0 { //如果用户传入的密钥为空那么就用默认密钥
		key = []byte("Abskjeqiu1234567") //默认密钥
	} else if keylen > 0 && keylen < 16 { //如果密钥长度在0到16之间，那么用0补齐剩余的
		key = append(key, bytes.Repeat([]byte{0}, (16-keylen))...)
	} else if keylen > 16 {
		key = key[:16]
	}
	//1.指定使用的加密aes算法
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	//2.不需要填充,直接获取ctr分组模式的stream
	// 返回一个计数器模式的、底层采用block生成key流的Stream接口，初始向量iv的长度必须等于block的块尺寸。
	iv := []byte("wumansgygoaesctf")

	stream := cipher.NewCTR(block, iv)

	//3.加密操作
	cipherText := make([]byte, len(plainText))
	stream.XORKeyStream(cipherText, plainText)

	return cipherText
}

//解密
func AesCTR_Decrypt(cipherText, key []byte) []byte {
	//判断用户传过来的key是否符合16字节，如果不符合16字节加以处理
	keylen := len(key)
	if keylen == 0 { //如果用户传入的密钥为空那么就用默认密钥
		key = []byte("Abskjeqiu1234567") //默认密钥
	} else if keylen > 0 && keylen < 16 { //如果密钥长度在0到16之间，那么用0补齐剩余的
		key = append(key, bytes.Repeat([]byte{0}, (16-keylen))...)
	} else if keylen > 16 {
		key = key[:16]
	}
	//1.指定算法:aes
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	//2.返回一个计数器模式的、底层采用block生成key流的Stream接口，初始向量iv的长度必须等于block的块尺寸。
	iv := []byte("wumansgygoaesctf")
	stream := cipher.NewCTR(block, iv)

	//3.解密操作
	plainText := make([]byte, len(cipherText))
	stream.XORKeyStream(plainText, cipherText)

	return plainText
}
