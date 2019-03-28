package main

import (
	"bytes"
	"crypto/cipher" //密码
	"crypto/des"
	"encoding/base64" //将对象转换成字符串
	"fmt"
)

//DES加密的方法
func MyDesEncrypt(origData, key []byte) {
	//生成加密块
	block, _ := des.NewCipher(key)
	//按照blocksize的长度padding
	origData = PKCS5Padding(origData, des.BlockSize)
	//设置加密方式
	blockMode := cipher.NewCBCEncrypter(block, key)
	//创建明文长度的字节数组
	crypted := make([]byte, len(origData))
	//加密明文
	blockMode.CryptBlocks(crypted, origData)
	//将字节数组转换成字符串
	fmt.Println(base64.StdEncoding.EncodeToString(crypted))
}

//明文补码 补够64 比特
func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize

	padtext := bytes.Repeat([]byte{byte(padding)}, padding) //补码过程

	return append(ciphertext, padtext...)
}

//实现去补码
func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

//DES解密方法
func MyDESDecrypt(data string, key []byte) {
	//将字符串转换成字节数组
	crypted, _ := base64.StdEncoding.DecodeString(data)
	//将字节密钥转换成block块
	block, _ := des.NewCipher(key)
	//设置解密方式
	blockMode := cipher.NewCBCDecrypter(block, key)
	//创建秘文大小的数组变量
	origData := make([]byte, len(crypted))
	//解密秘文到数组origData中
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS5UnPadding(origData)
	fmt.Println(string((origData)))
}

func main() {
	fmt.Println("hello world")
	//声明一个密钥,利用此密钥实现明文的加密和解密
	key := []byte("12345698")
	MyDesEncrypt([]byte("hello world "), key)
	MyDESDecrypt("NIJWb9F1DO11q08fSnB/HA==", key)
}
