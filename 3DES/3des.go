package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"fmt"
)

//补码
func PKCS5Padding(ciphertext []byte, blocksize int) []byte {
	//求得补码的长度x
	padding := blocksize - len(ciphertext)%blocksize
	//将x转换成字节，并创建一个长度为x，元素都为x的切片
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	//返回补码后要加密的明文
	return append(ciphertext, padtext...)
}

//去码
func PKCS5UnPadding(origData []byte) []byte {
	//求得加密时补码的长度，长度就等于密文最后元素的10进制数字
	length := len(origData)
	unpadding := int(origData[length-1])
	//返回去码之后要进行解密的密文
	return origData[:(length - unpadding)]
}

//3DES加密
////3DES的密钥长度必须为24位
func TripleEncrypt(origData []byte, key []byte) []byte {
	//通过调用3des库里方法产生分组密钥块
	block, _ := des.NewTripleDESCipher(key)
	//补码
	origData = PKCS5Padding(origData, block.BlockSize())
	//设置加密模式，此处用CBC模式
	blockMode := cipher.NewCBCEncrypter(block, key[:8])
	//创建密文数组，加密
	crypted := make([]byte, len(origData))
	//加密
	blockMode.CryptBlocks(crypted, origData)
	return crypted
}

//解密
func TrileDesDecrypt(crypted, key []byte) []byte {
	//设置分组的密钥块
	block, _ := des.NewTripleDESCipher(key)
	//设置解密模式
	blockMode := cipher.NewCBCDecrypter(block, key[:8])
	//创建切片
	origData := make([]byte, len(crypted))
	//解密
	blockMode.CryptBlocks(origData, crypted)
	//去码得到原文
	origData = PKCS5UnPadding(origData)
	return origData
}
func main() {
	fmt.Println("hello world")
	var key = []byte("123456789012345678901239")
	var encirtcode = TripleEncrypt([]byte("hello world"), key)
	var decryptcode = TrileDesDecrypt(encirtcode, key)
	fmt.Printf("%x\n", encirtcode)
	fmt.Println(string(decryptcode))

}
