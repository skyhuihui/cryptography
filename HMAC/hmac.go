package main

import (
	hm "crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	ripe "golang.org/x/crypto/ripemd160"
)

//HMAC算法中文名称叫哈希消息认证码，英文全称是Hash-based Message Authentication Code。它的算法是基于某个哈希散列函数（主要是SHA系列和MD系列），以一个密钥和一个消息为输入，生成一个消息摘要作为输出。
// HMAC算法与其他哈希散列算法最大区别就是需要有密钥。它的算法函数是利用分组密码来建立的一个单向Hash函数

func Md5(data string) string {
	md5 := md5.New()
	md5.Write([]byte(data))
	md5Data := md5.Sum([]byte(""))
	return hex.EncodeToString(md5Data)
}

func Hmac(key, data string) string {
	hmac := hm.New(md5.New, []byte(key))
	hmac.Write([]byte(data))
	return hex.EncodeToString(hmac.Sum(nil))
}

func Sha1(data string) string {
	sha1 := sha1.New()
	sha1.Write([]byte(data))
	return hex.EncodeToString(sha1.Sum(nil))
}

func Sha256(data string) string {
	sha256 := sha256.New()
	sha256.Write([]byte(data))
	return hex.EncodeToString(sha256.Sum(nil))
}

func Ripemd160(data string) string {
	ripemd160 := ripe.New()
	ripemd160.Write([]byte(data))
	return hex.EncodeToString(ripemd160.Sum(nil))
}

// hash  算法
func main() {
	fmt.Println(Md5("hello"))
	fmt.Println(Hmac("key2", "hello"))
	fmt.Println(Sha1("hello"))
	fmt.Println(Sha256("hello"))
	fmt.Println(Ripemd160("hello"))
}
