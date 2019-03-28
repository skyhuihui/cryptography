package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

//通过CFB模式，进行AES加密
//加密
func AESEncrypt(plaintext []byte, key []byte) []byte {
	//分组密钥,key字节的长度必须是16或24，或32；密钥的长度可以使用128位、192位或256位；位只有两种形式0和1，而字节是有8个位组成的。可以表示256个状态。1字节（byte）=8位（bit）
	block, _ := aes.NewCipher(key)
	//block 是个*aes.aesCipherGCMiv 类型 包含encode 和decode  这两个code类型是[]uint32, n。 n=BlockSize+28，n是新创建enc和dec的长度

	//创建数组，目的是存储你接下来加密的密文
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	//设置内存空间可读，类似在明文前面加入一个长度16切片，用于被读取内存流
	iv := ciphertext[:aes.BlockSize]
	//[]uint8
	//[0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
	//读内存流,把rand.reader随机读取的内存流数据复制到iv里
	io.ReadFull(rand.Reader, iv) //n是iv的长度
	//iv=[127 78 10 244 97 152 178 224 62 49 156 74 239 99 211 94]每次不一样，包含时间戳应该
	//设置加密模式，返回一个流，也就是把iv放到block里，返回stream流
	//下边方法将iv的数copy到block里的next字段的字节数组里
	stream := cipher.NewCFBEncrypter(block, iv)

	//&{0xc42007e2a0 [127 78 10 244 97 152 178 224 62 49 156 74 239 99 211 94]（输出和读出的iv一样） [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0] 16 false}
	//拿着你的密文进行异或运算，加密利用ciphertext[:aes.BlockSize]与明文进行异或,overlap使部分重叠

	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
	return ciphertext
}

//解密
func AesDecrypt(ciphertext []byte, key []byte) []byte {
	block, _ := aes.NewCipher(key)
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	//设置解密方式
	stream := cipher.NewCFBDecrypter(block, iv)
	//解密
	stream.XORKeyStream(ciphertext, ciphertext)
	return ciphertext
}
func main() {
	var encryptcode = AESEncrypt([]byte("hello world"), []byte("123456789abcde12"))
	var decryptcode = AesDecrypt(encryptcode, []byte("123456789abcde12"))
	fmt.Println(string(decryptcode))
	fmt.Println(base64.StdEncoding.EncodeToString(encryptcode))
}
