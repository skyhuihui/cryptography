package main

import "fmt"

func main() {

	data := []byte("helloworld")
	output := make([]byte, len(data))
	fmt.Printf("明文:%s\n", data)

	K := []byte("qwuoa0knfabiufdhjfdsabjdfhfdsjkfdhsajkyfhdasjkfhdsajkfhdsjkfabkjhhjkdfbalafbj")
	keylen := len(K)
	SetKey(K, keylen)
	output = Transform(output, data, len(data))
	fmt.Printf("密文: %x\n", output)

	SetKey(K, keylen)
	output1 := make([]byte, len(data))
	output1 = Transform(output1, output, len(data))
	fmt.Printf("解密后明文:%s", output1)
}

var S = [256]int{}

//初始化S盒
func SetKey(K []byte, keylen int) {
	for i := 0; i < 256; i++ {
		S[i] = i
	}

	j := 0
	for i := 0; i < 256; i++ {
		j = (j + S[i] + int(K[i%keylen])) % 256

		S[i], S[j] = S[j], S[i]

	}

}

//生成密钥流
func Transform(output []byte, data []byte, lenth int) []byte {
	i := 0
	j := 0
	output = make([]byte, lenth)

	for k := 0; k < lenth; k++ {
		i = (i + 1) % 256
		j = (j + S[i]) % 256
		S[i], S[j] = S[j], S[i]
		key := S[(S[i]+S[j])%256]
		//按位异或操作

		output[k] = uint8(key) ^ data[k]

	}
	return output
}

/**
1. RC4实现过程
RC4算法的实现非常简单，使用从1到256个字节（8到2048位）可变长度密钥初始化一个256个字节的状态向量S，S的元素记为S[0]，S[1]，S[2]，...，S[255]，S先初始化为S[i]=i。以后自始至终都包含从0到255的所有8比特数，只是对它进行置换操作。
每次生成的密钥字节ki由S中256个元素按一定方法选出一个元素而生成。每生成一个密钥字节，S向量中元素会进行一次置换操作。则RC4算法分为两部分：初始化S和密钥流的生成，
其中密钥流的生成过程中每次产生的密钥字与对应明文的元素进行异或运算得到密文字。

1.1 初始化S
生成S的步骤如下：
1）声明一个长度为256的字节数组，并给S中的元素从0到255以升序的方式填充，即S[0]=0，S[1]=1，S[2]=2，...，S[255]=255。
2）j:=0
3）对于0<=i<=255，循环下边两个方法：
j = (j + S[i] + int(K[i%keylen])) % 256
S[i], S[j]=S[j], S[i]

1.2 密钥流的生成
步骤如下：
1）i=0；j=0
2）i = (i + 1) % 256
3）j = (j + S[i]) % 256
4）S[i], S[j]=S[j], S[i]
5）输出密钥字key = S[(S[i]+S[j])%256]

1.3 RC4的安全性
由于RC4算法加密采用的是异或方式，所以，一旦子密钥序列出现了重复，密文就有可能被破解，但是目前还没有发现密钥长度达到128位的RC4有重复的可能性，所以，RC4也是目前最安全的加密算法之一。

1.4 RC4加密过程
简单介绍下RC4的加密过程：
1）利用自己的密钥，产生密钥流发生器
2）密钥流发生器根据明文的长度产生伪随机序列
3）伪随机序列每个位元素与明文对应的位元素进行异或运算，生成密文
*/
