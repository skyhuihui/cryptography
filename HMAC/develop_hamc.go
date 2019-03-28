package main

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"hash"
)

// 原理公式 hmac = H([key ^ opad] H([key ^ ipad] text))

//定义一个hmac的结构体
type hmac struct {
	size         int       //散列函数MD5的输出数据字节数
	B            int       // 加密块的长度
	opad, ipad   []byte    //分别重复16进制0x36和0x5c，使其字节长度等于blocksize
	outer, inner hash.Hash //hmac外部和内部压缩函数，类型是实现MD5的接口
}

//处理消息的组合方法
func (h *hmac) Sum(in []byte) []byte {
	origLen := len(in)

	//实现Sum这个接口的方法如下：
	/*func (d0 *digest) Sum(in []byte) []byte {
		d := *d0
		hash := d.checkSum()
		return append(in, hash[:]...)
	}*/
	//通过实现的方法，我们可以看出in一般传参为nil；d0就是要加密的信息；
	//要是in不为空，则代表需要将in后边填充已经运算过一段信息的hash值。
	//in就是消息第一次被hash处理的数据
	in = h.inner.Sum(in)

	//输出压缩函数保证初始hash为空
	h.outer.Reset()
	//将key与0x5c异或后的数据，写入
	h.outer.Write(h.opad)
	//再写入in
	h.outer.Write(in[origLen:])

	//最后得到组合后的数据，进行一次MD5运算就得到HMAC的hash值。
	return h.outer.Sum(in[:origLen])
}

//写入的方法
func (h *hmac) Write(p []byte) (n int, err error) {
	return h.inner.Write(p)
}

//方法返回散列函数输出数据字节数
func (h *hmac) Size() int { return h.size }

//方法返回散列函数的分割数据块字长
func (h *hmac) BlockSize() int { return h.B } //方法返回blocksize

//
func (h *hmac) Reset() {
	h.inner.Reset()
	h.inner.Write(h.ipad)
}

//创建一个hmac对象去实现hash.Hash这个接口
func New(h func() hash.Hash, key []byte) hash.Hash {
	hm := new(hmac)
	hm.outer = h() //输出压缩函数
	hm.inner = h() //输入压缩函数,函数是一个，都是MD5

	hm.size = hm.inner.Size()   //散列函数MD5的输出数据字节数=16
	hm.B = hm.inner.BlockSize() //散列函数的分割数据块字长=64

	//创建两个变量，用于去接收key变化之后的结果
	hm.ipad = make([]byte, hm.B)
	hm.opad = make([]byte, hm.B)
	if len(key) > hm.B {
		// 如果密码长度太大，对它进行hash运算。
		hm.outer.Write(key)
		key = hm.outer.Sum(nil)
	}
	//将key覆盖到创建的两个变量中
	copy(hm.ipad, key)
	copy(hm.opad, key)

	//copy key后的两个变量，分别将他的每一个元素与0x36和0x36异或运算
	for i := range hm.ipad {
		hm.ipad[i] ^= 0x36

	}
	for i := range hm.opad {
		hm.opad[i] ^= 0x36
	}

	//将异或后的值写入hm里。
	hm.inner.Write(hm.ipad)
	hm.outer.Write(hm.opad)

	return hm
}

func main() {

	//创建运算对象，HMAC需要两个参数：key和hash函数
	hmac := New(md5.New, []byte("23456uikjdfgh"))

	//将明文写入到hmac中
	hmac.Write([]byte("helloworld"))

	//hmac对象对写入数据的运算
	hashBytes := hmac.Sum(nil)

	//字节转换成字符串
	hash := hex.EncodeToString(hashBytes)

	fmt.Println(hash)

}
