# cryptography
加密 
1 密码学的发展历程
 密码学的发展大致可以分为三个阶段：古典密码学->现代密码学->公钥密码学

1 古典密码学：
（代替置换）这阶段的核心密码学思想主要为代替和置换。代替就是将明文每个字符替换成另外一种字符产生密文，接收者根据对应的字符替换密文就得到明文了。置换就是将明文的字符顺序按照某种规则打乱。
2.现代密码学：
（对称加密）这阶段的发展主要是对称加密算法。对称加密是发送方使用某种公开的算法使用密钥对明文进行加密，接收方使用之前发送方给予的密钥对密文进行解密得到明文。
3.公匙密码学：
（非对称加密）这个阶段的发展主要是非对称加密算法。非对称加密的原理是公钥加密，私钥解密。它的实现过程是A通过某种算法产生一对密钥，分别是公钥和私钥，然后将公钥公开。B想发送信息给A，就使用A的公钥对明文进行加密产生密文并发送给A。A接收到密文后，用自己的私钥对密文进行解密，得到明文。

2 密码学在区块链的应用
密码学在区块链的应用非常广泛，可分为3类：对称加密算法、非对称加密算法和哈希散列算法。常见的方法有： Merkle tree 哈希树算法，椭圆曲线算法，SHA-256算法，Base58编码。作用有：通过hash算法快速查找；对明文进行加解密；对信息进行签名以及验证；产生数字证书；生成账户地址等。

3 对称加密：

使用过程：
在对称加密算法中，数据发信方将明文（原始数据）和加密密钥一起经过特殊加密算法处理后，使其变成复杂的加密密文发送出去。收信方收到密文后，若想解读原文，则需要使用加密用过的密钥及相同算法的逆算法对密文进行解密，才能使其恢复成可读明文。在对称加密算法中，使用的密钥只有一个，发收信双方都使用这个密钥对数据进行加密和解密，这就要求解密方事先必须知道加密密钥。

特点：
对称加密算法的特点是算法公开、计算量小、加密速度快、加密效率高， 安全性差（双方都知道秘钥容易泄露），管理秘钥困难，没有签名功能

对称加密划分：
对称加密分为序列密码和分组加密。
序列密码，也叫流加密(stream cyphers)，依次加密明文中的每一个字节。加密是指利用用户的密钥通过某种复杂的运算（密码算法）产生大量的伪随机流，对明文流的加密。解密是指用同样的密钥和密码算法及与加密相同的伪随机流，用以还原明文流。

分组密码，也叫块加密(block cyphers)，一次加密明文中的一个块。是将明文按一定的位长分组，明文组经过加密运算得到密文组，密文组经过解密运算（加密运算的逆运算），还原成明文组。

序列密码
序列密码，也叫流密码，是利用种子密钥通过密钥流生成器产生与明文长度一致的伪随机序列，该随机序列与明文进行某种算法相结合产生的密文的一种密码算法。

序列密码具有实现简单、便于硬件实施、加解密处理速度快、没有或只有有限的错误传播等特点，但是因为这类密码主要运用在军事，政治机密机构上，因此它的研究成果较少有公开。目前可以公开在其他领域应用的算法有RC4，SEAL，A5等

序列密码的结构可细分为  同步流密码和  自同步流密码。同步流密码指它的密钥流的产生与明文无关，而是通过某种独立的随机方法产生的伪随机数字流。自同步流密码也叫异步流密码，它与同步流密码相反，密钥流的产生与明文有关，具体是后一个密钥字的产生与前一个明文加密后的字有关。自同步密码这个特性，使得它非常难以研究，所以大部分序列密码的研究都集中在同步密码上。

同步流密码产生密码流的过程分为两部分，一个是密钥流产生器，另一个是加密变换器。
加密过程表达式是：ci=E(ki,mi)，参数都是字节数组的单个元素。解密过程和加密过程必须同步，表达式是一个。因为密钥流的产生每次都是不一样的。所以加密时，每次产生的密钥流元素先缓存到寄存器中，等解密用完这个元素以后再继续进行加密。整个过程有点类似tcp协议。目前最为常用的流密码体制是有限域GF(2)上的二元加法流密码，其加密变换可表示为ci=ki⊕mi。
特点：
1）同步要求
在同步流密码中，发送方和接收方必须是同步的，即双方使用同样的密钥，对同一位置进行操作。一旦密文字符在传输中出现丢失，损坏或者删除，那么解密将失败
2）无错误传播
密文字符在传输过程中被修改，只是对该字符产生影响，并不影响其他密文字符的解密。
3）主动攻击性破坏同步性
作为同步要求的结果，主动攻击者对传输中的密文字符进行重放，插入，删除等破坏操作，直接会造成加解密过程的同步性。所以在使用时，需要借助其他密码学技术对传输的密文进行认证和完整性的验证操作。

自同步密码的密钥流的产生不独立于明文流和密文流，通常第i个密钥字的产生不仅与主密钥有关，而且与前面已经产生的若干个密文字有关。
特点：
1）自同步
发送方在传输密文流过程中，某些密文字符被攻击，接收方的解密只是在这些被攻击过的密文与发送方不同步，而其他密文流解密同步不会有问题。
2）有限的错误传播
接收方的解密只是对攻击过的i个密文字符有影响，而对其他密文流不会有问题。所以产生的明文至多有i个错误。
3）主动攻击破坏当前的同步性
4）明文统计扩算
每个明文字符都会影响其后的整个密文，即明文的统计学特性扩散到了密文中。因此，自同步流密码在抵抗利用明文冗余而发起的攻击方面要强于同步流密码。

分组密码
分组密码，也叫块加密，英文Block Cyper，一般先对明文m进行填充得到一个长度是固定分组长度s的整数倍明文串M；然后将M划分成一个个长度为s的分组；最后对每个分组使用同一个密钥执行加密变换。比较常见的算法有AES;DES;3DES。
分组密码中，无论是明文块还是密文块，块与块之间都有一些逻辑运算关系，这些关系即为运算的模式
Electronic Code Book(ECB)电子密码本模式
Cipher Block Chaining(CBC)密码分组链接模式
Cipher Feedback Mode(CFB)加密反馈模式
Output Feedback Mode(OFB)输出反馈模式
Counter mode（CTR）计数器模式
目前推荐使用的是CBC模式和CTR模式，其它模式较少使用或不推荐使用。
1. ECB模式
ECB又称电子密码本模式，英文全称是Electronic codebook，是最基本的块密码加密模式，加密前根据加密块大小（如AES为128位）分成若干块，如果最后一块不足128位，使用填充(具体看算法，默认是0x00)，之后将每个块使用相同的密钥单独加密得到密文块，然后将密文块连在一起就得到密文了。解密同理。

加密过程：
图片: http://img.kongyixueyuan.com/ECB%E5%8A%A0%E5%AF%86.jpg
解密过程：
图片: http://img.kongyixueyuan.com/ECB%E8%A7%A3%E5%AF%86.jpg
由此得知相同的明文内容将永远加密成相同的密文，而且密文的格式和明文也相同。这是很不安全的，尤其是传输图片或明文内容重复很多的情况下。由于所有分组的加密方式一致，明文中的重复内容会在密文中有所体现，因此难以抵抗统计分析攻击。还有因为明文和密文的内容顺序一致，攻击者很容易破坏密文。攻击者在密文传输过程中截获，并对密文内容次序打乱，接收密文信息者得到的密文就不可能解密成原本的明文信息了。这也是ECB模式很少使用的原因。
特点：
1.操作简单，易于实现，有利于并行计算，误差不会被传送；
2.不能隐藏明文的模式；
3.可能对明文进行主动攻击；

2. CBC模式
CBC又称密文分组链接模式，英文全称是Cipher Block Chaining，之所以叫这个名字，是因为密文分组像链条一样相互连接在一起。
在CBC模式中，每个明文块先与前一个密文块进行异或后，再进行加密。在这种方法中，每个密文块都依赖于它前面的所有明文块。同时，为了保证每条消息的唯一性，在第一个块中需要使用初始化向量。
若第一个块的下标为1，则CBC模式的加密过程为：
Ci = Ek (P ⊕ Ci-1), C0 = IV.
而其解密过程则为：
Pi = Dk (Ci) ⊕Ci-1, C0 = IV.
CBC模式运算过程示意图：
图片: http://img.kongyixueyuan.com/CBC%E5%8A%A0%E5%AF%86.jpg
图片: http://img.kongyixueyuan.com/CBC%E8%A7%A3%E5%AF%86.png
CBC算法优点：
明文的重复排列不会反映在密文中
支持并行计算（仅解密）
能够解密任意密文分组
CBC算法缺点：
对包含某些错误比特的密文进行解密时，第一个分组的全部比特以及后一个分组的相应比特会出错
加密不支持并行计算
3.CFB模式
CFB又称密文反馈，英文全称为Cipher feedback。模式类似于CBC，可以将块密码变为自同步的流密码；工作过程亦非常相似。需要使用一个与块的大小相同的移位寄存器，并用IV将寄存器初始化。然后，将寄存器内容使用块密码加密，然后将结果的最高x位与平文的x进行异或，以产生密文的x位。下一步将生成的x位密文移入寄存器中，并对下面的x位平文重复这一过程。解密过程与加密过程相似，以IV开始，对寄存器加密，将结果的高x与密文异或，产生x位平文，再将密文的下面x位移入寄存器。
与CBC相似，明文的改变会影响接下来所有的密文，因此加密过程不能并行化；而同样的，与CBC类似，解密过程是可以并行化的。
CFB模式运算过程示意图：
加密过程：
图片: http://img.kongyixueyuan.com/CFB%E5%8A%A0%E5%AF%86.png解密过程：
图片: http://img.kongyixueyuan.com/CFB%E8%A7%A3%E5%AF%86.png
CFB模式的优点：
不需要填充（padding）
支持并行计算（仅解密）
能够解密任意密文分组
CFB模式的缺点：
加密不支持并行计算
对包含某些错误比特的密文进行解密时，第一个分组的全部比特以及后一个分组的相应比特会出错
不能抵御重放攻击
4. OFB模式
OFB：将分组密码作为同步序列密码运行，和CFB相似，不过OFB用的是前一个n位密文输出分组反馈回移位寄存器，OFB没有错误扩散问题。
输出反馈模式（Output feedback, OFB）可以将块密码变成同步的流密码。它产生密钥流的块，然后将其与平文块进行异或，得到密文。与其它流密码一样，密文中一个位的翻转会使平文中同样位置的位也产生翻转。这种特性使得许多错误校正码，例如奇偶校验位，即使在加密前计算而在加密后进行校验也可以得出正确结果。
每个使用OFB的输出块与其前面所有的输出块相关，因此不能并行化处理。然而，由于平文和密文只在最终的异或过程中使用，因此可以事先对IV进行加密，最后并行的将平文或密文进行并行的异或处理。
可以利用输入全0的CBC模式产生OFB模式的密钥流。这种方法十分实用，因为可以利用快速的CBC硬件实现来加速OFB模式的加密过程。
加密过程：
图片: http://img.kongyixueyuan.com/OFB%E5%8A%A0%E5%AF%86.png
解密过程：
图片: http://img.kongyixueyuan.com/OFB%E8%A7%A3%E5%AF%86.png
OFB模式的优点：
不需要填充（padding）
可事先进行加密、解密的准备
加密、解密使用相同结构
对包含某些错误比特的密文进行解密时，只有铭文中相应的比特会出错
OFB模式的缺点：
不支持并行运算
主动攻击这反转密文分组中的某些比特时，明文分组中相对应的比特也会被反转
5. CTR模式
计数模式（CTR模式）加密是对一系列输入数据块(称为计数)进行加密，产生一系列的流密码，流密码与明文异或得到密文，同样解密就是流密码与密文异或得到明文。
数据块是加密之前通过将逐次累加的计数器产生不同的比特序列，它是由nonce和counter（分组序号）构成的。CTR计数器，长度是128比特(16字节)。前8个字节是叫做nonce的初始值，这个值每次加密都不相同。后8个字节则是分组序号，也就是不断+1得到的值。nonce的作用是让数据块内容复杂化。如果没有nonce，只有counter，数据块过于单一。Golang里封装的计数器实现与这里讲的有些许不同，首先初始化一个长度为BLOCK.SIZE()的初始向量iv，然后iv最后一个字节通过计数器逐组递增，同样也会产生分组加密之前不同的数据块。
加密的过程就是生成一个初始的计数器。假设有8个分组，就通过初始计数器不断+1得到8个计数器值，每个计数器值再加密得到密钥流，每个密钥流和对应分组明文异或得到密文。所以它的加密过程相当于一次一密。
CTR模式中可以以任意顺序对分组进行加密和解密，因为在加密和解密时需要用到的“计数器”的值可以由nonce和分组序号直接计算出来。这就意味着能够实现并行计算。在支持并行计算的系统中，CTR模式的速度是非常快的。
下图展示CTR模式的加解密的过程：
加密过程：
图片: http://img.kongyixueyuan.com/CTR%E5%8A%A0%E5%AF%86.png解密过程：
图片: http://img.kongyixueyuan.com/CTR%E8%A7%A3%E5%AF%86.png
CTR模式的优点：
不需要填充（padding）
可事先进行加密、解密的准备
加密、解密使用相同的结构
对包含某些错误比特的密文进行解密时，只有明文中相对应的比特会出错
支持并行计算（加密、解密）
CTR模式的缺点：
主动攻击者反转密文分组中的某些比特时，明文分组中对应的比特也会被反转
没有错误传播，不适合用于数据完整性认证。
分组密码模式比较


DES算法
DES算法为密码体制中的对称密码体制，又被称为美国数据加密标准，是1972年美国IBM公司研制的对称密码体制加密算法，英文全称是Data Encryption Standard。于1973年5月被美国采纳为联邦信息处理标准。该标准每5年审查一次。因为DES的安全性出现问题，同时AES的出现，美联邦在1994年1月取消了DES作为联邦加密标准。DES加密不断被破解，其中用时最短的时间是22小时15分钟，所以DES算法现在应用越来越少了。
DES是以64比特的明文为一个单位来进行加密的，超过64比特的数据，要求按固定的64比特的大小分组。每组64比特的明文加密得到同样长度的密文。DES的密钥长度为64位。加密运算时实际用到的密钥长度是56位，原密钥舍弃掉8位比特，分别是每隔8位的比特，即原密钥的第8位，第16位，......，第64位。而舍弃掉的这8位比特作用是校验奇偶性的。这8个比特的定义如下：若其前面7个比特中有奇数个1，则该比特为0，反之为1。

1. DES算法加密过程
DES是一个迭代分组密码，在对明文加密之前先对明文进行补长，使补长后明文的比特长度模64为0，再按照每组64比特分组。依次对分组密文进行加密，最终把加密后的结果拼接一起，得到密文。
每组64位的输入数据块m的加密过程如下：
1) 首先m经过初始置换IP得到m0 ；
2) 将m0分成左右各为32比特两部分，记为m0 = L0 R0 ；
3) 对L0和R0进行16轮迭代运算加密，得到L16和R16；
4) 再对L16R16进行初始置换IP的逆初始置换IP^-1 ，得到该分组输入块的密文

2 DES算法解密过程
加密和解密使用相同的算法。加密和解密唯一不同的是秘钥的次序是相反的。就是说如果每一轮的加密秘钥分别是K1、K2、K3...K16，那么解密秘钥就是K16、K15、K14...K1。为每一轮产生秘钥的算法也是循环的。加密是秘钥循环左移，解密是秘钥循环右移。解密秘钥每次移动的位数是：0、1、2、2、2、2、2、2、1、2、2、2、2、2、2、1。具体不做讲解。但是要注意一点，解密的结果并不一定是我们原来的加密数据，可能还含有你补得位，一定要把补位去掉才是你的原来的数据。

3 DES算法特点
1、分组加密算法：
以64位为分组。64位明文输入，64位密文输出。
2、对称算法：
加密和解密使用同一秘钥
3、有效密钥长度为56位
秘钥通常表示为64位数，但每个第8位用作奇偶校验，可以忽略。
4、代替和置换
DES算法是两种加密技术的组合：混乱和扩散。先替代后置换。
5、易于实现
DES算法只是使用了标准的算术和逻辑运算，其作用的数最多也只有64 位，因此用70年代末期的硬件技术很容易实现

3DES算法
3DES，或叫3重DES，英文全称是triple-DES，是普通DES的升级改进版。在AES未出现之前，DES加密慢慢被发现存有较大的安全性，为此3DES作为过渡期的重要对称加密诞生了。1999年，NIST将3-DES指定为过渡的加密标准。
3DES并不是一个全新的加密算法，它可以被认为是DES系列的加密范畴。DES的密钥长度是8个字节，由于长度较短，较容易被暴力破解。增加密钥的长度成为提高DES安全性的重大突破口。密钥长度增加至2倍，也就是2DES（双重DES），但这个算法存在一种中间相遇攻击隐患，对其安全性构成了威胁，所以实际应用中，很少或不推荐双重DES。密码长度增加至3倍，也就是3DES。该算法不仅很大提高了DES的安全性，而且还可以抵抗中间相遇攻击。到目前为止，还没有相关它被暴力破解或其它安全性受到威胁的信息。尽管已经公布了高级加密标准AES，但是目前3DES还被当作一个安全有效的加密算法在使用。
3DES算法的原理及加解密过程
密钥长度为192bit（也就是24字节），加密过程是进行3次DES加密或解密的密码算法叫3DES。
由于当时DES算法的应用较多，所以设计3DES不得不考虑与DES的兼容问题，也就是2者之间可以混用，3DES加密，DES能够解密，DES加密，3DES能够解密。最终IBM公司设计出来了合理方案，将第2重加密过程改为解密过程，整体的加密过程是加密-->解密-->加密，当3DES的密钥是DES密钥的3次重复时，两者完全兼容，此时的3DES实际只有最后一重加密是有效的。如果3DES的密钥不是DES密钥的3次重复，此时两者不存在兼容，3DES的第二重解密实际上也是加密过程，只不过用的DES的解密算法而已。
3DES加密解密过程首先对输入的私钥平均分成3组，每组密钥对应一重DES算法，其具体实现如下：
设Ek()和Dk()代表DES算法的加密和解密过程，k代表DES算法使用的密钥，M代表明文，C代表密文，这样：
3DES加密过程为：C=Ek3(Dk2(Ek1(M)))
3DES解密过程为：M=Dk1(EK2(Dk3(C)))
AES算法
AES英文全称是Advanced Encryption Standard,中文是高级加密标准。它的出现就是为了替代之前的加密标准DES。1997年1月2号，美国国家标准技术研究所（National Institute of Standards and Technology: NIST）发起征集高级加密标准算法的活动，目的是重新确立一种新的分组密码代替DES，成为新的美联邦信息处理的标准。该活动得到了全世界很多密码工作者的响应，先后有很多人提交了自己设计的算法。最终获胜的是由两位比利时的著名密码学家Joan Daemen和Vincent Rijmen设计的Rijndael算法。2001年11月，NIST正式公布该算法，命名为AES算法。

1. AES算法原理
AES算法采用分组密码体制，即AES加密会首先把明文切成一段一段的，而且每段数据的长度要求必须是128位16个字节，如果最后一段不够16个字节，需要用Padding来把这段数据填满16个字节，然后分组对每段数据进行加密，最后再把每段加密数据拼起来形成最终的密文。AES算法的密钥长度可以有三种，分别是128位，256位，512位。
AES算法的加密过程使用了四个变换：字节替换变换（SubBytes）、行移位变换（SiftRows）、列混淆变换（MixColumns）和轮密钥加变换（AddRoundKey）。解密过程用了这四个变换的逆操作，分别是逆字节替换变换（InvSubBytes）、逆行移位变换（InvShiftRows）、逆列混淆变换（InvMixColumns）和轮密钥加变换。这里说明一下，轮密钥加变换的逆运算就是它本身，所以名字就通用一个。

字节替换变换
字节替换变换是一个非线形变换。输入的任意字节我们看作是有限域GF(2^8 )的元素，也就是这些字节都会在这个有限域内找到。在这个有限域内任何元素通过映射运算都会找到与之对应的元素，而且他们之间映射是可逆的。根据这个映射关系，制作了一个S盒对照表。根据这个表我们会很容易的查找对应的映射元素。如果输入的字节为xy，查找S盒中的第x行盒第y列找到对应的值，将其输出替换xy输出。例如1D，替换之后就是A4。

逆字节替换变换
逆字节替换变换是字节替换变换的逆变换。字节替换变换的映射运算是可逆的，所以根据映射逆运算也制作了一张逆S盒的对照表。查找方法与字节替换变换方法一样。例如A4，替换之后就是1D。

行移位变换
行移位的功能是实现一个4x4矩阵内部字节之间的置换。AES算法的明文分组要求是每组的字节长度为16，就是因为能够刚好转换成4x4矩阵。
行移位的过程：第一行保持不变，第二行循环左移1个字节，第三行循环左移2个字节，第四行循环左移3个字节

逆行移位变换
逆向行移位即是相反的操作。即第一行保持不变，第二行循环右移1个字节，第三行循环右移2个字节，第四行循环右移3个字节。

 列混淆变换
列混淆变换将状态矩阵中的每一列视为系数在GF(2^8 )上的次数小于4的多项式与同一个固定的多项式a(x)进行模多项式m(x)=x^4 +1的乘法运算。在AES中，a(x)={03}x^3 +{01}x^2 +{01}x+{02}。

逆列混淆变换
逆列混淆变换是列混淆变换的逆，它将状态矩阵中的每一列视为系数在GF(2^ 8)上的次数小于4的多项式与同一个固定的多项式a^-1 (x)进行模多项式m(x)=x^4 +1的乘法运算。a^-1 (x)={0B}x^3 +{0D}x^2 +{09}x+{0E}。

轮密钥加变换
任何数和自身的异或结果为0。加密过程中，每轮的输入与轮密钥异或一次；因此，解密时再异或上该轮的密钥即可恢复输入。

密钥扩展算法
AES加密的每一轮用到的密钥都是不一样的。AES密钥扩展算法的输入值是4个字（16字节），输出值是一个由44个字组成（176字节）的一维线性数组。

非对称加密算法
非对称加密也叫公钥密码。
1976年Diffie和Hellman首次提出了一种全新的加密思想，公钥密码体制思想。在当时几乎所有的密码体制都是对称密码体制，原理都是基于替换和置换这些较简单方法。公钥密码体制完全与之不同，它是非对称的，有两个不同的密钥，分别是公钥和私钥，加密的原理也不是之前的简单置换或替换，而是一些复杂的数学函数。这些数学函数都是基于数学难题。其所依据的难题一般分为三类：大整数分解问题类、离散对数问题类、椭圆曲线类。有时也把椭圆曲线类归为离散对数类。公钥密码体制是一次革命性的变革，突破了原有的密码体制模式，它解决了传统密码体制的两个大难题：密钥分配和数字签名。

1 非对称加密的概述
传统密码体制用的都是一个密钥，发送方传输密钥给接收方成本很高，而且风险很大。接收方收到的密文如果在传输过程中被修改，接收方无法判断密文的真伪性。公钥体制完美地解决了上述问题。它有一对密钥，一个是公钥，完全公开，任何人都可以收到该密钥；另一个是私钥，自己保存，不需要告诉任何人。通过公开的公钥是无法计算出私钥的，所以私钥是安全的。发送方A用公钥对明文进行加密，接收方B用对应的私钥进行解密。为保证传输密文的完整性和消息来源的准确性，需要对密文进行数字签名。A对密文用自己的私钥进行再次加密，此过程叫数字签名；B接收到密文用该私钥对应的公钥进行解密，此过程叫验签。
所以公钥密码体制可以分为两个模型：加密解密模型和签名验签模型。两个模型可以独立使用，也可以一起混用。具体按照自己的应用场景使用，一般情况下发送的密文都是需要进行数字签名的，发送的内容包括密文和签名两部分。接受者先进行验签，验签通过后，再进行解密。
非对称加密的方式有很多，以下讲解RSA，DSA，ECDSA这三种加密方式。

2 公钥密码体制的要求
公钥密码体制要想实现必须满足以下要求：
1.产生一对密钥对，即公私钥对，在计算上是容易的；
2.通过公钥对明文进行加密，在计算上是容易的；
3.通过私钥对密文进行解密，在计算上是容易的；
4.已知公钥，无法计算出私钥；
5.已知公钥和密文，无法计算出明文；
6.加密和解密的顺序可以交换。
目前满足以上要求，建立公钥密码体制基于的困难问题有较多，我只分析以下两种常用的：
1.大整数分解问题
若已知两个大素数p和q，求n=pq是很容易的，但是已知n，求p和q是几乎不可能的，这就是大整数分解问题。
2.离散对数问题
先了解两个概念，阶和原根。
设m > 1 且 (a, m) = 1, 则使得a^t ≡ 1 mod m成立的最小的正整数t称为a对模m的阶, 记为δm(a)。
原根，是一个数学符号。设m是正整数，a是整数，若a模m的阶等于φ(m)，则称a为模m的一个原根。里面提到的φ(m)是m质因数的个数。
给定一个公式a^t mod b ≡ c，其中a是b的原根，b是一个超大的素数，c是小于b大于0的正整数。问题是已知a，t，b求c很容易，但是已知a，b，c求t非常困难。这就是离散对数问题。
举个例子（b取个小值）：根据给定的t求 3^t mod 17很容易。t=1时，得3；t=2时，得9；t=3时，得10，等等最终的结果都是在小于17大于0的正整数。但是现在3^t mod 17≡12，求t。求解过程非常困难，而且满足条件的t不计其数。这里用的是17，如果换成很大的数，那几乎没有可能求解出来真正的t。

RSA算法
RSA是目前使用最广泛的公钥密码体制之一。它是1977年由罗纳德·李维斯特（Ron Rivest）、阿迪·萨莫尔（Adi Shamir）和伦纳德·阿德曼（Leonard Adleman）一起提出的。当时他们三人都在麻省理工学院工作。RSA就是他们三人姓氏开头字母拼在一起组成的。
RSA算法的安全性基于RSA问题的困难性，也就是基于大整数因子分解的困难性上。但是RSA问题不会比因子分解问题更加困难，也就是说，在没有解决因子分解问题的情况下可能解决RSA问题，因此RSA算法并不是完全基于大整数因子分解的困难性上的。
1. RSA算法描述
1.1 RSA产生公私钥对
具体实例讲解如何生成密钥对
1.随机选择两个不相等的质数p和q。
alice选择了61和53。（实际应用中，这两个质数越大，就越难破解。）
2.计算p和q的乘积n。
n = 61×53 = 3233
n的长度就是密钥长度。3233写成二进制是110010100001，一共有12位，所以这个密钥就是12位。实际应用中，RSA密钥一般是1024位，重要场合则为2048位。
3.计算n的欧拉函数φ(n)。称作L
根据公式φ(n) = (p-1)(q-1)
alice算出φ(3233)等于60×52，即3120。
4.随机选择一个整数e，也就是公钥当中用来加密的那个数字
条件是1< e < φ(n)，且e与φ(n) 互质。
alice就在1到3120之间，随机选择了17。（实际应用中，常常选择65537。）
5.计算e对于φ(n)的模反元素d。也就是密钥当中用来解密的那个数字
所谓"模反元素"就是指有一个整数d，可以使得ed被φ(n)除的余数为1。ed ≡ 1 (mod φ(n))
alice找到了2753，即17*2753 mode 3120 = 1
6.将n和e封装成公钥，n和d封装成私钥。
在alice的例子中，n=3233，e=17，d=2753，所以公钥就是 (3233,17)，私钥就是（3233, 2753）。
1.2 RSA加密
首先对明文进行比特串分组，使得每个分组对应的十进制数小于n，然后依次对每个分组m做一次加密，所有分组的密文构成的序列就是原始消息的加密结果，即m满足0<=m<n，则加密算法为：
c≡ m^e mod n; c为密文，且0<=c<n。
1.3 RSA解密
对于密文0<=c<n，解密算法为：
m≡ c^d mod n;
1.4 RSA签名验证
RSA密码体制既可以用于加密又可以用于数字签名。下面介绍RSA数字签名的功能。
已知公钥（e，n），私钥d
1.对于消息m签名为：sign ≡ m ^d mod n
2.验证：对于消息签名对（m，sign），如果m ≡ sign ^e mod n，则sign是m的有效签名

DSA算法
DSA（Digital Signature Algorithm）是Schnorr和ElGamal签名算法的变种，被美国NIST作为DSS(DigitalSignature Standard)。
DSA加密算法主要依赖于整数有限域离散对数难题，素数P必须足够大，且p-1至少包含一个大素数因子以抵抗Pohlig &Hellman算法的攻击。M一般都应采用信息的HASH值。DSA加密算法的安全性主要依赖于p和g，若选取不当则签名容易伪造，应保证g对于p-1的大素数因子不可约。其安全性与RSA相比差不多。
DSA 一般用于数字签名和认证。在DSA数字签名和认证中，发送者使用自己的私钥对文件或消息进行签名，接受者收到消息后使用发送者的公钥来验证签名的真实性。DSA只是一种算法，和RSA不同之处在于它不能用作加密和解密，也不能进行密钥交换，只用于签名,它比RSA要快很多.

1. DSA签名及验证
DSA算法中应用了下述参数：
p：L bits长的素数。L是64的倍数，范围是512到1024；
q：p – 1的160bits的素因子；
g：g = h^((p-1)/q) mod p，h满足h < p – 1, h^((p-1)/q) mod p > 1；
x：x < q，x为私钥 ；
y：y = g^x mod p ，( p, q, g, y )为公钥；
H( x )：One-Way Hash函数。DSS中选用SHA( Secure Hash Algorithm )。
p, q, g可由一组用户共享，但在实际应用中，使用公共模数可能会带来一定的威胁。
签名及验证协议：
1.P产生随机数k，k < q；
2.P计算 r = ( g^k mod p ) mod q
s = ( k^(-1) (H(m) xr)) mod q
签名结果是( m, r, s )。
3.验证时计算 w = s^(-1)mod q
u1 = ( H( m ) w ) mod q
u2 = ( r w ) mod q
v = (( g^u1 * y^u2 ) mod p ) mod q
若v = r，则认为签名有效。

椭圆曲线算法ECC ECDSA
1. 椭圆曲线密码学简介

椭圆曲线密码学（英语：Elliptic curve cryptography，缩写为 ECC），一种建立公开密钥加密的算法，基于椭圆曲线数学。椭圆曲线在密码学中的使用是在1985年由Neal Koblitz和Victor Miller分别独立提出的。
ECC的主要优势是在某些情况下它比其他的方法使用更小的密钥——比如RSA加密算法——提供相当的或更高等级的安全。
椭圆曲线密码学的许多形式有稍微的不同，所有的都依赖于被广泛承认的解决椭圆曲线离散对数问题的困难性上.
不管是RSA还是ECC或者其它，公钥加密算法都是依赖于某个正向计算很简单（多项式时间复杂度），而逆向计算很难（指数级时间复杂度）的数学问题。
椭圆曲线依赖的数学难题是:
k为正整数，G是椭圆曲线上的点（称为基点）, k*G=Q , 已知G和Q，很难计算出k
2. 椭圆曲线
一般，椭圆曲线可以用如下二元三阶方程表示：
  y² = x³ + ax + b，其中a、b为系数。
参数a=0;b=7,得到y² = x³ +7，这个方程式产生的曲线就是secp256k1曲线。
曲线形状：图片: http://img.kongyixueyuan.com/%E6%A4%AD%E5%9C%86%E6%9B%B2%E7%BA%BF%E5%9B%BE.jpg
3. 椭圆曲线在密码学的应用
椭圆曲线是连续的，并不适合用于加密；所以，我们必须把椭圆曲线变成离散的点，我们要把椭圆曲线定义在有限域上。
我们给出一个有限域Fp，Fp中有p（p为质数）个元素0,1,2,…, p-2,p-1
Fp的加法是a+b≡c(mod p)
Fp的乘法是a×b≡c(mod p)
Fp的除法是a÷b≡c(mod p)，即 a×b^(-1)≡c (mod p)，b-1也是一个0到p-1之间的整数，但满足b×b-1≡1 (mod p)
考虑K=kG ，其中K、G为椭圆曲线Ep(a,b)上的点，n为G的阶（nG=O∞ ），k为小于n的整数。则给定k和G，根据加法法则，计算K很容易但反过来，给定K和G，求k就非常困难。因为实际使用中的ECC原则上把p取得相当大，n也相当大，要把n个解点逐一算出来列成上表是不可能的。这就是椭圆曲线加密算法的数学依据。 点G称为基点（base point）k（k 小于n）为私有密钥（privte key），K为公开密钥（public key)
4. 椭圆曲线运算
• 加法
• 过曲线上的两点A、B画一条直线，找到直线与椭圆曲线的交点，交点关于x轴对称位置的点，定义为A+B，即为加法。如下图所示：
图片: http://img.kongyixueyuan.com/%E6%A4%AD%E5%9C%86%E6%9B%B2%E7%BA%BF%E5%8A%A0%E6%B3%95%E8%BF%90%E7%AE%97.jpg• 二倍运算
• 上述方法无法解释A + A，即两点重合的情况。因此在这种情况下，将椭圆曲线在A点的切线，与椭圆曲线的交点，交点关于x轴对称位置的点，定义为A + A，即2A，即为二倍运算。
图片: http://img.kongyixueyuan.com/%E6%A4%AD%E5%9C%86%E6%9B%B2%E7%BA%BF2%E5%80%8D%E8%BF%90%E7%AE%97.jpg• 正负取反
• 将A关于x轴对称位置的点定义为-A，即椭圆曲线的正负取反运算。如下图所示：
图片: http://img.kongyixueyuan.com/%E6%A4%AD%E5%9C%86%E6%9B%B2%E7%BA%BF%E6%AD%A3%E8%B4%9F%E8%BF%90%E7%AE%97.jpg• 无穷远点
• 如果将A与-A相加，过A与-A的直线平行于y轴，可以认为直线与椭圆曲线相交于无穷远点。
综上，定义了A+B、2A运算，因此给定椭圆曲线的某一点G，可以求出2G、3G（即G + 2G）、4G......。即：当给定G点时，已知x，求xG点并不困难。反之，已知xG点，求x则非常困难。此即为椭圆曲线加密算法背后的数学原理。
5. 有限域上的椭圆曲线运算
• 椭圆曲线要形成一条光滑的曲线，要求x,y取值均为实数，即实数域上的椭圆曲线。但椭圆曲线加密算法，并非使用实数域，而是使用有限域。按数论定义，有限域GF(p)指给定某个质数p，由0、1、2......p-1共p个元素组成的整数集合中定义的加减乘除运算。
• 假设椭圆曲线为y² = x³ + x + 1，其在有限域GF(23)上时，写作：y² ≡ x³ + x + 1 (mod 23)
• 此时，椭圆曲线不再是一条光滑曲线，而是一些不连续的点。以点(1,7)为例，7² ≡ 1³ + 1 + 1 ≡ 3 (mod 23)。如此还有如下点：
• (0,1) (0,22)(1,7) (1,16)(3,10) (3,13)(4,0)(5,4) (5,19)(6,4) (6,19)(7,11) (7,12)(9,7) (9,16)(11,3) (11,20)等等。
• 另外，如果P(x,y)为椭圆曲线上的点，则-P即(x,-y)也为椭圆曲线上的点。如点P(0,1)，-P=(0,-1)=(0,22)也为椭圆曲线上的点。
6. 椭圆曲线加密算法原理
设私钥、公钥分别为k、K，即K = kG，其中G为G点。
公钥加密：
选择随机数r，将消息M生成密文C，该密文是一个点对，即：
C = {rG, M+rK}，其中K为公钥
私钥解密：
M + rK - k(rG) = M + r(kG) - k(rG) = M
其中k、K分别为私钥、公钥。
7. 椭圆曲线签名算法原理
• 椭圆曲线签名算法，即ECDSA。设私钥、公钥分别为k、K，即K = kG，其中G为G点。
• 私钥签名：
• 1、选择随机数R，计算点RG(x, y)。
• 2、根据随机数R、消息M的哈希h、私钥k，计算出两个*big.int类型的数r，s。
• 3、将r，s转换成字节切片，并拼接一起，形成签名
• 4、将消息M、和签名发给接收方。
公钥验证签名：
1、接收方收到消息M、以及签名。
2、将签名提取出r，s
3、根据消息求哈希h。
4、通过r，s产生的一个点，如果这个点在椭圆曲线上，即验签成功。


HASH算法
哈希函数是密码学中的一个重要分支，该函数是一类数学函数，它可以在有限的合理时间内，将任意长度的消息变换成固定长度的二进制串，且不可逆，这个输出值就是哈希值，也叫散列值或消息摘要。以hash函数为基础的hash算法，在数字签名，实现数据完整性，merkle树数据存储和检索等方面有着广泛的应用。
在比特币系统中使用了两个密码学hash函数，一个是SHA256,另一个是ripemd160。ripemd160主要用于生成比特币地址，SHA256是比特币链上几乎所有加密算法的hash函数。
1. 技术原理
hash函数也叫散列函数，杂凑函数。它是一种单向密码机制，也就是只能加密，而不能解密。数学表达式可以为：h=H(m)，其中H是哈希函数，m是要加密的信息，h是输出的固定长度的哈希值。运算过程是设定一个初始向量，对消息补长到算法要求长度，将补长后的消息拆分成N份数据块，N份数据块与初始向量通过hash算法进行迭代循环运算，最终得到固定长度的hash值。
hash函数具有以下特点：
压缩性：对任意长度的信息加密成固定长度的hash值；
单向性：hash函数的数学原理没有逆运算，所以不能将hash值转换成加密前的信息；
抗碰撞性：hash函数的运算过程相当复杂，包含多种数学运算和大量变量循环运算，要满足两个不同的消息产生相同的hash值几乎不可能发生；
高灵敏性：任何微小的输入都有可能对输出产生巨大的影响。
典型的hash函数有两类：消息摘要算法（MD5）和安全散列算法（SHA）。
2. hash碰撞
理想的hash函数对于不同的输入得到两个不同的hash值。在实际中，如果存在两个不同的信息m，m'使H(m)=H(m')，那么就称m和m'是该函数的一个碰撞。简言之，hash碰撞是指两个不同的消息在同一个哈希函数作用下，产生两个相同的哈希值。
为了保证数据安全性和不可篡改性，实际hash算法要足够复杂使其有很强的hash抗碰撞性。
hash抗碰撞性分为两种：一种是弱抗碰撞性，即指定的消息x和函数H，去求消息y，使H(x)=H(y)在计算上是不可行的；另一个是强抗碰撞性，即给定函数H，对于任意一对不同的消息x和y，使得H(x)=H(y)在计算上也是不可行的。

SHA256
SHA是一个密码散列函数家族，是英文Secure Hash Algorithm的缩写。由美国国家安全局（NSA）所设计，并由美国国家标准与技术研究院（NIST）发布。SHA家族目前有三个系列：SHA-1，SHA-2，SHA-3。因为SHA-1已经被计算出能够被破解，所以现在几乎不再使用。SHA-3是2012年产生的算法，也叫Keccak算法，在以太坊公链中主要使用。SHA-2是当前使用最广泛的算法，尤其是比特币一代的公链。
图片: http://img.kongyixueyuan.com/sha%E7%B3%BB%E5%88%97.jpg
SHA算法有如下特性：1.不可以从消息摘要中复原信息；2.两个不同的消息不会产生同样的消息摘要。
SHA256是目前区块链加密算法中最基础也是应用最多的算法。它是SHA-2算法系列的最具代表性的加密算法。了解和熟练运用SHA256是区块链技术人才的最基本要求。
1. SHA256的算法原理
SHA-256是指对于任意小于2^64 位长度（按bit计算）的消息，以512位的分组为单位进行处理，最终产生一个32个字节长度数据的一种加密算法。产生的数据称作消息摘要。因为消息摘要的唯一性和确定性，所以可以用来验证数据在传输过程中是否发生改变，即验证其完整性。
1.1 运算单位
SHA算法过程的处理单位是位。本文中，一个“字”（Word）是32位，而一个“字节”（Byte）是8位。比如，字符串“abc”可以被转换成一个位字符串：01100001 01100010 01100011。它也可以被表示成16进制字符串:0x616263.
1.2 补位
将消息转换成二进制串，在后边添加一个“1”和若干个“0”，使其长度模512余数为448。以信息“abc”为例显示补位的过程。
  原始信息：01100001 01100010 01100011
  补位第一步：0110000101100010 01100011 1
  首先补一个“1”
  补位第二步：0110000101100010 01100011 10…..0
  然后补423个“0”   
1.3 消息填充 
将补位过的信息再追加一个64位的消息长度信息，使得填充完成后的消息长度正好是512位的整数倍。追加的64位的消息长度信息是原始消息的位长，填充完成的消息会被分成512位的消息分组。   
1.4 初始向量
SHA256是一个Merkle-Damgard结构的迭代哈希函数，进行第一次运算的时候需要一个初始向量。该向量在整个运算过程中是一个变量。SHA256的初始变量是取自然数前8个素数（2，3，5，7，11，13，17，19）的平方根的小数部分前32bit的值。如2的平方根取小数部分是：0.414213562373095048...，转换成二进制取前32bit值是：10110111111100101010000101001010，然后将其转换成16进制的值是：0x6a09e667。同样我们也会得到其他素数的初始变量。这些初始变量存储于8个寄存器A、B、C、D、E、F、G和H中，分别是：
A= H0 = 0x6a09e667
B= H1 = 0xbb67ae85
C= H2 = 0x3c6ef372
D= H3 = 0xa54ff53a
E= H4 = 0x510e527f
F= H5 = 0x9b05688c
G= H6 = 0x1f83d9ab
H= H7 = 0x5be0cd19
1.5 使用的64个常量
在SHA256算法中，用到64个常量，这些常量是对自然数中前64个素数的立方根的小数部分取前32bit而来。其作用是提供了一个64位随机串集合，用于被随机选取作为改变每次消息块运算初始向量函数的参数。这样每次消息块加密运算时，输入的初始向量都是没有任何规则的。这64个常量如下：
    428a2f98 71374491 b5c0fbcf e9b5dba5 
    3956c25b 59f111f1 923f82a4 ab1c5ed5 
    d807aa98 12835b01 243185be 550c7dc3 
    72be5d74 80deb1fe 9bdc06a7 c19bf174 
    e49b69c1 efbe4786 0fc19dc6 240ca1cc 
    2de92c6f 4a7484aa 5cb0a9dc 76f988da 
    983e5152 a831c66d b00327c8 bf597fc7 
    c6e00bf3 d5a79147 06ca6351 14292967 
    27b70a85 2e1b2138 4d2c6dfc 53380d13 
    650a7354 766a0abb 81c2c92e 92722c85 
    a2bfe8a1 a81a664b c24b8b70 c76c51a3 
    d192e819 d6990624 f40e3585 106aa070 
    19a4c116 1e376c08 2748774c 34b0bcb5
    391c0cb3 4ed8aa4a 5b9cca4f 682e6ff3 
    748f82ee 78a5636f 84c87814 8cc70208 
    90befffa a4506ceb bef9a3f7 c67178f2
1.6 运算过程
运算过程简单描述如下：
创建8个变量a,b,c,d,e,f,g,h，并分别赋值初始向量对应的值；
将原始消息补位和填充后，分为N个512bit的消息块M(i)；
运算M有个大的循环，形如： For i =1 to N;
大循环里面有个64次的循环，用于改变8个变量，并将最终改变后的8个变量作为下一次大循环的参数；
大循环最后得到的a,b,c,d,e,f,g,h拼接在一起就是最后的长度为256位的消息摘要。
下边分析一下64次的循环里面的具体函数，伪代码如下：
For t = 0 to 63
T1 = （h +（∑1(e) + CH(e,f,g) + Kt + Wt）mod2^32
T2 = ∑0(a) + MAJ(a,b,c)mod2^32
h = g
g = f
f = e
e = (d + T1)mod2^32
d = c
c = b
b = a
a = (T1 + T2)mod2^32
其中∑1(e)和∑0(a)分别是e和a的位移异或函数，表达式不做展开；与异或运算函数；MAJ(a,b,c)是a，b，c之间异或运算加法运算函数，表达式不做展开，；T1和T2是每一步生成的两个临时变量；Kt是每次循环从随机串里随机选取的数值；Wt是对输入的消息块的处理函数。
消息块的处理：每个消息块分解为16个32-bit的big-endian的字，记为w[0], …, w[15]。也就是说，前16个字直接由消息的第i个块分解得到，其余的字由如下迭代公式得到，这样Wt的表达式如下表示：
Wt=w[t],0<=t<=16
Wt=σ1(Wt−2)+Wt−7+σ0(Wt−15)+Wt−16,16<=t<=63
最后一次循环所产生的八个字合起来即是第i个块对应到的散列字符串Hi就是sha256加密后的散列值。

MD5算法
MD5英文全称Message-Digest Algorithm，中文叫消息摘要算法。它是由美国密码学家罗纳德·李维斯特（Ronald Linn Rivest）设计，于1992年公开，用以取代被发现有安全缺陷的MD4算法。它是目前使用最广泛的密码学算法之一。
1 算法描述
MD5算法将任意长度的消息进行函数运算，得到长度为128比特的hash值，该哈希值就是信息摘要。MD5的算法是个单向函数，无法进行逆运算。单向函数的正运算速度快，安全性高，非常实用。目前MD5被广泛应用在防篡改、数字签名、安全访问认证等方面。
算法过程是将消息进行填充，之后按512比特一组进行分组，每组信息与初始向量的缓存值进行各种逻辑运算，迭代运算和压缩函数运算，最后得到的值就是hash值。
算法流程图如下：
图片: http://img.kongyixueyuan.com/MD5%E7%AE%97%E6%B3%95%E6%8F%8F%E8%BF%B0.png
1. 填充消息
填充消息使其长度与448模512同与（即长度≡448 mod 512）。也就是说，填充后的消息长度比512的某整数倍少64比特。填充的方法是：在消息后面进行填充，填充第一位为1，其余为0。注意，如果消息的长度刚好满足要求，也就是不填充消息，其长度与448模512同与。这种情况下也要进行填充操作，填充第一位为1，剩余511位都是0。
2. 填充消息长度
完成第一步后，我们会发现如果再给消息填充64比特，那么消息的长度正好可以整除512。那好，我们就把消息的长度转换成二进制填充到经过第一步处理的消息后边。如果消息的长度过于长，长度值大于2^64 ，此时64位比特放不下这个长度值。如果这种情况，就取消息长度模2^64 的值作为填充的长度值。
在此步骤进行完毕后，最终消息长度就是512的整数倍。
3. 初始化初始向量
定义4个16进制的大整数（这些突然冒出来的数也叫幻数） A=67452301；B=EFCDAB89；C=98BADCFE；D=10325476。
将这四个幻数以字节数组存储，也就是我们声明4个变量去存储这四个幻数。但是存储的类型有两种：小端法(Little-Endian)存储和大端法(Big-Endian)存储。小端法就是低位字节排放在内存的低地址端即该值的起始地址，高位字节排放在内存的高地址端。大端法(Big-Endian)就是高位字节排放在内存的低地址端即该值的起始地址，低位字节排放在内存的高地址端。
我们现在用这两种存储方法存储A，来展示它们的区别：
小端法：A:=[]byte{01，23，45，67}
大端法：A:=[]byte{67，45，23，01}
MD5算法的逻辑函数处理字节是从最低有效字节增大顺序处理的，所以要求大整数的存储需要小端法进行存储。
所以，代码中我们可以直接定义4个变量，并给予赋值，分别为了存储以上4个大数，变量如下：
A:=[]byte{01，23，45，67}
B:=[]byte{89，AB，CD，EF}
C:=[]byte{FE，DC，BA，98}
D:=[]byte{76，54，32，10}
变量的长度都为4个字节，也就是32比特，加在一起是128，正好是最后hash值的长度。
这四个变量经过MD5函数处理后最终得到的结果拼接，就是最后的hash值。
4. 以512比特的分组（16个字）为单位处理消息
MD5算法的核心就是压缩函数H。每组消息的压缩由4轮运算完成，如图4.1所示。4轮运算结构相同，但各轮使用的逻辑函数不同，分别是H0，H1，H2，H3。每轮的输入为当前要处理的消息分组Mq和缓存区的当前A、B、C、D，前3轮输出的A、B、C、D直接替换旧的并放在缓存区，最后一轮，也就是第四轮的输出A、B、C、D需要和第一轮的输入A、B、C、D进行模2^32 加法运算之后再放到缓存区。这4轮的运算每轮都需要对缓存区ABCD进行16步迭代运算。
模加法运算很简单，其运算结果为两数相加后除以n的余数。模加法的数学符号是+。如9和8对10进行取模，结果是7。
具体的分组信息压缩过程如下图：
图片: http://img.kongyixueyuan.com/MD5%E5%8E%8B%E7%BC%A9%E5%88%86%E7%BB%84%E4%BF%A1%E6%81%AF%E8%BF%87%E7%A8%8B.png
5. MD5 16步迭代运算
压缩过程的每一轮都对缓冲区的ABCD进行16步的迭代运算，每一步的运算公式结构都是一样的，只是压缩函数不一样，我现在把4轮的压缩函数定义为g，那么每轮的运算公式如下：
a=D
b=CLSs(A+g(B,C,D)+X[k]+T[i])+B
c=B
d=C
其中A，B，C，D是缓存区中的4个字，a，b，c，d是A，B，C，D压缩后对应的字，g是基本逻辑函数H0，H1，H2，H3的对应一个，CLSs是32比特的变量循环左移s位，s的取值如表5.1所示。X[k]=Yq[q*16+k]，即消息的第q个分组中第k个字（k=0，...，15）。T[i]为表T中的第i个字，+为模2^32 加法。


通过上边的公式我们得到了a，b，c，d，将他们放到缓存区A，B，C，D进入下一步运算
运算示意图如下：
图片: http://img.kongyixueyuan.com/MD5%E4%B8%80%E6%AD%A5%E8%BF%AD%E4%BB%A3%E8%BF%90%E7%AE%97.png
表5.1 压缩函数中每步循环左移位数表

g逻辑函数每轮的表示：
第一轮：H0(B,C,D)=(B & C) | ((~B) & D)
第二轮：H1(B,C,D)=(B&D)|(C&(~D))
第三轮：H2(B,C,D)=B ^ C ^ D
第四轮：H3(B,C,D)=C ^ (B|~D)
上边公式里的运算符：
按位异或运算符" ^ "；按位或运算符"|"；按位与运算符"&"；按位取反运算符"~"。
对于X[k]再做一下解释。当前要处理的512比特的分组消息保存在Y[0...15]，其元素是一个32比特的字。每轮的16步运算每一步都是对Y里的某个元素进行处理。压缩是需要4轮进行的，但是每一轮对Y处理的次序是不一样的。
第一轮：顺序处理，k=k++
第二轮：k=（1+5i）mod 16
第三轮：k=（5+3i）mod 16
第四轮：k= 7i mod 16
其中i是16步运算的第i步。

RipeMD160算法
1 RipeMD算法简述
RIPEMD（RACE Integrity Primitives Evaluation Message Digest），中文译为“RACE原始完整性校验消息摘要”，是比利时鲁汶大学COSIC研究小组开发的散列函数算法。RIPEMD使用MD4的设计原理，并针对MD4的算法缺陷进行改进，1996年首次发布RIPEMD-128版本，在性能上与较受欢迎的SHA-1相似。
RipeMD算法是针对MD4和MD5算法缺陷分析提出的一种升级版本算法。这些算法主要是针对摘要值的长度进行了区分，如下表：

所以构成RIPEMD家族的四个成员分别是：RIPEMD-128、RIPEMD-160、RIPEMD-256、RIPEMD-320。但安全性最高，使用最广泛的是RIPEMD160算法。
2 RipeMD160算法简介
RIPEMD-160是基于Merkle-Damgard构造的加密散列函数。哈希值的输出值一般是16进制的字符串。而16进制字符串，每两个字符占一个字节。我们知道，一个字节=8bit.所以使用ripemd160加密函数所得到的是一个160bit的值。
Merkle-Damgard结构属于一个函数迭代运算的结构，抗hash碰撞能力强。
算法的原理几乎和MD算法的原理一样，但具体函数内容和过程不一样。RIPEMD-160的核心是一个有10个循环的压缩函数模块，其中每个循环由16个处理步骤组成。在每个循环中使用不同的原始逻辑函数，算法的处理分为两种不同的情况，在这两种情况下，分别以相反的顺序使用5个原始逻辑函数。每一个循环都以当前分组的消息字和160位的缓存值A、B、C、D、E为输入得到新的值。每个循环使用一个额外的常数，在最后一个循环结束后，两种情况的计算结果A、B、C、D、E和A′、B′、C′、D′、E′及链接变量的初始值经过一次相加运算产生最终的输出。对所有的512位的分组处理完成之后，最终产生的160位输出即为消息摘要。
在比特币系列的公链中经常用到该算法，尤其是账户地址的生成。
3 RipeMD160算法过程
RipeMD160算法过程的流程与MD5算法几乎一样，下面一步步进行分析。
3.1 填充
规则与MD5一模一样，使消息填充后的长度与448模512同与（即长度≡448 mod 512）。
3.2 填充消息长度
规则与MD5一模一样，将消息的长度填充到经过第一步填充之后的消息。最后得到的消息就是512的整数倍。
3.3 设置初始向量
比MD5多一个向量元素，但存储方式一样，采用小端法。
定义了5个16进制的大整数
A=67452301;
B=EFCDAB89;
C=98BADCFE;
D=10325476;
E=c3d2e1f0;
3.4 以512比特的分组（16个字）为单位处理消息
和MD5处理分组消息的原理类似，实现过程不同。
先看一下流程图：
图片: http://img.kongyixueyuan.com/ripemd%E5%8E%8B%E7%BC%A9%E8%BF%87%E7%A8%8B.jpeg
图中Yq为分组后的512比特的消息；f是每个加密块用到的运算函数；Ki是常量表K中的元素,与MD5的T表一样；Xi是消息的第q个分组中第i个字（i=0，...，15）；+为模2^32 加法。
具体f压缩函数为：
f1=x ^ y ^ z
f2=(x&y) | (~x&z)
f3=(x | ~y) ^ z
f4=(x&y) | (y&~z)
f5=x ^ (y | ~z)
按位异或运算符"^"；按位或运算符"|"；按位与运算符"&"；按位取反运算符"~"。
处理分组消息的过程分为5轮，每轮分为两组，分别是Left加密块和Right加密块运算，每个加密块运算又循环16步迭代运算。最后左右两侧经过5轮运算后得到的数据，和本组运算的初始向量按照指定组合顺序，将它们三组数据进行组合。组合之后的值就是本组运算结果，该结果就是下一组消息运算的初始向量。
Left和Right运算的函数顺序是相反的，同时它们分别总共运行80次。














