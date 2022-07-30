# Innovation-and-Entrepreneurship-Course

SM3部分：
Project1：implement birthday attack on SM2
- 项目代码说明：
	- openssl 中实现了 SM3，但考虑到 openssl 整体体量较大，且需要通过统一接口进行调用，无法直接调用 SM3 模块，这里将 SM3 的模块从 openssl 中抽离出来，作为可用的单独模块进行调用；
	- 通过 unordered map 来存储 message，hashvalue(key) 数对
	- 利用 SM3 不断生成新消息的 hashvalue，然后在 map 中查找是否存在相同的 hashvalue 值，若找到，则说明碰撞发生；
	- 对于仅要求碰撞部分位的情况，则只需在 map 中存储 message 的部分 hashvalue 位即可；
	- 考虑到可移植性，代码中将目标碰撞位数与字节数都设定成了宏定义，要想改变碰撞位数，仅需修改宏定义中的值即可；注意，目标碰撞比特值不应该超过64，事实上，在该值为64时，birthday attack 的内存占用会迅速大幅提升，且运行时间长，有可能出现占满内存的情况；
- 运行指导：
	- 直接用 VS 新建项目，将库中文件添加到其中即可运行；
- 运行截图：
- ![图片1](https://raw.githubusercontent.com/SIIICON/Innovation-and-Entrepreneurship-Course/main/%E6%88%AA%E5%9B%BE/1.png)

Project2：implement Rho method attack on SM2
- 项目代码说明：
	- 同 Project1一致：openssl 中实现了 SM3，但考虑到 openssl 整体体量较大，且需要通过统一接口进行调用，无法直接调用 SM3 模块，这里将 SM3 的模块从 openssl 中抽离出来，作为可用的单独模块进行调用；
	- 使用了以下结构体来装载一个摘要实例；
	- 使用了链表 `list<size_t,size_t>` 来表示 Rho method 链；
	- 由于采用的 list 结构，导致在每次生成摘要后，查找是否存在相同摘要的代价随元素数量增大而大幅增大，导致在目标碰撞位为32时，已经无法在段时间内碰撞成功；以后应该考虑更换容器以达到更快速的查询；
```
typedef struct {
    size_t A; // 一个SM3摘要的最高64位（8B）
    size_t B; // 次高64位
    size_t C; // 以此类推...
    size_t D; // 最低64位
} Digest_Instance;
```
- 运行指导：
	- 直接用 VS 新建项目，将库中文件添加到其中即可运行；
- 运行截图：
- ![图片2](https://raw.githubusercontent.com/SIIICON/Innovation-and-Entrepreneurship-Course/main/%E6%88%AA%E5%9B%BE/2.png)

Project3：implement Length_Extension_Attack on SM2
- 项目代码说明：
	- 同 Project1一致：openssl 中实现了 SM3，但考虑到 openssl 整体体量较大，且需要通过统一接口进行调用，无法直接调用 SM3 模块，这里将 SM3 的模块从 openssl 中抽离出来，作为可用的单独模块进行调用；
	- 代码分为三个步骤（此处我们设原始消息为“secretdata”，设要拼接的字符串为“append”）：
		1. 模拟攻击者获取到了 H(’secretdata‘(已padding))
			- 第一步只需要正常地用 SM3 生成 H(’secretdata‘(已padding)) 即可；
		2. 模拟攻击者计算 H((’secretdata‘(已padding)||’append‘)(已padding))
			- 第二步，攻击者需要将 SM3 的输入状态 SM3_CTX 还原成第一步结束时的状态，然后将 “append” 在该状态下进行 SM3 哈希，以达到将其拼接到原消息（已padding）的末尾处；
			- 还原状态前需要先调用 `ossl_sm3_update(&c2, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 64)`  这是为了确保新创建的 SM3_CTX 不会对接下来的还原过程、拼接过程造成任何额外影响；
		3. 验证攻击者的计算正确性：
			- 虽然只是验证，但确实最容易出错的一步，因为openssl 中 SM3 的接收的message以及padding 是 Littlendian 存储的，即摘要的高位字节会被存放在存储单元的低位物理地址上，这就要求我们在用 SM3 哈希 (’secretdata‘(已padding)||’append‘)(已padding) 时，要注意 padding 中每个 64 位的书写顺序（与逻辑上的顺序刚好相反）
- 运行指导：
	- 直接用 VS 新建项目，将库中文件添加到其中即可运行；
- 运行截图：
- ![图片3](https://raw.githubusercontent.com/SIIICON/Innovation-and-Entrepreneurship-Course/main/%E6%88%AA%E5%9B%BE/3.png)

Project4：按照RFC6962实现默克尔树
- 代码无法运行出结果，未完成。

Project5：



SM2部分：
Project1：Deduce ECDSA PK with ethereum
- 项目代码说明：
	- Go 语言可以快速抓取 github/ethereum/ethereum-go/crypto 上的密码学组件，然后模拟推断公钥的过程；
	- 利用 crypto 模块生成私钥 privateKey，然后利用 privateKey 生成 PublicKey；
	- 用 Keccake256 对要签名的 data 进行哈希得到 hash；然后用私钥对 hash 进行签名；然后可以通过cypto 的 Ecrecover 函数利用 hash 与 signature 对公钥进行推断；
- 运行指导：
	- 需要安装 Go，且需要有 64位 gcc 支持；GOPROXY 的 源可能需要修改，以防止因网络原因无法从抓取模块；主要的运行方式参考 Go 官网的指引；
- 运行截图：
- ![图片4](https://raw.githubusercontent.com/SIIICON/Innovation-and-Entrepreneurship-Course/main/%E6%88%AA%E5%9B%BE/4.png)

Project:2：implement SM2
- 项目代码说明：
	- 一种方式也是将 openssl 中SM2椭圆曲线分离出来，避免了总是需要调用统一接口来使用 SM2 的缺点；
	- 另一种方式是基于 Miracl 大整数库构造一套SM2椭圆曲线加密模块；
- 运行指导：
	- 第一种方式需要在项目中依赖openssl 1.1.1（注意openssl 3.0.0无法通过编译）的库；参考教程[https://blog.csdn.net/Neu_webin/article/details/76546571?spm=1001.2014.3001.5506]
	- 第二种方式需要依赖miracl库；
- 运行截图：
- ![图片5](https://raw.githubusercontent.com/SIIICON/Innovation-and-Entrepreneurship-Course/main/%E6%88%AA%E5%9B%BE/5.jpg)

Project3：用概念验证代码验证上述缺陷
- 不理解题意，未完成。
Project4：实施上述ECMH计划
- 跑不出结果，未完成。
Project5：使用SM2实现PGP方案
- 跑不出结果，未完成。
Project6：实现真是网络通信的sm2 2P解密
- 不会，未完成。


Bitcoin部分：
Project1：伪造中本聪签名
- 项目代码说明：
	 -区块链采用椭圆曲线数字签名算法（ECDSA），私钥可以表述为给定的两个签名（r，s）和（r，s'），采用相同的随机整数k用于不同的已知消息m和m'，攻击者可以通过计算z和z'，再根据s-s'=(z-z')/k，解出k，进而计算私钥。
	 -签名的验证步骤可以概括为：
	 	1.验证r和s是否为区间[1, n -1]中的整数.否则，签名无效。
		2.计算e =HASH(m)，其中HASH与签名生成中使用的函数相同。
		3.让z成为eL_n的最左位。
		4.算u_1= zs_(—1) mod n和u2= rs_(-1) mod n.
		5.计算曲线点(x_1, y_1) =u_1 × G + u_2 × Q_A.如果(x_1, y_1) = O,则签名无效。
		6.在以下情况下，签名有效:r1=x_1(mod n)，否则无效。

- 运行指导：
	-若验签的时候不用提供m，只需提供消息的hash，则理论上可以伪造任何签名。以此为思路，先从二进制文件中获取签名并将其添加到另一个二进制文件中。同时保存签名到磁盘备用，再使用翻录签名，验证签名。
- 运行截图：
- ![图片6]https://raw.githubusercontent.com/SIIICON/Innovation-and-Entrepreneurship-Course/main/%E6%88%AA%E5%9B%BE/6.png


ETH部分：
Project1：MPT研究报告（见"research report on MPT"）


Real World Cryptanalyses部分：
Project1：Find a key with hash value “sdu_cst_20220610” under a message composed of your name followed by your student ID. For example, “San Zhan 202000460001”.
- 项目代码说明：
	-根据题目要求，在给定hash value和message的情况下，通过碰撞反解key。由于meow hash在设计时三个模块的操作都是可逆的，因此可以通过h和m的信息反过来求k。针对算法的可逆性、对称性、通过对称性碰撞均可对其进行攻击，或进行差分分析。
	-恢复密钥的关键在于，只有当对输入到AES中的值的猜测是正确的，消失的特征才会成立，可以通过随机数辅助找到这样的消息对。
- 运行指导：
	-将message设为"JingruTang202000180044"，同时用给定的hash value：sdu[] = "sdu_cst_20220610"作为参数，进行碰撞，最终输出密钥恢复的结果。
- 运行截图：
- ![图片7]https://raw.githubusercontent.com/SIIICON/Innovation-and-Entrepreneurship-Course/main/%E6%88%AA%E5%9B%BE/7.jpg

Project2：Find a 64-byte message under some 𝒌 fulfilling that their hash value is symmetrical（选做）
- 未完成。






