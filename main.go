package main

import (
	"BcAddressCode/base58"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"golang.org/x/crypto/ripemd160"
)

const VERSION  =  0x00
func main() {
	fmt.Println("这是一个比特币地址生成")
	//第一步，生成私钥和公钥
	curve := elliptic.P256()
	//ecdsa.GenerateKey(curve,rand.Reader)
	//x和y可以组成公钥
	_,x,y,err :=elliptic.GenerateKey(curve,rand.Reader)
	if err!= nil {
		 fmt.Println(err.Error())
		return
	}
	//将x和y组成公钥转换为[]byte类型
	//公钥：x坐标加y坐标


	//系统的api
	pubKey := elliptic.Marshal(curve,x,y)
	fmt.Println("非压缩格式的公钥",pubKey)
	fmt.Println("非压缩公钥格式的长度",len(pubKey))//65个字节

	//第二步，hash计算
	//sha256
	sha256Hash := sha256.New()
	sha256Hash.Write(pubKey)
	pubHash256 :=sha256Hash.Sum(nil)
	//ripemd160:github
	ripemd := ripemd160.New()
	ripemd.Write(pubHash256)
	pubRipemd160 :=ripemd.Sum(nil)
	//第三步，添加版本号前缀
	versionPubRipemd160 :=append([]byte{0x00},pubRipemd160...)

	//第四步，计算校验位
	//a、sha256hash
	sha256Hash.Reset()//重置
	sha256Hash.Write(versionPubRipemd160)
	hash1 := sha256Hash.Sum(nil)
	//b、sha256
	sha256Hash.Reset()
	sha256Hash.Write(hash1)
	hash2 := sha256Hash.Sum(nil)
	//c、取hash2前四个字节
	check := hash2[:4]

	//第五步,拼接校验位，得到地址
	addBytes := append(versionPubRipemd160,check...)

	fmt.Println("地址是：",addBytes)
	//第六步，对地址进行base58编码
	//github：
	address :=base58.Encode(addBytes)
	fmt.Println("生成的新的比特币地址：",address)
    //效验地址
	address1 := base58.Decode(address)
	addbyte1 := address1[21:]
	fmt.Println("待效验位：",addbyte1)
	addbyte2 := address1[0:21]
	//fmt.Println(addbyte2)
	//对除去后四位的地址进行双hash
	//第一次hash
	sha256Hash.Reset()
	sha256Hash.Write(addbyte2)
	a :=sha256Hash.Sum(nil)
	//第二次hash
	sha256Hash.Reset()
	sha256Hash.Write(a)
	b := sha256Hash.Sum(nil)
	//取出校验位
	addbyte3 := b[0:4]
	fmt.Println("校验位是：",addbyte3)
	//验证校验位
	if string(addbyte1) ==string(addbyte3) {
		fmt.Println("有效")
	}else {
		fmt.Println("无效")
	}


fmt.Println("--------------------------------------------------------------------------------------分界线------------------------------------------------------------------------------------")


	//方法的实现
	address10 := GetAddress()
	is := CheckAdd(address10)
	fmt.Println(is)
}
//生成私钥
func GenerateKey(curve elliptic.Curve)(*ecdsa.PrivateKey,error)  {

	return ecdsa.GenerateKey(curve,rand.Reader)
}

func GetUnPressPub(curve elliptic.Curve,pri *ecdsa.PrivateKey)[]byte{
	return elliptic.Marshal(curve,pri.X,pri.Y)
}
func SHA256Hash(msg []byte)[]byte  {
	sha256Hash := sha256.New()
	sha256Hash.Write(msg)
	return sha256Hash.Sum(nil)
}

func Ripemd160Hash(msg []byte)[]byte  {
	ripemd := ripemd160.New()
	ripemd.Write(msg)
	return ripemd.Sum(nil)
}
func GetAddress() string {
	curve := elliptic.P256()
	pri,_ := GenerateKey(curve)
	pub := GetUnPressPub(curve,pri)
	//1、sha256
	hash256 := SHA256Hash(pub)
	//ripemd160
	ripemd := Ripemd160Hash(hash256)
	//version
	versionRipemd := append([]byte{VERSION},ripemd...)
	//双hash
	hash1 := SHA256Hash(versionRipemd)
	hash2 := SHA256Hash(hash1)

	check := hash2[:4]

	add := append(versionRipemd,check...)
	return base58.Encode(add)

}

func CheckAdd(add string)bool  {
	//1、反编码
	deAddByets := base58.Decode(add)
	//截取校验位
	decheck := deAddByets[len(deAddByets)-4:]
	//计算校验码
	versionRipemd160 := deAddByets[:len(deAddByets)-4]
	//双hash
	sha256Hash := sha256.New()
	sha256Hash.Write(versionRipemd160)
	hash1 := sha256Hash.Sum(nil)

	sha256Hash.Reset()
	sha256Hash.Write(hash1)
	hash2 := sha256Hash.Sum(nil)
	check := hash2[:4]

	//截取校验位
	//isValid := bytes.Compare(decheck,check)
	//if isValid == 0 {
	//	fmt.Println("恭喜有效")
	//	return true
	//}
	return bytes.Compare(decheck,check) == 0//上面注释的优化
}