package main

import (
	"encoding/base64"
	"fmt"
	"github.com/liu578101804/rsa-demo/tool"
	"io/ioutil"
	"os"
)

func main() {

	tool.GenRsaKey(1024)

	publicKey, err := ioutil.ReadFile("public.pem")
	if err != nil {
		os.Exit(-1)
	}
	privateKey,err := ioutil.ReadFile("private.pem")
	if err != nil {
		os.Exit(-1)
	}

	enc1,_ := tool.Sign([]byte("hello"), privateKey)
	fmt.Println(enc1)
	err = tool.Verify([]byte("hello"), enc1, publicKey)
	fmt.Println("err: ",err)

	enc2,_ := tool.Encrypt([]byte("hello"), publicKey)
	fmt.Println(base64.StdEncoding.EncodeToString(enc2))
	data,err := tool.Decrypt(enc2, privateKey)
	fmt.Println("data: ",string(data), "err: ",err)

}
