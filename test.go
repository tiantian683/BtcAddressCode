package main

import "fmt"

func main() {
	address := GetAddress()
	is := CheckAdd(address)
	fmt.Println(is)
}
