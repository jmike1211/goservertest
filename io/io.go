package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
)

func main(){
	x,err := readFile("config.json")
	if err != nil{
		fmt.Println(err.Error())
	}
	fmt.Println(x)
}

func readFile(filename string) (map[string]string, error) {
    bytes, err := ioutil.ReadFile(filename)
    if err != nil {
        fmt.Println("ReadFile: ", err.Error())
        return nil, err
    }
    var j = map[string]string{}
    if err := json.Unmarshal(bytes, &j); err != nil {
        fmt.Println("Unmarshal: ", err.Error())
        return nil, err
    }
    return j, nil
}
