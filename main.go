package main

import (
	"encoding/json"
	//"fmt"
	"os"
)

func main() {
	v, err := os.ReadFile("pkglist.json")
	if err != nil {
		panic(err)
	}
	var pkglist []interface{}
	err = json.Unmarshal(v, &pkglist)
	if err != nil {
		panic(err)
	}
	for _, pl := range pkglist {
		p, ok := pl.(map[string]interface{})
		pkgn := map[string][]interface{}{}
		if ok {
			pkg, ok := p["Packages"].([]interface{})
			if ok {
				for _, pu := range pkg {
				//	fmt.Print(pu)
					pkgs := pu.(map[string]interface{})
					pname := pkgs["ID"].(string)
					ifs, ok := pkgs["InstalledFiles"].([]interface{})
					if ok {
						pkgn[pname] = ifs
					}
				}
			}
		}
	}
}
