package main

import (
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	pkgList, err := pkgListToMap()
	if err != nil {
		panic(err)
	}
	cves, err := mergeReportPkgs(pkgList)
	if err != nil {
		panic(err)
	}
	eventList, err := eventsToMap()
	if err != nil {
		panic(err)
	}
	fr := findReachability(cves, eventList)
	for _, cve := range fr {
		if cve.Reachable {
			fmt.Printf("Vulnerability %s is reachable\n", cve.CveID)
		}
	}
}

func pkgListToMap() (map[string][]interface{}, error) {
	v, err := os.ReadFile("scan_result.json")
	if err != nil {
		return nil, err
	}
	var report map[string]interface{}
	err = json.Unmarshal(v, &report)
	if err != nil {
		return nil, err
	}
	results, ok := report["Results"].([]interface{})
	pkgn := map[string][]interface{}{}
	if ok {
		for _, r := range results {
			res := r.(map[string]interface{})
			pkgs, ok := res["Packages"].([]interface{})
			if ok {
				for _, pu := range pkgs {
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
	return pkgn, nil
}
func mergeReportPkgs(pkgList map[string][]interface{}) ([]CvePkgs, error) {
	v, err := os.ReadFile("scan_result.json")
	if err != nil {
		return nil, err
	}
	var report map[string]interface{}
	err = json.Unmarshal(v, &report)
	if err != nil {
		return nil, err
	}
	results, ok := report["Results"].([]interface{})
	cvePkgs := []CvePkgs{}
	if ok {
		for _, r := range results {
			res := r.(map[string]interface{})
			Vulnerabilities := res["Vulnerabilities"].([]interface{})
			for _, v := range Vulnerabilities {
				vuln := v.(map[string]interface{})
				pkgID := vuln["PkgID"].(string)
				if _, ok := pkgList[pkgID]; ok {
					cvePkgs = append(cvePkgs, CvePkgs{
						CveID:          vuln["VulnerabilityID"].(string),
						PkgID:          pkgID,
						InstalledFiles: pkgList[pkgID],
					})
				}
			}
		}
	}
	return cvePkgs, nil
}

type CvePkgs struct {
	CveID          string
	PkgID          string
	InstalledFiles []interface{}
	Reachable      bool
}

func eventsToMap() (map[string]string, error) {
	v, err := os.ReadFile("runtime.json")
	if err != nil {
		return nil, err
	}
	var runtimeEvents []interface{}
	err = json.Unmarshal(v, &runtimeEvents)
	if err != nil {
		return nil, err
	}
	eventList := map[string]string{}
	for _, pl := range runtimeEvents {
		p, ok := pl.(map[string]interface{})
		if ok {
			args, ok := p["args"].([]interface{})
			if ok {
				for _, pu := range args {
					pkgs := pu.(map[string]interface{})
					aname := pkgs["name"].(string)
					if aname == "syscall_pathname" || aname == "pathname" {
						aValue := pkgs["value"].(string)
						eventList[aValue] = aValue
					}
				}
			}
		}
	}
	return eventList, nil
}

func findReachability(cvePkgs []CvePkgs, eventList map[string]string) []CvePkgs {
	newCvePkgs := []CvePkgs{}
	for _, cve := range cvePkgs {
		for _, f := range cve.InstalledFiles {
			filePath := f.(string)
			if _, ok := eventList[filePath]; ok {
				cve.Reachable = true
				newCvePkgs = append(newCvePkgs, cve)
			}
		}
	}
	return newCvePkgs
}
