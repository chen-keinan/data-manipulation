package main

import (
	"encoding/json"
	"fmt"
	lo "github.com/samber/lo"
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
	runtimeSbom, err := eventsToRuntimeSbom()
	if err != nil {
		panic(err)
	}

	fr := findReachability(cves, runtimeSbom)
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

func eventsToRuntimeSbom() (*RunTimeSbom, error) {
	v, err := os.ReadFile("runtime_events.json")
	if err != nil {
		return nil, err
	}
	var runtimeEvents []interface{}
	err = json.Unmarshal(v, &runtimeEvents)
	if err != nil {
		return nil, err
	}

	containerSbomMap := map[string]*ContainerRuntimeSbom{}
	for _, pl := range runtimeEvents {
		p, ok := pl.(map[string]interface{})
		filepaths := []string{}
		if ok {
			args, ok := p["args"].([]interface{})
			if ok {
				for _, pu := range args {
					pkgs := pu.(map[string]interface{})
					aname := pkgs["name"].(string)
					if aname == "syscall_pathname" || aname == "pathname" {
						filepaths = append(filepaths, pkgs["value"].(string))

					}
				}
			}
			name, ok := p["eventName"].(string)
			if !ok {
				continue
			}
			sysCall, ok := p["syscall"].(string)
			if !ok {
				continue
			}
			container, ok := p["container"].(map[string]interface{})
			if ok {
				if id, ok := container["image"].(string); ok {
					if sbom, ok := containerSbomMap[id]; ok {
						newEvent := Event{
							filesPath: filepaths,
							name:      name,
							sysCall:   sysCall,
						}
						sbom.Events = append(sbom.Events, newEvent)
					} else {
						containerSbomMap[id] = &ContainerRuntimeSbom{
							ContainerName: container["name"].(string),
							ImageID:       container["image"].(string),
							ImageDigest:   container["imageDigest"].(string),
							Events: []Event{
								{
									name:      name,
									sysCall:   sysCall,
									filesPath: filepaths,
								},
							},
						}
					}
				}
			}
		}
	}
	return &RunTimeSbom{ContainerRuntimeSbom: lo.Values(containerSbomMap)}, nil
}

func runTimeSbomToMap(runtimeSbom *RunTimeSbom) map[string]string {
	eventList := map[string]string{}
	for _, cr := range runtimeSbom.ContainerRuntimeSbom {
		for _, e := range cr.Events {
			for _, f := range e.filesPath {
				eventList[f] = f
			}
		}
	}
	return eventList
}

func findReachability(cvePkgs []CvePkgs, runtimeSbom *RunTimeSbom) []CvePkgs {
	newCvePkgs := []CvePkgs{}
	eventMap := runTimeSbomToMap(runtimeSbom)
	for _, cve := range cvePkgs {
		for _, f := range cve.InstalledFiles {
			filePath := f.(string)
			if _, ok := eventMap[filePath]; ok {
				cve.Reachable = true
				newCvePkgs = append(newCvePkgs, cve)
			}
		}
	}
	return newCvePkgs
}

type RunTimeSbom struct {
	ContainerRuntimeSbom []*ContainerRuntimeSbom
}

type ContainerRuntimeSbom struct {
	ContainerName string
	ImageID       string
	ImageDigest   string
	Events        []Event
}

type Event struct {
	name      string
	sysCall   string
	filesPath []string
}
