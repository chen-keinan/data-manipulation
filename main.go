package main

import (
	"bufio"
	"encoding/json"
	"fmt"

	"github.com/jedib0t/go-pretty/v6/table"

	"os"
	"strings"

	lo "github.com/samber/lo"
)

func main() {
	args := os.Args[1:]
	if len(args) < 2 {
		fmt.Print("missing scan result or events args")
		os.Exit(1)
	}
	te, err := LoadTraceeEvent(args[1])
	if err != nil {
		panic(err)
	}
	pkgList, err := pkgListToMap(args[0])

	if err != nil {
		panic(err)
	}

	cves, err := mergeReportPkgs(pkgList, args[0])

	if err != nil {
		panic(err)
	}

	b, _ := json.Marshal(te)
	os.WriteFile("runtime_sbom.json", b, 0644)
	reachableCves := findReachability(cves, te)
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"CVE-ID", "Package", "Type", "Reachable Files"})
	printCVE := make(map[string]bool)
	for _, rc := range reachableCves {
		if rc.Reachable {
			if _, ok := printCVE[rc.CveID]; !ok {
				printCVE[rc.CveID] = true
				reachableFiles := strings.Join(rc.ReachableFiles, "\n")
				t.AppendRows([]table.Row{
					{rc.CveID, rc.PkgID, rc.pkgType, reachableFiles},
				})
				t.AppendSeparator()
			}
		}
	}
	t.AppendFooter(table.Row{"Total Cves", len(cves), "Total reachable CVEs", len(printCVE)})
	t.Render()
}

func LoadTraceeEvent(eventFilePath string) (*TraceeSbom, error) {
	file, err := os.Open(eventFilePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	traceeEvents := make([]TracceEvent, 0)
	// optionally, resize scanner's capacity for lines over 64K, see next example
	for scanner.Scan() {
		line := scanner.Text()
		if !(strings.HasPrefix(line, "{") && strings.HasSuffix(line, "}")) {
			continue
		}
		var event TracceEvent
		err := json.Unmarshal([]byte(line), &event)
		if err != nil {
			return nil, err
		}
		if len(event.EventID) == 0 {
			continue
		}
		traceeEvents = append(traceeEvents, event)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return &TraceeSbom{TracceEvents: traceeEvents}, nil
}

func pkgListToMap(scanResultFile string) (map[string][]interface{}, error) {
	v, err := os.ReadFile(scanResultFile)
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
					var pname string
					if _, ok := pkgs["ID"].(string); ok {
						pname = pkgs["ID"].(string)
					} else {
						pname = fmt.Sprintf("%s:%s", pkgs["Name"].(string), pkgs["Version"].(string))
					}
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
func mergeReportPkgs(pkgList map[string][]interface{}, scanFilePath string) ([]CvePkgs, error) {
	v, err := os.ReadFile(scanFilePath)
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
			pkgType := res["Type"].(string)
			Vulnerabilities := res["Vulnerabilities"].([]interface{})
			for _, v := range Vulnerabilities {
				vuln := v.(map[string]interface{})
				var pkgID string
				if pkgID, ok = vuln["PkgID"].(string); !ok {
					pkgID = fmt.Sprintf("%s:%s", vuln["PkgName"].(string), vuln["InstalledVersion"].(string))
				}
				if _, ok := pkgList[pkgID]; ok {
					cvePkgs = append(cvePkgs, CvePkgs{
						CveID:          vuln["VulnerabilityID"].(string),
						PkgID:          pkgID,
						InstalledFiles: pkgList[pkgID],
						pkgType:        pkgType,
					})
				}
			}
		}
	}
	return cvePkgs, nil
}

type CvePkgs struct {
	pkgType        string
	CveID          string
	PkgID          string
	InstalledFiles []interface{}
	Reachable      bool
	ReachableFiles []string
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
							FilesPath: filepaths,
							Name:      name,
							SysCall:   sysCall,
						}
						sbom.Events = append(sbom.Events, newEvent)
					} else {
						containerSbomMap[id] = &ContainerRuntimeSbom{
							ContainerName: container["name"].(string),
							ImageID:       container["image"].(string),
							ImageDigest:   container["imageDigest"].(string),
							Events: []Event{
								{
									Name:      name,
									SysCall:   sysCall,
									FilesPath: filepaths,
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

func runTimeSbomToMap(traceeSbom *TraceeSbom) map[string]string {
	eventList := map[string]string{}
	for _, te := range traceeSbom.TracceEvents {
		for _, arg := range te.Args {
			if arg.Name == "pathname" || arg.Name == "syscall_pathname" {
				if vs, ok := arg.Value.(string); ok {
					eventList[vs] = vs
				}
			}
		}
	}
	return eventList
}

func findReachability(cvePkgs []CvePkgs, ts *TraceeSbom) []CvePkgs {
	reachableCves := []CvePkgs{}
	eventMap := runTimeSbomToMap(ts)
	for _, cve := range cvePkgs {
		reachable := make([]string, 0)
		for _, f := range cve.InstalledFiles {
			filePath := f.(string)
			if _, ok := eventMap[filePath]; ok {
				reachable = append(reachable, filePath)
				cve.Reachable = true
			}
		}
		if cve.Reachable {
			cve.ReachableFiles = reachable
		}
		reachableCves = append(reachableCves, cve)
	}
	return reachableCves
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
	Name      string
	SysCall   string
	FilesPath []string
}

type TraceeSbom struct {
	TracceEvents []TracceEvent
}

type TracceEvent struct {
	EventID   string    `json:"eventName"`
	Container Container `json:"container"`
	SysCall   string    `json:"syscall"`
	Args      []Args    `json:"args"`
}

type Container struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Image       string `json:"image"`
	ImageDigest string `json:"imageDigest"`
}

type Args struct {
	Name  string      `json:"name"`
	Type  string      `json:"type"`
	Value interface{} `json:"value"`
}

type VexReport struct {
	BomFormat       string             `json:"bomFormat"`
	SpecVersion     string             `json:"specVersion"`
	Version         string             `json:"version"`
	Vulnerabilities []VexVulnerability `json:"vulnerabilities"`
}

type VexVulnerability struct {
	ID       string   `json:"id"`
	Analysis Analysis `json:"analysis"`
	Affects  []Affect `json:"affects"`
}
type Analysis struct {
	State         string   `json:"state"`
	Justification string   `json:"justification"`
	Response      []string `json:"response"`
	Detailes      string   `json:"details"`
}

type Affect struct {
	Ref string `json:"ref"`
}
