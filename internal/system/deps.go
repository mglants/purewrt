package system

import "os/exec"

type Dependency struct {
	Name string
	OK   bool
	Path string
}

func CheckDependencies(names ...string) []Dependency {
	out := make([]Dependency, 0, len(names))
	for _, n := range names {
		p, err := exec.LookPath(n)
		out = append(out, Dependency{Name: n, OK: err == nil, Path: p})
	}
	return out
}
