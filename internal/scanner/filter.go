package scanner

import (
	"math"
	"path"
	"strings"
)

func placeholder(value string) bool {
	value = strings.TrimSpace(strings.Trim(value, "\"'"))
	lower := strings.ToLower(value)
	for _, prefix := range []string{"${", "$", "{{", "process.env.", "os.getenv(", "os.environ", "getenv("} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	normalized := strings.NewReplacer("-", "", "_", "", " ", "").Replace(lower)
	switch normalized {
	case "", "yourapikeyhere", "yourapikey", "exampleapikey", "testtoken", "changeme", "replacewithyourkey", "yourpassword", "passwordhere", "examplepassword":
		return true
	}
	return len(value) >= 4 && (strings.Trim(value, "xX") == "" || strings.Trim(value, "*") == "")
}

func entropy(value string) float64 {
	if len(value) == 0 {
		return 0
	}
	var counts [256]int
	for i := range value {
		counts[value[i]]++
	}
	var result float64
	for _, count := range counts {
		if count != 0 {
			p := float64(count) / float64(len(value))
			result -= p * math.Log2(p)
		}
	}
	return result
}

func documentation(file string) bool {
	name := strings.ToLower(path.Base(strings.ReplaceAll(file, "\\", "/")))
	switch path.Ext(name) {
	case ".md", ".rst", ".adoc":
		return true
	}
	return name == "readme" || name == "license" || name == "changelog"
}

func (d *Detector) keepGeneric(file string, value []byte, rule Rule) bool {
	text := strings.Trim(string(value), "\"'")
	if documentation(file) || placeholder(text) || entropy(text) < rule.MinEntropy {
		return false
	}
	// Une règle fournisseur donne un résultat plus précis pour la même valeur.
	for _, specific := range d.rules {
		if !specific.rule.Generic && specific.pattern.MatchString(text) {
			return false
		}
	}
	return true
}
