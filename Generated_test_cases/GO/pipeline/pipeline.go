package pipeline

import (
	"os/exec"
	"strings"
)

// VULN-5: Command injection – incomplete sanitizer
func Execute(cmd, input string) string {
	safe := sanitize(cmd)
	if safe == "" {
		return ""
	}
	c := exec.Command("/bin/sh", "-c", safe)
	out, _ := c.CombinedOutput()
	return string(out)
}

func sanitize(cmd string) string {
	// removes only ; | &
	r := strings.NewReplacer(";", "", "|", "", "&", "")
	return r.Replace(cmd)
}