//go:build darwin

package main

import (
	"os/exec"
	"strings"
)

func checkRSTSuppression() bool {
	out, err := exec.Command("pfctl", "-sr").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "flags R/R")
}

func rstSuppressionHint() string {
	return `echo "block drop out proto tcp from any to any flags R/R" | sudo pfctl -ef -`
}

func checkRSTSuppressionV6() bool {
	// pfctl rules apply to both IPv4 and IPv6 by default
	return checkRSTSuppression()
}

func rstSuppressionHintV6() string {
	// Same hint — pfctl is protocol-agnostic
	return rstSuppressionHint()
}
