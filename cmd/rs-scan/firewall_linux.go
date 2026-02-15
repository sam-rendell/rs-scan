//go:build linux

package main

import "os/exec"

func checkRSTSuppression() bool {
	return exec.Command("iptables", "-C", "OUTPUT",
		"-p", "tcp", "--tcp-flags", "RST", "RST", "-j", "DROP").Run() == nil
}

func rstSuppressionHint() string {
	return "iptables -I OUTPUT 1 -p tcp --sport 32768:60999 --tcp-flags RST RST -j DROP"
}

func checkRSTSuppressionV6() bool {
	return exec.Command("ip6tables", "-C", "OUTPUT",
		"-p", "tcp", "--tcp-flags", "RST", "RST", "-j", "DROP").Run() == nil
}

func rstSuppressionHintV6() string {
	return "ip6tables -I OUTPUT 1 -p tcp --sport 32768:60999 --tcp-flags RST RST -j DROP"
}
