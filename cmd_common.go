package main

import (
	"github.com/fatih/color"
)

const (
	defaultRegistryPath = "./certs/.registry.json"
	defaultCADir        = "./certs/ca"
	defaultServerDir    = "./certs/servers"
	defaultClientDir    = "./certs/clients"
)

var (
	// Colors
	successColor = color.New(color.FgGreen, color.Bold)
	errorColor   = color.New(color.FgRed, color.Bold)
	infoColor    = color.New(color.FgCyan)
	warnColor    = color.New(color.FgYellow)
)
