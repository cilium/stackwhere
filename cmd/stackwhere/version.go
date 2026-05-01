package main

import (
	"fmt"
	"runtime"
	"time"

	"github.com/spf13/cobra"
)

var (
	version = defaultVersion
	commit  string
	date    string
)

const defaultVersion = "0.0.0"

func versionCommand() *cobra.Command {
	c := &cobra.Command{
		Use:   "version",
		Short: "Prints the version of stackwhere and copyright information.",
		Long:  "Prints the version of stackwhere and copyright information.",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("version:", versionString())
			fmt.Println("go:", goVersion())
			fmt.Println()
			fmt.Println("Copyright (c) 2026 Cilium authors")
			fmt.Println("Copyright (c) 2014 Derek Parker")
		},
	}

	return c
}

func versionString() string {
	if date == "" {
		return "v0.0.0 (development build)"
	}

	shortCommit := commit
	if len(commit) > 12 {
		shortCommit = commit[:12]
	}

	var releaseDate string
	dateTime, err := time.Parse(time.RFC3339, date)
	if err == nil {
		releaseDate = dateTime.Format("20060102150405")
	} else {
		releaseDate = "unknown"
	}

	return fmt.Sprintf("v%s-%s-%s", version, releaseDate, shortCommit)
}

func goVersion() string {
	return fmt.Sprintf("%s %s/%s", runtime.Version(), runtime.GOOS, runtime.GOARCH)
}
