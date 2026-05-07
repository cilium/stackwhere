package main

import (
	"encoding/json"
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
		RunE: func(cmd *cobra.Command, args []string) error {
			data := getVersionData()
			if jsonOutput(cmd) {
				e := json.NewEncoder(cmd.OutOrStdout())
				e.SetIndent("", "  ")
				if err := e.Encode(data); err != nil {
					return err
				}

				return nil
			}

			w := cmd.OutOrStdout()
			if _, err := fmt.Fprintln(w, "version:", data.Version); err != nil {
				return err
			}
			if _, err := fmt.Fprintln(w, "go:", data.GoVersion); err != nil {
				return err
			}
			if _, err := fmt.Fprintln(w); err != nil {
				return err
			}
			for _, c := range data.Copyright {
				if _, err := fmt.Fprintln(w, c); err != nil {
					return err
				}
			}

			return nil
		},
	}

	return c
}

type versionData struct {
	Version   string   `json:"version"`
	GoVersion string   `json:"go_version"`
	Copyright []string `json:"copyright"`
}

func getVersionData() versionData {
	return versionData{
		Version:   versionString(),
		GoVersion: goVersion(),
		Copyright: []string{
			"Copyright (c) 2026 Cilium authors",
			"Copyright (c) 2014 Derek Parker",
		},
	}
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
