package main

import (
	"context"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/skyhook-io/radar/internal/errorlog"
	"github.com/skyhook-io/radar/internal/k8s"
)

// shellEnvVars lists exact environment variables to capture from the user's
// login shell. GUI apps (macOS .app, Linux .desktop) inherit a minimal
// environment that lacks these, causing silent failures when tools or
// configs set in .zshrc/.bashrc are not available.
var shellEnvVars = []string{
	"PATH",
	"KUBECONFIG",
	"AWS_PROFILE",
	"AWS_DEFAULT_REGION",
	"AWS_REGION",
	"GOOGLE_APPLICATION_CREDENTIALS",
	"CLOUDSDK_CONFIG",
	"AZURE_CONFIG_DIR",
	// Self-hosted Hub overrides — a Finder/Dock launch strips the shell env,
	// and without these Cloud Connect would silently target the hosted Hub.
	"RADAR_HUB_URL",
	"RADAR_HUB_APP_URL",
}

var shellEnvPrefixes = []string{
	"ANTHROPIC_",
	"CLAUDE_CODE_",
}

// enrichEnv captures key environment variables from the user's login
// shell so the desktop app can find CLI tools and config files that are
// set in .zshrc/.bashrc but not available to macOS .app bundles or
// Linux desktop applications.
func enrichEnv() {
	originalKubeconfig := os.Getenv("KUBECONFIG")
	captured := getShellEnv(shellEnvVars, shellEnvPrefixes)

	if path, ok := captured["PATH"]; ok && path != "" {
		os.Setenv("PATH", path)
		log.Printf("PATH enriched from login shell (%d entries)", len(strings.Split(path, ":")))
	} else {
		// Fallback: append common tool locations
		current := os.Getenv("PATH")
		extras := commonPaths()
		if len(extras) > 0 {
			os.Setenv("PATH", current+":"+strings.Join(extras, ":"))
			log.Printf("PATH enriched with %d common paths (shell detection failed)", len(extras))
		} else {
			log.Printf("PATH enrichment: no additional paths found; auth plugins like gke-gcloud-auth-plugin may not be found")
		}
	}

	for key, val := range captured {
		if key == "PATH" {
			continue
		}
		if val != "" && os.Getenv(key) == "" {
			os.Setenv(key, val)
			log.Printf("Env enriched: %s from login shell", key)
			if key == "KUBECONFIG" {
				k8s.SetEnrichedKubeconfigFromShell(true)
			}
		}
	}

	// Explain KUBECONFIG skip reasons — the GUI app starts with a stripped
	// env on macOS/Linux, and if enrichment doesn't fire the user may see
	// fewer clusters than they expect in the switcher. We surface this via
	// the errorlog so it shows up in bug report diagnostics.
	kubeconfigVal, kubeconfigFound := captured["KUBECONFIG"]
	switch {
	case originalKubeconfig != "" && kubeconfigFound && kubeconfigVal != "":
		pathCount := len(filepath.SplitList(originalKubeconfig))
		log.Printf("KUBECONFIG enrichment skipped: already set in process env (%d path(s))", pathCount)
		errorlog.Record("env-enrich", "warning",
			"KUBECONFIG enrichment skipped: already set in process env with %d path(s); "+
				"login shell value ignored", pathCount)
	case !kubeconfigFound || kubeconfigVal == "":
		shellName := "unknown"
		if s := os.Getenv("SHELL"); s != "" {
			shellName = filepath.Base(s)
		}
		log.Printf("KUBECONFIG enrichment skipped: not found in login shell")
		errorlog.Record("env-enrich", "warning",
			"KUBECONFIG not found in login shell (%s -l -i); "+
				"multi-file configs from .zshrc/.bashrc will not be visible", shellName)
	}
}

// getShellEnv runs the user's login shell to capture environment variables.
// It uses -i (interactive) so that zsh reads ~/.zshrc, where tools like
// Homebrew's google-cloud-sdk add their PATH/KUBECONFIG entries. Without -i,
// a non-interactive login shell skips ~/.zshrc.
//
// The full, unfiltered shell environment is captured and then matched against
// keys/prefixes in Go rather than filtered via shell grep: a filtered `env`
// stream can't be split back into records by newline alone once a matching
// value itself contains a newline, so filtering has to happen after parsing.
func getShellEnv(keys []string, prefixes []string) map[string]string {
	shell := os.Getenv("SHELL")
	if shell == "" {
		if runtime.GOOS == "darwin" {
			shell = "/bin/zsh"
		} else {
			shell = "/bin/bash"
		}
	}

	const startMarker = "__RADAR_ENV_START__"
	const endMarker = "__RADAR_ENV_END__"

	echoCmd := "echo " + startMarker + "; env; echo " + endMarker

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, shell, "-l", "-i", "-c", echoCmd)
	cmd.Env = []string{
		"HOME=" + os.Getenv("HOME"),
		"USER=" + os.Getenv("USER"),
		"SHELL=" + shell,
	}
	cmd.Stdin = nil
	out, err := cmd.Output()
	if err != nil {
		log.Printf("Shell env detection failed (%s -l -i -c): %v", shell, err)
		return nil
	}

	output := string(out)
	startIdx := strings.Index(output, startMarker)
	endIdx := strings.Index(output, endMarker)
	if startIdx == -1 || endIdx == -1 || endIdx <= startIdx {
		log.Printf("Shell env detection: markers not found in output")
		return nil
	}

	payload := output[startIdx+len(startMarker) : endIdx]
	all := parseEnvOutput(payload)

	result := make(map[string]string)
	keySet := make(map[string]bool, len(keys))
	for _, k := range keys {
		keySet[k] = true
	}
	for key, val := range all {
		if keySet[key] {
			result[key] = val
			continue
		}
		for _, p := range prefixes {
			if strings.HasPrefix(key, p) {
				result[key] = val
				break
			}
		}
	}
	return result
}

// envVarStart matches the start of a new KEY=VALUE record in `env` output.
// A line that doesn't match is a continuation of the previous record's
// (multiline) value.
var envVarStart = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// parseEnvOutput parses `env`-style output into a key/value map, preserving
// values that span multiple lines.
func parseEnvOutput(payload string) map[string]string {
	payload = strings.Trim(payload, "\n")
	if payload == "" {
		return nil
	}

	result := make(map[string]string)
	var key string
	var val strings.Builder
	flush := func() {
		if key != "" {
			result[key] = val.String()
		}
	}
	for _, line := range strings.Split(payload, "\n") {
		if loc := envVarStart.FindStringIndex(line); loc != nil {
			flush()
			eq := strings.IndexByte(line, '=')
			key = line[:eq]
			val.Reset()
			val.WriteString(line[eq+1:])
		} else if key != "" {
			val.WriteByte('\n')
			val.WriteString(line)
		}
	}
	flush()
	return result
}

// commonPaths returns well-known directories where CLI tools are typically installed.
func commonPaths() []string {
	home := os.Getenv("HOME")
	if home == "" {
		if u, err := user.Current(); err == nil {
			home = u.HomeDir
		}
	}

	candidates := []string{
		"/opt/homebrew/bin",
		"/opt/homebrew/sbin",
		"/opt/homebrew/share/google-cloud-sdk/bin", // Homebrew gcloud (Apple Silicon)
		"/usr/local/bin",
		"/usr/local/share/google-cloud-sdk/bin", // Homebrew gcloud (Intel)
		"/usr/local/go/bin",
		"/snap/bin", // Snap packages on Linux (kubectl, gcloud, aws-cli)
	}

	if home != "" {
		candidates = append(candidates,
			filepath.Join(home, "google-cloud-sdk", "bin"),
			filepath.Join(home, "go", "bin"),
			filepath.Join(home, ".local", "bin"),
			filepath.Join(home, ".krew", "bin"),
		)
	}

	var existing []string
	current := os.Getenv("PATH")
	for _, p := range candidates {
		if strings.Contains(current, p) {
			continue
		}
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			existing = append(existing, p)
		}
	}
	return existing
}
