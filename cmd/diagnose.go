package cmd

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/go-i2p/common/router_info"
	"github.com/urfave/cli/v3"
)

// NewDiagnoseCommand creates a new CLI command for diagnosing RouterInfo files
// in the netDb directory to identify corrupted or problematic files that cause
// parsing errors during reseed operations.
func NewDiagnoseCommand() *cli.Command {
	return &cli.Command{
		Name:  "diagnose",
		Usage: "Diagnose RouterInfo files in netDb to identify parsing issues",
		Description: `Scan RouterInfo files in the netDb directory to identify files that cause
parsing errors. This can help identify corrupted files that should be removed
to prevent "mapping format violation" errors during reseed operations.`,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "netdb",
				Aliases:  []string{"n"},
				Usage:    "Path to the netDb directory containing RouterInfo files",
				Value:    findDefaultNetDbPath(),
				Required: false,
			},
			&cli.DurationFlag{
				Name:    "max-age",
				Aliases: []string{"a"},
				Usage:   "Maximum age for RouterInfo files to consider (e.g., 72h for 3 days)",
				Value:   72 * time.Hour, // Matches reseed server --routerInfoAge default (I2P standard)
			},
			&cli.BoolFlag{
				Name:    "remove-bad",
				Aliases: []string{"r"},
				Usage:   "Remove files that fail parsing (use with caution)",
				Value:   false,
			},
			&cli.BoolFlag{
				Name:    "verbose",
				Aliases: []string{"v"},
				Usage:   "Enable verbose output",
				Value:   false,
			},
			&cli.BoolFlag{
				Name:    "debug",
				Aliases: []string{"d"},
				Usage:   "Enable debug mode (sets I2P_DEBUG=true)",
				Value:   false,
			},
		},
		Action: diagnoseRouterInfoFiles,
	}
}

// diagnoseRouterInfoFiles performs the main diagnosis logic for RouterInfo files
func diagnoseRouterInfoFiles(ctx *cli.Context) error {
	config, err := extractDiagnosisConfig(ctx)
	if err != nil {
		return err
	}

	if err := validateNetDbPath(config.netdbPath); err != nil {
		return err
	}

	printDiagnosisHeader(config)

	routerInfoPattern, err := compileRouterInfoPattern()
	if err != nil {
		return err
	}

	stats := &diagnosisStats{}

	err = filepath.WalkDir(config.netdbPath, func(path string, d fs.DirEntry, err error) error {
		return processRouterInfoFile(path, d, err, routerInfoPattern, config, stats)
	})
	if err != nil {
		return fmt.Errorf("error walking netDb directory: %v", err)
	}

	printDiagnosisSummary(stats, config.removeBad)
	return nil
}

// diagnosisConfig holds all configuration parameters for diagnosis
type diagnosisConfig struct {
	netdbPath string
	maxAge    time.Duration
	removeBad bool
	verbose   bool
	debug     bool
}

// diagnosisStats tracks file processing statistics
type diagnosisStats struct {
	totalFiles     int
	tooOldFiles    int
	corruptedFiles int
	validFiles     int
	removedFiles   int
}

// extractDiagnosisConfig extracts and validates configuration from CLI context
func extractDiagnosisConfig(ctx *cli.Context) (*diagnosisConfig, error) {
	config := &diagnosisConfig{
		netdbPath: ctx.String("netdb"),
		maxAge:    ctx.Duration("max-age"),
		removeBad: ctx.Bool("remove-bad"),
		verbose:   ctx.Bool("verbose"),
		debug:     ctx.Bool("debug"),
	}

	// Set debug mode if requested
	if config.debug {
		os.Setenv("I2P_DEBUG", "true")
		fmt.Println("Debug mode enabled (I2P_DEBUG=true)")
	}

	if config.netdbPath == "" {
		return nil, fmt.Errorf("netDb path is required. Use --netdb flag or ensure I2P is installed in a standard location")
	}

	return config, nil
}

// validateNetDbPath checks if the netDb directory exists
func validateNetDbPath(netdbPath string) error {
	if _, err := os.Stat(netdbPath); os.IsNotExist(err) {
		return fmt.Errorf("netDb directory does not exist: %s", netdbPath)
	}
	return nil
}

// printDiagnosisHeader prints the diagnosis configuration information
func printDiagnosisHeader(config *diagnosisConfig) {
	fmt.Printf("Diagnosing RouterInfo files in: %s\n", config.netdbPath)
	fmt.Printf("Maximum file age: %v\n", config.maxAge)
	fmt.Printf("Remove bad files: %v\n", config.removeBad)
	fmt.Println()
}

// compileRouterInfoPattern compiles the regex pattern for RouterInfo files
func compileRouterInfoPattern() (*regexp.Regexp, error) {
	pattern, err := regexp.Compile(`^routerInfo-[A-Za-z0-9-=~]+\.dat$`)
	if err != nil {
		return nil, fmt.Errorf("failed to compile regex pattern: %v", err)
	}
	return pattern, nil
}

// processRouterInfoFile handles individual RouterInfo file processing
func processRouterInfoFile(path string, d fs.DirEntry, err error, pattern *regexp.Regexp, config *diagnosisConfig, stats *diagnosisStats) error {
	if err != nil {
		if config.verbose {
			fmt.Printf("Error accessing path %s: %v\n", path, err)
		}
		return nil // Continue processing other files
	}

	// Skip directories
	if d.IsDir() {
		return nil
	}

	// Check if file matches RouterInfo pattern
	if !pattern.MatchString(d.Name()) {
		return nil
	}

	stats.totalFiles++

	// Get file info and check age
	if shouldSkipOldFile(path, d, config, stats) {
		return nil
	}

	// Try to read and parse the RouterInfo file
	return analyzeRouterInfoFile(path, config, stats)
}

// shouldSkipOldFile checks if file should be skipped due to age
func shouldSkipOldFile(path string, d fs.DirEntry, config *diagnosisConfig, stats *diagnosisStats) bool {
	info, err := d.Info()
	if err != nil {
		if config.verbose {
			fmt.Printf("Error getting file info for %s: %v\n", path, err)
		}
		return true
	}

	age := time.Since(info.ModTime())
	if age > config.maxAge {
		stats.tooOldFiles++
		if config.verbose {
			fmt.Printf("SKIP (too old): %s (age: %v)\n", path, age)
		}
		return true
	}

	return false
}

// analyzeRouterInfoFile reads and analyzes a RouterInfo file
func analyzeRouterInfoFile(path string, config *diagnosisConfig, stats *diagnosisStats) error {
	routerBytes, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("ERROR reading %s: %v\n", path, err)
		stats.corruptedFiles++
		return nil
	}

	// Try to parse RouterInfo using the same approach as the reseed server
	riStruct, remainder, err := router_info.ReadRouterInfo(routerBytes)
	if err != nil {
		return handleCorruptedFile(path, err, remainder, config, stats)
	}

	return validateRouterInfo(path, riStruct, config, stats)
}

// handleCorruptedFile processes files that fail parsing
func handleCorruptedFile(path string, parseErr error, remainder []byte, config *diagnosisConfig, stats *diagnosisStats) error {
	fmt.Printf("CORRUPTED: %s - %v\n", path, parseErr)
	if len(remainder) > 0 {
		fmt.Printf("  Leftover data: %d bytes\n", len(remainder))
		if config.verbose {
			maxBytes := len(remainder)
			if maxBytes > 50 {
				maxBytes = 50
			}
			fmt.Printf("  First %d bytes of remainder: %x\n", maxBytes, remainder[:maxBytes])
		}
	}
	stats.corruptedFiles++

	// Remove file if requested
	if config.removeBad {
		if removeErr := os.Remove(path); removeErr != nil {
			fmt.Printf("  ERROR removing file: %v\n", removeErr)
		} else {
			fmt.Printf("  REMOVED\n")
			stats.removedFiles++
		}
	}

	return nil
}

// validateRouterInfo performs additional checks on valid RouterInfo structures
func validateRouterInfo(path string, riStruct router_info.RouterInfo, config *diagnosisConfig, stats *diagnosisStats) error {
	gv, err := riStruct.GoodVersion()
	if err != nil {
		fmt.Printf("Version check error %s", err)
	}

	stats.validFiles++
	if config.verbose {
		if riStruct.Reachable() && riStruct.UnCongested() && gv {
			fmt.Printf("OK: %s (reachable, uncongested, good version)\n", path)
		} else {
			fmt.Printf("OK: %s (but would be skipped by reseed: reachable=%v uncongested=%v goodversion=%v)\n",
				path, riStruct.Reachable(), riStruct.UnCongested(), gv)
		}
	}

	return nil
}

// printDiagnosisSummary prints the final diagnosis results
func printDiagnosisSummary(stats *diagnosisStats, removeBad bool) {
	fmt.Println("\n=== DIAGNOSIS SUMMARY ===")
	fmt.Printf("Total RouterInfo files found: %d\n", stats.totalFiles)
	fmt.Printf("Files too old (skipped): %d\n", stats.tooOldFiles)
	fmt.Printf("Valid files: %d\n", stats.validFiles)
	fmt.Printf("Corrupted files: %d\n", stats.corruptedFiles)
	if removeBad {
		fmt.Printf("Files removed: %d\n", stats.removedFiles)
	}

	if stats.corruptedFiles > 0 {
		fmt.Printf("\nFound %d corrupted RouterInfo files causing parsing errors.\n", stats.corruptedFiles)
		if !removeBad {
			fmt.Println("To remove them, run this command again with --remove-bad flag.")
		}
		fmt.Println("These files are likely causing the 'mapping format violation' errors you're seeing.")
	} else {
		fmt.Println("\nNo corrupted RouterInfo files found. The parsing errors may be transient.")
	}
}

// findDefaultNetDbPath attempts to find the default netDb path for the current system
func findDefaultNetDbPath() string {
	// Common I2P netDb locations
	possiblePaths := []string{
		os.ExpandEnv("$HOME/.i2p/netDb"),
		os.ExpandEnv("$HOME/Library/Application Support/i2p/netDb"),
		"/var/lib/i2p/i2p-config/netDb",
		"/usr/share/i2p/netDb",
	}

	for _, path := range possiblePaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return "" // Return empty if not found
}
