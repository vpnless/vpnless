package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/vpnless/vpnless/devicestore"
)

func main() {
	approveCmd := flag.NewFlagSet("approve", flag.ExitOnError)
	listCmd := flag.NewFlagSet("list", flag.ExitOnError)
	denyCmd := flag.NewFlagSet("deny", flag.ExitOnError)
	removeCmd := flag.NewFlagSet("remove", flag.ExitOnError)
	clearThreatCmd := flag.NewFlagSet("clear-threat", flag.ExitOnError)
	exportCmd := flag.NewFlagSet("export", flag.ExitOnError)

	approveStorage := approveCmd.String("storage", "./vpnless.db", "Path to device store SQLite database")
	listStorage := listCmd.String("storage", "./vpnless.db", "Path to device store SQLite database")
	denyStorage := denyCmd.String("storage", "./vpnless.db", "Path to device store SQLite database")
	removeStorage := removeCmd.String("storage", "./vpnless.db", "Path to device store SQLite database")
	clearThreatStorage := clearThreatCmd.String("storage", "./vpnless.db", "Path to device store SQLite database")
	exportStorage := exportCmd.String("storage", "./vpnless.db", "Path to device store SQLite database")
	exportOutput := exportCmd.String("output", "devices_export.json", "Output path for export")

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "approve":
		approveCmd.Parse(os.Args[2:])
		if approveCmd.NArg() < 1 {
			fmt.Fprintf(os.Stderr, "Error: device ID or public key required\n")
			os.Exit(1)
		}
		if err := devicestore.CLIApprove(*approveStorage, approveCmd.Arg(0)); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	case "list":
		listCmd.Parse(os.Args[2:])
		listType := "pending"
		if listCmd.NArg() > 0 {
			listType = strings.TrimSpace(listCmd.Arg(0))
		}
		var err error
		switch strings.ToLower(listType) {
		case "authorized":
			err = devicestore.CLIListAuthorized(*listStorage)
		case "denied":
			err = devicestore.CLIListDenied(*listStorage)
		case "all":
			err = devicestore.CLIListAllActivity(*listStorage)
		case "threats":
			err = devicestore.CLIListThreats(*listStorage)
		case "pending", "":
			err = devicestore.CLIListPending(*listStorage)
		default:
			fmt.Fprintf(os.Stderr, "Error: unknown list %q (use pending, authorized, denied, all, or threats)\n", listType)
			os.Exit(1)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	case "deny":
		denyCmd.Parse(os.Args[2:])
		if denyCmd.NArg() < 1 {
			fmt.Fprintf(os.Stderr, "Error: device ID or public key required\n")
			os.Exit(1)
		}
		if err := devicestore.CLIDeny(*denyStorage, denyCmd.Arg(0)); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	case "remove":
		removeCmd.Parse(os.Args[2:])
		if removeCmd.NArg() < 1 {
			fmt.Fprintf(os.Stderr, "Error: device ID or public key required\n")
			os.Exit(1)
		}
		if err := devicestore.CLIRemove(*removeStorage, removeCmd.Arg(0)); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	case "clear-threat":
		clearThreatCmd.Parse(os.Args[2:])
		if clearThreatCmd.NArg() < 1 {
			fmt.Fprintf(os.Stderr, "Error: IP address required (e.g. 203.0.113.50)\n")
			os.Exit(1)
		}
		if err := devicestore.CLIClearThreat(*clearThreatStorage, clearThreatCmd.Arg(0)); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	case "export":
		exportCmd.Parse(os.Args[2:])
		if err := devicestore.CLIExport(*exportStorage, *exportOutput); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `VPNLess CLI

Usage:
  vpnless <command> [options] [arguments]

Commands:
  approve <device-id|public-key>  Approve a pending device
  list [pending|authorized|denied|all|threats]  List pairing keys, merged activity (all), or threat targets
  clear-threat <ip>                 Remove IP from blacklist/tarpit/etc. (reset threat row)
  deny <device-id|public-key>      Deny a pending device
  remove <device-id|public-key>    Revoke authorized device or clear pairing-denial row
  export                           Export device store to JSON

Options:
  -storage <path>                  Path to device store SQLite DB (default: ./vpnless.db)

Examples:
  vpnless approve abc123
  vpnless list pending
  vpnless list authorized
  vpnless list denied
  vpnless list all
  vpnless list threats
  vpnless clear-threat 203.0.113.50
  vpnless deny abc123
  vpnless remove Q3GG_kQJNwDKOYMr
  vpnless export -output devices_backup.json
`)
}
