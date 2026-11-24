package main

import (
	"fmt"
	"os"

	"github.com/podkop-net/podkop-experimental/src/backend/migrate"

	"github.com/spf13/cobra"
)

var commandMigrateFlagUCI string

// The command migrate: the settings of podkop 0.7 and of podkop-exp 0.8 turn into the format
// of this version, the old file kept beside them, and what else an older release left to change
// is changed (migrate.Install). The uci-defaults of the package runs it at an install and an
// upgrade, with its lines to the log; settings that need nothing are left alone.
var commandMigrate = &cobra.Command{
	Use:   "migrate",
	Short: "Convert the settings to the format of this version; the old file is kept",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		err := migrate.Install(commandMigrateFlagUCI, func(note string) { fmt.Println(note) })
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
	},
}

func init() {
	commandMigrate.Flags().StringVar(&commandMigrateFlagUCI, "uci", "/etc/config/podkop", "The settings file")
	mainCommand.AddCommand(commandMigrate)
}
