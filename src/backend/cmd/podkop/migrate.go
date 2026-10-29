package main

import (
	"fmt"
	"os"

	"github.com/podkop-net/podkop-experimental/src/backend/migrate"

	"github.com/spf13/cobra"
)

var commandMigrateFlagUCI string

// The command migrate: the settings of podkop 0.7 and of podkop-exp 0.8 turn into the format
// of this version (package migrate), the old file kept beside them. The uci-defaults of the
// package runs it at an install and an upgrade; settings of the format already are left alone.
var commandMigrate = &cobra.Command{
	Use:   "migrate",
	Short: "Convert the settings to the format of this version; the old file is kept",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		notes, err := migrate.File(commandMigrateFlagUCI)
		for _, note := range notes {
			fmt.Println(note)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "the settings were not converted: "+err.Error())
			os.Exit(1)
		}
	},
}

func init() {
	commandMigrate.Flags().StringVar(&commandMigrateFlagUCI, "uci", "/etc/config/podkop", "The settings file")
	mainCommand.AddCommand(commandMigrate)
}
