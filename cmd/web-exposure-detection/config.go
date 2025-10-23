package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// configCmd represents the config command
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage configuration settings",
	Long: `Get and set configuration values for web-exposure-detection.
Configuration is stored in ~/.web-exposure-detection.yaml

Examples:
  web-exposure-detection config get pdf_generator
  web-exposure-detection config set pdf_generator playwright
  web-exposure-detection config list`,
}

var configGetCmd = &cobra.Command{
	Use:   "get [key]",
	Short: "Get a configuration value",
	Long: `Get a configuration value by key.

Examples:
  web-exposure-detection config get pdf_generator
  web-exposure-detection config get openrouter_api_key`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		key := args[0]
		value := viper.Get(key)

		if value == nil {
			fmt.Printf("%s is not set\n", key)
			return nil
		}

		fmt.Printf("%s: %v\n", key, value)
		return nil
	},
}

var configSetCmd = &cobra.Command{
	Use:   "set [key] [value]",
	Short: "Set a configuration value",
	Long: `Set a configuration value and save it to ~/.web-exposure-detection.yaml

Examples:
  web-exposure-detection config set pdf_generator playwright
  web-exposure-detection config set openrouter_api_key your-key-here
  web-exposure-detection config set debug true`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		key := args[0]
		value := args[1]

		// Set the value in viper
		viper.Set(key, value)

		// Get config file path
		configPath := viper.ConfigFileUsed()
		if configPath == "" {
			// Create default config file path
			home, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("failed to get home directory: %w", err)
			}
			configPath = filepath.Join(home, ".web-exposure-detection.yaml")
		}

		// Read existing config or create new one
		existingConfig := make(map[string]interface{})
		if data, err := os.ReadFile(configPath); err == nil {
			yaml.Unmarshal(data, &existingConfig)
		}

		// Update the value
		existingConfig[key] = value

		// Write updated config
		data, err := yaml.Marshal(existingConfig)
		if err != nil {
			return fmt.Errorf("failed to marshal config: %w", err)
		}

		err = os.WriteFile(configPath, data, 0600)
		if err != nil {
			return fmt.Errorf("failed to write config file: %w", err)
		}

		fmt.Printf("Set %s = %v in %s\n", key, value, configPath)
		return nil
	},
}

var configListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all configuration values",
	Long:  `List all configuration values from config file and environment.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		configPath := viper.ConfigFileUsed()
		if configPath == "" {
			fmt.Println("No config file loaded")
			fmt.Println("Default location: ~/.web-exposure-detection.yaml")
		} else {
			fmt.Printf("Config file: %s\n", configPath)
		}

		fmt.Println("\nConfiguration values:")
		fmt.Println("---------------------")

		allSettings := viper.AllSettings()
		if len(allSettings) == 0 {
			fmt.Println("No configuration values set")
			return nil
		}

		for key, value := range allSettings {
			fmt.Printf("%s: %v\n", key, value)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(configCmd)
	configCmd.AddCommand(configGetCmd)
	configCmd.AddCommand(configSetCmd)
	configCmd.AddCommand(configListCmd)
}
