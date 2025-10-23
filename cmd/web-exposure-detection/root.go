package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Use:   "web-exposure-detection",
	Short: "A CLI tool for detecting web exposure vulnerabilities",
	Long: `Web Exposure Detection is a security tool that scans for 
potential web exposure vulnerabilities and misconfigurations that 
could lead to data breaches or unauthorized access.`,
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.web-exposure-detection.yaml)")
	rootCmd.PersistentFlags().BoolP("debug", "d", false, "Enable debug logging")
	rootCmd.PersistentFlags().String("pdf-generator", "rod", "PDF generator to use: 'rod' (Chrome/rod library) or 'playwright' (Chromium/playwright library)")

	// Bind viper to flags
	viper.BindPFlag("pdf_generator", rootCmd.PersistentFlags().Lookup("pdf-generator"))
}

func initConfig() {
	// Set defaults for discovery
	viper.SetDefault("discovery.skip_all", false)
	viper.SetDefault("discovery.skip_passive", false)
	viper.SetDefault("discovery.skip_certificate", false)
	viper.SetDefault("discovery.recursive", true)
	viper.SetDefault("discovery.recursion_depth", 0)
	viper.SetDefault("discovery.max_domains", 0)
	viper.SetDefault("discovery.threads", 50)
	viper.SetDefault("discovery.timeout", "10m")

	// Set defaults for scan
	viper.SetDefault("scan.preset", "slow")
	viper.SetDefault("scan.force", false)

	// Set defaults for output
	viper.SetDefault("pdf_generator", "rod")
	viper.SetDefault("log_level", "info")

	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".web-exposure-detection")
	}

	// Enable environment variable binding with prefix
	viper.SetEnvPrefix("WEB_EXPOSURE")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}
