package cli

import (
	"net/http"
	"strings"

	"github.com/kanopy-platform/k8s-auth-portal/internal/server"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type RootCommand struct{}

func NewRootCommand() *cobra.Command {
	root := &RootCommand{}

	cmd := &cobra.Command{
		Use:               "k8s-auth-portal",
		PersistentPreRunE: root.persistentPreRunE,
		RunE:              root.runE,
	}

	cmd.PersistentFlags().String("log-level", "info", "Configure log level")
	cmd.PersistentFlags().String("listen-address", ":8080", "Server listen address")
	cmd.PersistentFlags().String("session-name", "k8s-auth-portal-session", "session cookie name")
	cmd.PersistentFlags().String("session-secret-filepath", "", "path to session secret")
	cmd.PersistentFlags().String("kubectl-client-id", "kubectl", "public oidc client-id for kubectl")
	cmd.PersistentFlags().StringSlice("scope", []string{}, "extra oidc scope claims")
	cmd.PersistentFlags().String("api-url", "https://api.example.com", "kubernetes API URL")
	cmd.PersistentFlags().String("issuer-url", "https://dex.example.com", "oidc issuer URL")
	cmd.PersistentFlags().String("cluster-ca-filepath", "", "cluster CA certificate filepath")
	cmd.PersistentFlags().String("kubectl-client-secret-filepath", "", "path to public odic client secret")
	cmd.PersistentFlags().String("debug-url", "https://prometheus.example.com/metrics", "additional URL endpoint for debugging")

	return cmd
}

func (c *RootCommand) persistentPreRunE(cmd *cobra.Command, args []string) error {
	// bind flags to viper
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.SetEnvPrefix("app")
	viper.AutomaticEnv()

	if err := viper.BindPFlags(cmd.Flags()); err != nil {
		return err
	}

	// set log level
	logLevel, err := log.ParseLevel(viper.GetString("log-level"))
	if err != nil {
		return err
	}

	log.SetLevel(logLevel)

	return nil
}

func getServerOptions() []server.ServerFuncOpt {
	opts := []server.ServerFuncOpt{
		server.WithSessionName(viper.GetString("session-name")),
		server.WithSessionSecret(viper.GetString("session-secret-filepath")),
		server.WithKubectlClientID(viper.GetString("kubectl-client-id")),
		server.WithExtraScopes(viper.GetStringSlice("scope")...),
		server.WithAPIServerURL(viper.GetString("api-url")),
		server.WithIssuerURL(viper.GetString("issuer-url")),
		server.WithClusterCA(viper.GetString("cluster-ca-filepath")),
		server.WithKubectlClientSecret(viper.GetString("kubectl-client-secret-filepath")),
		server.WithDebugURL(viper.GetString("debug-url")),
	}

	return opts
}

func (c *RootCommand) runE(cmd *cobra.Command, args []string) error {
	addr := viper.GetString("listen-address")

	log.Printf("Starting server on %s\n", addr)

	opts := getServerOptions()

	s, err := server.New(opts...)
	if err != nil {
		return err
	}

	log.Debug("debug mode on")

	return http.ListenAndServe(addr, s)
}
