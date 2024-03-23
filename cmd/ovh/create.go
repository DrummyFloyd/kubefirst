/*
Copyright (C) 2021-2023, Kubefirst

This program is licensed under MIT.
See the LICENSE file for more details.
*/
package ovh

import (
	"fmt"
	"os"

	"github.com/kubefirst/kubefirst/internal/catalog"
	"github.com/kubefirst/kubefirst/internal/cluster"
	"github.com/kubefirst/kubefirst/internal/gitShim"
	"github.com/kubefirst/kubefirst/internal/launch"
	"github.com/kubefirst/kubefirst/internal/progress"
	"github.com/kubefirst/kubefirst/internal/provision"
	"github.com/kubefirst/kubefirst/internal/utilities"
	"github.com/kubefirst/runtime/pkg"
	internalssh "github.com/kubefirst/runtime/pkg/ssh"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func createOvh(cmd *cobra.Command, args []string) error {
	cliFlags, err := utilities.GetFlags(cmd, "ovh")
	if err != nil {
		progress.Error(err.Error())
		return nil
	}

	progress.DisplayLogHints(15)

	isValid, catalogApps, err := catalog.ValidateCatalogApps(cliFlags.InstallCatalogApps)
	if !isValid {
		return err
	}

	err = ValidateProvidedFlags(cliFlags.GitProvider)
	if err != nil {
		progress.Error(err.Error())
		return nil
	}

	// If cluster setup is complete, return

	utilities.CreateK1ClusterDirectory(clusterNameFlag)

	gitAuth, err := gitShim.ValidateGitCredentials(cliFlags.GitProvider, cliFlags.GithubOrg, cliFlags.GitlabGroup)
	if err != nil {
		progress.Error(err.Error())
		return nil
	}

	// Validate git
	executionControl := viper.GetBool(fmt.Sprintf("kubefirst-checks.%s-credentials", cliFlags.GitProvider))
	if !executionControl {
		newRepositoryNames := []string{"gitops", "metaphor"}
		newTeamNames := []string{"admins", "developers"}

		initGitParameters := gitShim.GitInitParameters{
			GitProvider:  cliFlags.GitProvider,
			GitToken:     gitAuth.Token,
			GitOwner:     gitAuth.Owner,
			Repositories: newRepositoryNames,
			Teams:        newTeamNames,
		}

		err = gitShim.InitializeGitProvider(&initGitParameters)
		if err != nil {
			progress.Error(err.Error())
			return nil
		}
	}
	viper.Set(fmt.Sprintf("kubefirst-checks.%s-credentials", cliFlags.GitProvider), true)
	viper.WriteConfig()

	k3dClusterCreationComplete := viper.GetBool("launch.deployed")
	if !k3dClusterCreationComplete {
		launch.Up(nil, true, cliFlags.UseTelemetry)
	}

	err = pkg.IsAppAvailable(fmt.Sprintf("%s/api/proxyHealth", cluster.GetConsoleIngresUrl()), "kubefirst api")
	if err != nil {
		progress.Error("unable to start kubefirst api")
	}

	provision.CreateMgmtCluster(gitAuth, cliFlags, catalogApps)

	return nil
}

func ValidateProvidedFlags(gitProvider string) error {
	progress.AddStep("Validate provided flags")
	//
	// API OVH for DNS/TF and other OVH stuff
	OVH_ENDPOINT := os.Getenv("OVH_ENDPOINT")
	OVH_APPLICATION_KEY := os.Getenv("OVH_APPLICATION_KEY")
	OVH_APPLICATION_SECRET := os.Getenv("OVH_APPLICATION_SECRET")
	OVH_CONSUMER_KEY := os.Getenv("OVH_CONSUMER_KEY")
	ovhCredentials := []string{OVH_ENDPOINT, OVH_APPLICATION_KEY, OVH_APPLICATION_SECRET, OVH_CONSUMER_KEY}

	for _, ovhCredential := range ovhCredentials {
		if ovhCredential == "" {
			return fmt.Errorf("your OVH API credentials are not set. Please set and try again")
		}
	}
	// Validate required environment variables for dns provider
	if dnsProviderFlag == "cloudflare" {
		if os.Getenv("CF_API_TOKEN") == "" {
			return fmt.Errorf("your CF_API_TOKEN environment variable is not set. Please set and try again")
		}
	}

	switch gitProvider {
	case "github":
		key, err := internalssh.GetHostKey("github.com")
		if err != nil {
			return fmt.Errorf("known_hosts file does not exist - please run `ssh-keyscan github.com >> ~/.ssh/known_hosts` to remedy")
		} else {
			log.Info().Msgf("%s %s\n", "github.com", key.Type())
		}
	case "gitlab":
		key, err := internalssh.GetHostKey("gitlab.com")
		if err != nil {
			return fmt.Errorf("known_hosts file does not exist - please run `ssh-keyscan gitlab.com >> ~/.ssh/known_hosts` to remedy")
		} else {
			log.Info().Msgf("%s %s\n", "gitlab.com", key.Type())
		}
	}

	progress.CompleteStep("Validate provided flags")

	return nil
}
