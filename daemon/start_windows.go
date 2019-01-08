package daemon // import "github.com/docker/docker/daemon"

import (
	"github.com/Microsoft/opengcs/client"
	"github.com/containerd/containerd/runtime/v2/runhcs/options"
	"github.com/docker/docker/container"
	"github.com/docker/docker/pkg/system"
	"github.com/sirupsen/logrus"
)

func (daemon *Daemon) getLibcontainerdCreateOptions(container *container.Container) (interface{}, error) {

	// Make sure we set the runhcs options to debug if we are at debug level.
	if system.ContainerdSupported() && logrus.GetLevel() == logrus.DebugLevel {
		opts := &options.Options{Debug: true}
		return opts, nil
	}

	// TODO @jhowardmsft (containerd) - Probably need to revisit LCOW options here
	// rather than blindly ignoring them.

	// LCOW options.
	if container.OS == "linux" {
		config := &client.Config{}
		if err := config.GenerateDefault(daemon.configStore.GraphOptions); err != nil {
			return nil, err
		}
		// Override from user-supplied options.
		for k, v := range container.HostConfig.StorageOpt {
			switch k {
			case "lcow.kirdpath":
				config.KirdPath = v
			case "lcow.kernel":
				config.KernelFile = v
			case "lcow.initrd":
				config.InitrdFile = v
			case "lcow.vhdx":
				config.Vhdx = v
			case "lcow.bootparameters":
				config.BootParameters = v
			}
		}
		if err := config.Validate(); err != nil {
			return nil, err
		}

		return config, nil
	}

	return nil, nil
}
