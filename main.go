package main

import "github.com/hlandau/nomadircd/server"
import "gopkg.in/hlandau/service.v1"
import "github.com/hlandau/degoutils/config"

func main() {
	cfg := server.Config{}
	config := config.Configurator{
		ProgramName:     "nomadircd",
		ConfigFilePaths: []string{"$BIN/../etc/nomad.conf", "/etc/nomad/nomad.conf"},
	}
	config.ParseFatal(&cfg)

	service.Main(&service.Info{
		Name:          "nomadircd",
		Description:   "Nomad IRCd",
		DefaultChroot: service.EmptyChrootPath,
		RunFunc: func(smgr service.Manager) error {
			s, err := server.New(cfg)
			if err != nil {
				return err
			}

			err = s.Start()
			if err != nil {
				return err
			}

			err = smgr.DropPrivileges()
			if err != nil {
				return err
			}

			smgr.SetStarted()
			smgr.SetStatus("nomadircd: running ok")

			<-smgr.StopChan()
			s.Stop()

			return nil
		},
	})
}
