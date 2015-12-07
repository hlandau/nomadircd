package main

import "github.com/hlandau/nomadircd/server"
import "gopkg.in/hlandau/service.v2"
import "gopkg.in/hlandau/easyconfig.v1"

func main() {
	cfg := server.Config{}
	config := easyconfig.Configurator{
		ProgramName: "nomadircd",
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
