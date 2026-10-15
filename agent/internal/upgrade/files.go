package upgrade

import "github.com/alinksec/alinksec-agent/internal/securestate"

func lockUpgrade(workDir string) (func(), error) { return securestate.Lock(upgradeDir(workDir)) }
func replaceRecord(src, dst string) error        { return securestate.Replace(src, dst) }
func syncDirectory(path string) error            { return securestate.SyncDirectory(path) }
func moveExecutable(src, dst string) error       { return securestate.Move(src, dst) }
