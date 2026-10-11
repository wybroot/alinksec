package baseline

import (
	_ "embed"
	"encoding/json"
	"runtime"
)

// The command set is compiled into the Agent. Candidate imports cannot extend it.
//
//go:embed commands.json
var commandRegistry []byte

var approvedCmdOutput = func() map[string]struct{} {
	var platforms map[string][]string
	if err := json.Unmarshal(commandRegistry, &platforms); err != nil {
		panic(err)
	}
	commands := platforms[runtime.GOOS]
	result := make(map[string]struct{}, len(commands))
	for _, command := range commands {
		result[command] = struct{}{}
	}
	return result
}()

func isApprovedCmdOutput(command string) bool {
	_, ok := approvedCmdOutput[command]
	return ok
}
