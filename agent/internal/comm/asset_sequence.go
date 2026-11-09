package comm

import (
	"fmt"
	"github.com/alinksec/alinksec-agent/internal/securestate"
	"os"
	"path/filepath"
	"sync"
)

var assetSequenceMu sync.Mutex

// Reserve before collecting, so completion order and wall-clock rollback cannot
// make an older observation replace a newer one. The file survives Agent restart.
func reserveAssetSequence(work, agent string) (uint64, error) {
	assetSequenceMu.Lock()
	defer assetSequenceMu.Unlock()
	var state struct {
		Agent    string
		Sequence uint64
	}
	path := filepath.Join(work, "asset-sequence.json")
	err := securestate.ReadJSON(path, &state)
	if err != nil && !os.IsNotExist(err) {
		return 0, err
	}
	marker := filepath.Join(work, "asset-sequence.initialized.json")
	if os.IsNotExist(err) {
		if _, check := os.Stat(marker); check == nil {
			return 0, fmt.Errorf("asset sequence missing after initialization; restore state before collecting")
		} else if !os.IsNotExist(check) {
			return 0, check
		}
		state.Agent = agent
		if err := securestate.WriteJSON(path, state); err != nil {
			return 0, err
		}
	}
	if _, err := os.Stat(marker); os.IsNotExist(err) {
		if err := securestate.WriteJSON(marker, map[string]string{"agent": agent}); err != nil {
			return 0, err
		}
	} else if err != nil {
		return 0, err
	}
	if agent == "" || state.Agent != agent {
		return 0, fmt.Errorf("asset sequence belongs to a different Agent")
	}
	if state.Sequence >= uint64(1<<63-1) {
		return 0, fmt.Errorf("asset sequence exhausted")
	}
	state.Agent = agent
	state.Sequence++
	if err := securestate.WriteJSON(path, state); err != nil {
		return 0, err
	}
	return state.Sequence, nil
}
