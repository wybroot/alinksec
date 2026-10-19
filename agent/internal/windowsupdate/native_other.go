//go:build !windows

package windowsupdate

import (
	"context"
	"fmt"
)

func ExecutionContract() uint32 { return 0 }
func nativeRun(context.Context, Request) (response, error) {
	return response{}, fmt.Errorf("Windows Update Agent unavailable")
}
