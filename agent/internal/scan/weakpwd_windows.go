//go:build windows

package scan

import (
	"context"
	pb "github.com/alinksec/alinksec-agent/internal/proto"
)

func WeakPasswordContract() uint32 { return 0 }
func detectWeakPasswords(context.Context, func(context.Context) error) ([]*pb.WeakPwdFinding, *pb.WeakPasswordCoverage) {
	return nil, &pb.WeakPasswordCoverage{Status: "unsupported", Issues: []string{"platform_unsupported"}}
}
