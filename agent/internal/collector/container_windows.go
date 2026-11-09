//go:build windows

package collector

import pb "github.com/alinksec/alinksec-agent/internal/proto"

// Docker Desktop is intentionally not queried by the Windows Agent in this release.
func collectContainers(snap *pb.RptAssetSnapshot) {
	collectionStatus(snap, "containers", pb.AssetCollection_UNSUPPORTED, "unsupported_platform")
}

func collectContainersForNode(snap *pb.RptAssetSnapshot, kubernetesNodeName string) {
	collectContainers(snap)
}
