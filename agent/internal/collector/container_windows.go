//go:build windows

package collector

import pb "github.com/alinksec/alinksec-agent/internal/proto"

// Docker Desktop is intentionally not queried by the Windows Agent in this release.
func collectContainers(snap *pb.RptAssetSnapshot) { collectContainersForNode(snap, "") }

func collectContainersForNode(snap *pb.RptAssetSnapshot, kubernetesNodeName string) {
	recordAttempt(snap, "docker", pb.AssetCollectionAttempt_UNSUPPORTED, "windows_container_collection_unsupported")
	recordAttempt(snap, "kubernetes", pb.AssetCollectionAttempt_UNSUPPORTED, "windows_container_collection_unsupported")
}
