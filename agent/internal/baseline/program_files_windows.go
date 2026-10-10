//go:build windows

package baseline

func checkProgramFiles(cs *CheckSpec) ItemResult {
	return ItemResult{Error: true, Message: "linux_program_files仅支持Linux Ubuntu24"}
}
