package nuclei

// ProgressCallback interface for nuclei scan progress updates
type ProgressCallback interface {
	OnNucleiScanProgress(host string, testsCompleted int)
	OnNucleiScanComplete(testsPerformed, findings int)
}
