package tdx

import "crypto/sha256"

// ReportData returns authenticated bytes without claiming a client binding.
func (q *Quote) ReportData() (data [64]byte) {
	copy(data[:], q.quote.GetTdQuoteBody().GetReportData())
	return data
}

// ConfigHash returns the private config commitment for a runtime-only check.
func (q *Quote) ConfigHash() (hash [sha256.Size]byte) {
	copy(hash[:], q.quote.GetTdQuoteBody().GetMrConfigId())
	return hash
}
