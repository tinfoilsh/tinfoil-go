package sev

import (
	"encoding/hex"
	"fmt"
)

// Identity returns the machines-map lookup key for a verified SEV-SNP
// report's CHIP_ID field. The field is always 64 bytes; Turin hardware
// delivers its 8-byte hwID zero-padded, which is exactly the endorsed form,
// so no product-specific handling is needed.
func Identity(chipID []byte) (string, error) {
	if len(chipID) != 64 {
		return "", fmt.Errorf("SEV CHIP_ID must be 64 bytes, got %d", len(chipID))
	}
	return hex.EncodeToString(chipID), nil
}
