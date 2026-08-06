package measurement

// HardwareMeasurement represents the measurement values for a single platform from the hardware measurement repo
type HardwareMeasurement struct {
	ID    string // platform@digest
	MRTD  string
	RTMR0 string
}
