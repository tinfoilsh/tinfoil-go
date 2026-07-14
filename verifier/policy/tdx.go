package policy

// TDXPolicy is the standard Intel TDX policy block. PlatformMeasurements
// names the measurements-map entries the machine is endorsed to run; the
// quote's own MRTD/RTMR0 select exactly one of them at policy assembly.
type TDXPolicy struct {
	QEVendorID                     string   `json:"qe_vendor_id"`
	MinimumQESVN                   uint16   `json:"minimum_qe_svn"`
	MinimumPCESVN                  uint16   `json:"minimum_pce_svn"`
	MinimumTEETCBSVN               string   `json:"minimum_tee_tcb_svn"`
	MRSeam                         string   `json:"mr_seam"`
	TDAttributes                   string   `json:"td_attributes"`
	XFAM                           string   `json:"xfam"`
	MRConfigIDZero                 bool     `json:"mr_config_id_zero"`
	MROwnerZero                    bool     `json:"mr_owner_zero"`
	MROwnerConfigZero              bool     `json:"mr_owner_config_zero"`
	MinimumTCBEvaluationDataNumber int      `json:"minimum_tcb_evaluation_data_number"`
	PlatformMeasurements           []string `json:"platform_measurements"`
}
