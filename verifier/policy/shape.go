package policy

// Shape is the canonical VM shape descriptor: the launch dimensions that
// determine a platform measurement. Disks counts every attached disk
// (root, config, external config, one per model). GPUs is nil when the
// dimension is unknown for a measured slug; a code artifact always
// declares it.
type Shape struct {
	CPUs     int  `json:"cpus"`
	MemoryMB int  `json:"memory_mb"`
	GPUs     *int `json:"gpus,omitempty"`
	Disks    int  `json:"disks"`
}

// Satisfies reports whether a measured slug shape satisfies the shape a
// code artifact requires. GPUs is compared only when the slug declares it.
func (s *Shape) Satisfies(required *Shape) bool {
	if s == nil || required == nil {
		return false
	}
	if s.CPUs != required.CPUs || s.MemoryMB != required.MemoryMB || s.Disks != required.Disks {
		return false
	}
	if s.GPUs != nil && required.GPUs != nil && *s.GPUs != *required.GPUs {
		return false
	}
	return true
}

// Stack identifies the host software that produced a measurement.
type Stack struct {
	QEMU string `json:"qemu,omitempty"`
	OVMF string `json:"ovmf,omitempty"`
}
