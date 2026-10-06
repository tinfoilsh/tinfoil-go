package mobile

// An error crosses the FFI as its message alone, so its category is read from
// the prefix the SDK's error types give it. These are the prefixes; any other
// message is an error outside the three categories.
const (
	// ConfigurationErrorPrefix leads an error in the caller's arguments or
	// options. Retrying will not help.
	ConfigurationErrorPrefix = "configuration error: "
	// AttestationErrorPrefix leads rejected evidence, policy or channel binding.
	AttestationErrorPrefix = "attestation error: "
)
