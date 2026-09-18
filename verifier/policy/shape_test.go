package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShapeSatisfiesNil(t *testing.T) {
	shape := &Shape{CPUs: 4, MemoryMB: 4096, Disks: 3}
	assert.False(t, shape.Satisfies(nil))
	assert.False(t, (*Shape)(nil).Satisfies(shape))
}
