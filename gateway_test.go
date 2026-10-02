package tinfoil

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

func TestGatewayVerificationsNameReplicaHosts(t *testing.T) {
	seal := &sealTransport{}
	for _, host := range []string{"b.example", "a.example"} {
		verified := &verify.Verification{ConfigRepo: "tinfoilsh/model"}
		seal.enclaves.Store(replica{host: host, ref: "tinfoilsh/model"}, &verifiedReplicaTransport{
			verification: func() *verify.Verification { return verified },
		})
	}
	got := (&Gateway{seal: seal}).Verifications()
	require.Len(t, got, 2)
	require.Equal(t, "a.example", got[0].Host)
	require.Equal(t, "b.example", got[1].Host)
}
