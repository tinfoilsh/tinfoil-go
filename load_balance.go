package tinfoil

import (
	"sync/atomic"

	"github.com/openai/openai-go/option"
)

type Enclave struct {
	Host string
	Repo string
}

type LoadBalancer struct {
	clients []*Client
	counter uint64
}

func NewLoadBalancer(enclaves []Enclave, openaiOpts ...option.RequestOption) (*LoadBalancer, error) {
	clients := make([]*Client, len(enclaves))
	for i, enclave := range enclaves {
		client, err := NewClientWithParams(
			enclave.Host,
			enclave.Repo,
			openaiOpts...,
		)
		if err != nil {
			return nil, err
		}
		clients[i] = client
	}
	return &LoadBalancer{clients: clients}, nil
}

// NextClient returns the next client in round robin fashion using atomic operations
func (lb *LoadBalancer) NextClient() *Client {
	count := atomic.AddUint64(&lb.counter, 1)
	index := (count - 1) % uint64(len(lb.clients))
	return lb.clients[index]
}
