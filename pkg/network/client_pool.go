package network

import "sync"

var clientPool *clientBufferPool

const defaultClientBufferSize = 1024

// ClientBuffer amortizes the allocations of objects generated when a client
// calls `GetConnections`.
type ClientBuffer struct {
	clientID string
	*ConnectionBuffer
	// TODO: consider recycling objects for HTTP and DNS data as well
}

type clientBufferPool struct {
	mux            sync.Mutex
	bufferByClient map[string]*ClientBuffer
}

func (p *clientBufferPool) Get(clientID string) *ClientBuffer {
	p.mux.Lock()
	defer p.mux.Unlock()

	buffer := p.bufferByClient[clientID]
	if buffer != nil {
		p.bufferByClient[clientID] = nil
		return buffer
	}

	return &ClientBuffer{
		clientID:         clientID,
		ConnectionBuffer: NewConnectionBuffer(defaultClientBufferSize),
	}
}

func (p *clientBufferPool) Put(b *ClientBuffer) {
	p.mux.Lock()
	defer p.mux.Unlock()

	b.Reset()
	p.bufferByClient[b.clientID] = b
}

func (p *clientBufferPool) RemoveExpiredClient(clientID string) {
	p.mux.Lock()
	defer p.mux.Unlock()
	delete(p.bufferByClient, clientID)
}

// Reclaim memory from the `Connections` underlying buffer
func Reclaim(c *Connections) {
	b := c.Buffer
	if b == nil {
		return
	}

	clientPool.Put(b)
}

func init() {
	clientPool = &clientBufferPool{
		bufferByClient: make(map[string]*ClientBuffer),
	}
}
