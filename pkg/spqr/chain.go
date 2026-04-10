package spqr

import "github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"

// EpochChain holds the send and receive chain keys for a single epoch,
// along with counters tracking how many messages have been sent and
// received within this epoch.
type EpochChain struct {
	sendKey     *secret.Secret
	recvKey     *secret.Secret
	sendCounter uint32
	recvCounter uint32
}

// Zeroize destroys all key material in the chain.
func (c *EpochChain) Zeroize() {
	if c.sendKey != nil {
		c.sendKey.Destroy()
	}
	if c.recvKey != nil {
		c.recvKey.Destroy()
	}
}
