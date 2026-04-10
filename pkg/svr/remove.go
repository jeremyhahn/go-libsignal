package svr

import (
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-libsignal/pkg/svr/svrpb"
)

// Remove4 deletes a backup from the SVR servers. The same request is sent to
// every server. No finalization is needed; the server does not return
// meaningful data beyond acknowledgment.
type Remove4 struct{}

// Requests returns a serialized remove request message suitable for sending
// to one server.
func (Remove4) Requests() ([]byte, error) {
	req := &svrpb.Request4{
		Inner: &svrpb.Request4_Remove_{
			Remove: &svrpb.Request4_Remove{},
		},
	}
	return proto.Marshal(req)
}

// RequestsN returns n copies of the remove request, one per server.
func (r Remove4) RequestsN(n int) ([][]byte, error) {
	msg, err := r.Requests()
	if err != nil {
		return nil, err
	}
	result := make([][]byte, n)
	for i := range result {
		result[i] = make([]byte, len(msg))
		copy(result[i], msg)
	}
	return result, nil
}
