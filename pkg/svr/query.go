package svr

import (
	"math"

	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-libsignal/pkg/svr/svrpb"
)

// Query4 checks whether a backup exists on the SVR servers and returns the
// minimum number of tries remaining across all servers. The same request is
// sent to every server.
type Query4 struct{}

// Requests returns an iterator-like function that produces serialized query
// request messages. Each call returns the same message, suitable for sending
// to one server. The caller should invoke the function once per server.
func (Query4) Requests() ([]byte, error) {
	req := &svrpb.Request4{
		Inner: &svrpb.Request4_Query_{
			Query: &svrpb.Request4_Query{},
		},
	}
	return proto.Marshal(req)
}

// RequestsN returns n copies of the query request, one per server.
func (q Query4) RequestsN(n int) ([][]byte, error) {
	msg, err := q.Requests()
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

// Finalize processes all server responses and returns the minimum tries
// remaining. It returns an error if any response is malformed or has a non-OK
// status.
func (Query4) Finalize(responses [][]byte) (uint32, error) {
	if len(responses) == 0 {
		return 0, ErrBadData
	}
	minTries := uint32(math.MaxUint32)
	for _, b := range responses {
		resp := &svrpb.Response4{}
		if err := proto.Unmarshal(b, resp); err != nil {
			return 0, ErrBadData
		}
		inner, ok := resp.Inner.(*svrpb.Response4_Query_)
		if !ok || inner == nil {
			return 0, ErrBadData
		}
		q := inner.Query
		if err := checkStatus(q.GetStatus()); err != nil {
			return 0, err
		}
		if q.GetTriesRemaining() < minTries {
			minTries = q.GetTriesRemaining()
		}
	}
	return minTries, nil
}

// checkStatus validates a response status, returning nil for OK and an error
// otherwise.
func checkStatus(s svrpb.Response4_Status) error {
	if s == svrpb.Response4_OK {
		return nil
	}
	return newBadResponseStatusError(ResponseStatus(s))
}
