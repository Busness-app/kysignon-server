package backup

import "net/http"

// NewClientWithTransportForTest builds a KyRecoveryClient whose requests never leave the
// process. The production client resolves the host and refuses private addresses, so a canned
// response cannot be served from a local listener.
func NewClientWithTransportForTest(rt http.RoundTripper) *KyRecoveryClient {
	return &KyRecoveryClient{client: &http.Client{Transport: rt}}
}
