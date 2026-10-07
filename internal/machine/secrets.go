package machine

import (
	"sync"

	"github.com/jaredfolkins/vmcp/api"
)

// secretStore holds the full spec, with file bodies and upstream tokens,
// in memory only, from create until start.
type secretStore struct {
	mu    sync.Mutex
	specs map[string]*api.MachineSpec
}

func (s *secretStore) put(id string, spec api.MachineSpec) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.specs == nil {
		s.specs = map[string]*api.MachineSpec{}
	}
	cp := spec
	cp.Files = append([]api.File(nil), spec.Files...)
	for i := range cp.Files {
		cp.Files[i].Body = append([]byte(nil), spec.Files[i].Body...)
	}
	s.specs[id] = &cp
}

// take removes and returns the spec.
func (s *secretStore) take(id string) *api.MachineSpec {
	s.mu.Lock()
	defer s.mu.Unlock()
	spec := s.specs[id]
	delete(s.specs, id)
	return spec
}

// clearSpec zeroes the secret bytes that a spec holds.
func clearSpec(spec *api.MachineSpec) {
	for i := range spec.Files {
		clear(spec.Files[i].Body)
	}
	for i := range spec.Redactions {
		clear(spec.Redactions[i])
	}
}
