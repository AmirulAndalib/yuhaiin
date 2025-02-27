package domain

import (
	"encoding/json"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
)

type Domain[T any] struct {
	Root         *domainNode[T] `json:"root"`          // for example.com, example.*
	WildcardRoot *domainNode[T] `json:"wildcard_root"` // for *.example.com, *.example.*
	lock         sync.Mutex
}

func (d *Domain[T]) Insert(domain string, mark T) {
	d.lock.Lock()
	defer d.lock.Unlock()

	if len(domain) == 0 {
		return
	}

	r := newDomainReader(domain)
	if domain[0] == '*' {
		insert(d.WildcardRoot, r, mark)
	} else {
		insert(d.Root, r, mark)
	}
}

func (d *Domain[T]) Search(domain proxy.Address) (mark T, ok bool) {
	r := newDomainReader(domain.Hostname())

	mark, ok = search(d.Root, r)
	if ok {
		return
	}

	r.reset()

	return search(d.WildcardRoot, r)
}

func (d *Domain[T]) Marshal() ([]byte, error) {
	return json.MarshalIndent(d, "", "  ")
}

func (d *Domain[T]) Clear() error {
	d.Root = &domainNode[T]{Child: map[string]*domainNode[T]{}}
	d.WildcardRoot = &domainNode[T]{Child: map[string]*domainNode[T]{}}
	return nil
}

func NewDomainMapper[T any]() *Domain[T] {
	return &Domain[T]{
		Root:         &domainNode[T]{Child: map[string]*domainNode[T]{}},
		WildcardRoot: &domainNode[T]{Child: map[string]*domainNode[T]{}},
	}
}
