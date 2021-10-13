// Code generated by MockGen. DO NOT EDIT.
// Source: pkg/net/dns/dns.go

// Package mock_dns is a generated GoMock package.
package mock_dns

import (
	net "net"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
)

// MockDNS is a mock of DNS interface.
type MockDNS struct {
	ctrl     *gomock.Controller
	recorder *MockDNSMockRecorder
}

// MockDNSMockRecorder is the mock recorder for MockDNS.
type MockDNSMockRecorder struct {
	mock *MockDNS
}

// NewMockDNS creates a new mock instance.
func NewMockDNS(ctrl *gomock.Controller) *MockDNS {
	mock := &MockDNS{ctrl: ctrl}
	mock.recorder = &MockDNSMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockDNS) EXPECT() *MockDNSMockRecorder {
	return m.recorder
}

// LookupIP mocks base method.
func (m *MockDNS) LookupIP(domain string) ([]net.IP, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "LookupIP", domain)
	ret0, _ := ret[0].([]net.IP)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// LookupIP indicates an expected call of LookupIP.
func (mr *MockDNSMockRecorder) LookupIP(domain interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "LookupIP", reflect.TypeOf((*MockDNS)(nil).LookupIP), domain)
}

// Resolver mocks base method.
func (m *MockDNS) Resolver() *net.Resolver {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Resolver")
	ret0, _ := ret[0].(*net.Resolver)
	return ret0
}

// Resolver indicates an expected call of Resolver.
func (mr *MockDNSMockRecorder) Resolver() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Resolver", reflect.TypeOf((*MockDNS)(nil).Resolver))
}
