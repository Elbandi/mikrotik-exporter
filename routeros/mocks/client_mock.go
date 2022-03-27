package mocks

// Code generated by http://github.com/gojuno/minimock (dev). DO NOT EDIT.

import (
	"sync"
	mm_atomic "sync/atomic"
	mm_time "time"

	"github.com/gojuno/minimock/v3"
	"gopkg.in/routeros.v2"
)

// ClientMock implements routeros.Client
type ClientMock struct {
	t minimock.Tester

	funcAsync          func() (ch1 <-chan error)
	inspectFuncAsync   func()
	afterAsyncCounter  uint64
	beforeAsyncCounter uint64
	AsyncMock          mClientMockAsync

	funcClose          func()
	inspectFuncClose   func()
	afterCloseCounter  uint64
	beforeCloseCounter uint64
	CloseMock          mClientMockClose

	funcRun          func(sentence ...string) (rp1 *routeros.Reply, err error)
	inspectFuncRun   func(sentence ...string)
	afterRunCounter  uint64
	beforeRunCounter uint64
	RunMock          mClientMockRun
}

// NewClientMock returns a mock for routeros.Client
func NewClientMock(t minimock.Tester) *ClientMock {
	m := &ClientMock{t: t}
	if controller, ok := t.(minimock.MockController); ok {
		controller.RegisterMocker(m)
	}

	m.AsyncMock = mClientMockAsync{mock: m}

	m.CloseMock = mClientMockClose{mock: m}

	m.RunMock = mClientMockRun{mock: m}
	m.RunMock.callArgs = []*ClientMockRunParams{}

	return m
}

type mClientMockAsync struct {
	mock               *ClientMock
	defaultExpectation *ClientMockAsyncExpectation
	expectations       []*ClientMockAsyncExpectation
}

// ClientMockAsyncExpectation specifies expectation struct of the Client.Async
type ClientMockAsyncExpectation struct {
	mock *ClientMock

	results *ClientMockAsyncResults
	Counter uint64
}

// ClientMockAsyncResults contains results of the Client.Async
type ClientMockAsyncResults struct {
	ch1 <-chan error
}

// Expect sets up expected params for Client.Async
func (mmAsync *mClientMockAsync) Expect() *mClientMockAsync {
	if mmAsync.mock.funcAsync != nil {
		mmAsync.mock.t.Fatalf("ClientMock.Async mock is already set by Set")
	}

	if mmAsync.defaultExpectation == nil {
		mmAsync.defaultExpectation = &ClientMockAsyncExpectation{}
	}

	return mmAsync
}

// Inspect accepts an inspector function that has same arguments as the Client.Async
func (mmAsync *mClientMockAsync) Inspect(f func()) *mClientMockAsync {
	if mmAsync.mock.inspectFuncAsync != nil {
		mmAsync.mock.t.Fatalf("Inspect function is already set for ClientMock.Async")
	}

	mmAsync.mock.inspectFuncAsync = f

	return mmAsync
}

// Return sets up results that will be returned by Client.Async
func (mmAsync *mClientMockAsync) Return(ch1 <-chan error) *ClientMock {
	if mmAsync.mock.funcAsync != nil {
		mmAsync.mock.t.Fatalf("ClientMock.Async mock is already set by Set")
	}

	if mmAsync.defaultExpectation == nil {
		mmAsync.defaultExpectation = &ClientMockAsyncExpectation{mock: mmAsync.mock}
	}
	mmAsync.defaultExpectation.results = &ClientMockAsyncResults{ch1}
	return mmAsync.mock
}

//Set uses given function f to mock the Client.Async method
func (mmAsync *mClientMockAsync) Set(f func() (ch1 <-chan error)) *ClientMock {
	if mmAsync.defaultExpectation != nil {
		mmAsync.mock.t.Fatalf("Default expectation is already set for the Client.Async method")
	}

	if len(mmAsync.expectations) > 0 {
		mmAsync.mock.t.Fatalf("Some expectations are already set for the Client.Async method")
	}

	mmAsync.mock.funcAsync = f
	return mmAsync.mock
}

// Async implements routeros.Client
func (mmAsync *ClientMock) Async() (ch1 <-chan error) {
	mm_atomic.AddUint64(&mmAsync.beforeAsyncCounter, 1)
	defer mm_atomic.AddUint64(&mmAsync.afterAsyncCounter, 1)

	if mmAsync.inspectFuncAsync != nil {
		mmAsync.inspectFuncAsync()
	}

	if mmAsync.AsyncMock.defaultExpectation != nil {
		mm_atomic.AddUint64(&mmAsync.AsyncMock.defaultExpectation.Counter, 1)

		mm_results := mmAsync.AsyncMock.defaultExpectation.results
		if mm_results == nil {
			mmAsync.t.Fatal("No results are set for the ClientMock.Async")
		}
		return (*mm_results).ch1
	}
	if mmAsync.funcAsync != nil {
		return mmAsync.funcAsync()
	}
	mmAsync.t.Fatalf("Unexpected call to ClientMock.Async.")
	return
}

// AsyncAfterCounter returns a count of finished ClientMock.Async invocations
func (mmAsync *ClientMock) AsyncAfterCounter() uint64 {
	return mm_atomic.LoadUint64(&mmAsync.afterAsyncCounter)
}

// AsyncBeforeCounter returns a count of ClientMock.Async invocations
func (mmAsync *ClientMock) AsyncBeforeCounter() uint64 {
	return mm_atomic.LoadUint64(&mmAsync.beforeAsyncCounter)
}

// MinimockAsyncDone returns true if the count of the Async invocations corresponds
// the number of defined expectations
func (m *ClientMock) MinimockAsyncDone() bool {
	for _, e := range m.AsyncMock.expectations {
		if mm_atomic.LoadUint64(&e.Counter) < 1 {
			return false
		}
	}

	// if default expectation was set then invocations count should be greater than zero
	if m.AsyncMock.defaultExpectation != nil && mm_atomic.LoadUint64(&m.afterAsyncCounter) < 1 {
		return false
	}
	// if func was set then invocations count should be greater than zero
	if m.funcAsync != nil && mm_atomic.LoadUint64(&m.afterAsyncCounter) < 1 {
		return false
	}
	return true
}

// MinimockAsyncInspect logs each unmet expectation
func (m *ClientMock) MinimockAsyncInspect() {
	for _, e := range m.AsyncMock.expectations {
		if mm_atomic.LoadUint64(&e.Counter) < 1 {
			m.t.Error("Expected call to ClientMock.Async")
		}
	}

	// if default expectation was set then invocations count should be greater than zero
	if m.AsyncMock.defaultExpectation != nil && mm_atomic.LoadUint64(&m.afterAsyncCounter) < 1 {
		m.t.Error("Expected call to ClientMock.Async")
	}
	// if func was set then invocations count should be greater than zero
	if m.funcAsync != nil && mm_atomic.LoadUint64(&m.afterAsyncCounter) < 1 {
		m.t.Error("Expected call to ClientMock.Async")
	}
}

type mClientMockClose struct {
	mock               *ClientMock
	defaultExpectation *ClientMockCloseExpectation
	expectations       []*ClientMockCloseExpectation
}

// ClientMockCloseExpectation specifies expectation struct of the Client.Close
type ClientMockCloseExpectation struct {
	mock *ClientMock

	Counter uint64
}

// Expect sets up expected params for Client.Close
func (mmClose *mClientMockClose) Expect() *mClientMockClose {
	if mmClose.mock.funcClose != nil {
		mmClose.mock.t.Fatalf("ClientMock.Close mock is already set by Set")
	}

	if mmClose.defaultExpectation == nil {
		mmClose.defaultExpectation = &ClientMockCloseExpectation{}
	}

	return mmClose
}

// Inspect accepts an inspector function that has same arguments as the Client.Close
func (mmClose *mClientMockClose) Inspect(f func()) *mClientMockClose {
	if mmClose.mock.inspectFuncClose != nil {
		mmClose.mock.t.Fatalf("Inspect function is already set for ClientMock.Close")
	}

	mmClose.mock.inspectFuncClose = f

	return mmClose
}

// Return sets up results that will be returned by Client.Close
func (mmClose *mClientMockClose) Return() *ClientMock {
	if mmClose.mock.funcClose != nil {
		mmClose.mock.t.Fatalf("ClientMock.Close mock is already set by Set")
	}

	if mmClose.defaultExpectation == nil {
		mmClose.defaultExpectation = &ClientMockCloseExpectation{mock: mmClose.mock}
	}

	return mmClose.mock
}

//Set uses given function f to mock the Client.Close method
func (mmClose *mClientMockClose) Set(f func()) *ClientMock {
	if mmClose.defaultExpectation != nil {
		mmClose.mock.t.Fatalf("Default expectation is already set for the Client.Close method")
	}

	if len(mmClose.expectations) > 0 {
		mmClose.mock.t.Fatalf("Some expectations are already set for the Client.Close method")
	}

	mmClose.mock.funcClose = f
	return mmClose.mock
}

// Close implements routeros.Client
func (mmClose *ClientMock) Close() {
	mm_atomic.AddUint64(&mmClose.beforeCloseCounter, 1)
	defer mm_atomic.AddUint64(&mmClose.afterCloseCounter, 1)

	if mmClose.inspectFuncClose != nil {
		mmClose.inspectFuncClose()
	}

	if mmClose.CloseMock.defaultExpectation != nil {
		mm_atomic.AddUint64(&mmClose.CloseMock.defaultExpectation.Counter, 1)

		return

	}
	if mmClose.funcClose != nil {
		mmClose.funcClose()
		return
	}
	mmClose.t.Fatalf("Unexpected call to ClientMock.Close.")

}

// CloseAfterCounter returns a count of finished ClientMock.Close invocations
func (mmClose *ClientMock) CloseAfterCounter() uint64 {
	return mm_atomic.LoadUint64(&mmClose.afterCloseCounter)
}

// CloseBeforeCounter returns a count of ClientMock.Close invocations
func (mmClose *ClientMock) CloseBeforeCounter() uint64 {
	return mm_atomic.LoadUint64(&mmClose.beforeCloseCounter)
}

// MinimockCloseDone returns true if the count of the Close invocations corresponds
// the number of defined expectations
func (m *ClientMock) MinimockCloseDone() bool {
	for _, e := range m.CloseMock.expectations {
		if mm_atomic.LoadUint64(&e.Counter) < 1 {
			return false
		}
	}

	// if default expectation was set then invocations count should be greater than zero
	if m.CloseMock.defaultExpectation != nil && mm_atomic.LoadUint64(&m.afterCloseCounter) < 1 {
		return false
	}
	// if func was set then invocations count should be greater than zero
	if m.funcClose != nil && mm_atomic.LoadUint64(&m.afterCloseCounter) < 1 {
		return false
	}
	return true
}

// MinimockCloseInspect logs each unmet expectation
func (m *ClientMock) MinimockCloseInspect() {
	for _, e := range m.CloseMock.expectations {
		if mm_atomic.LoadUint64(&e.Counter) < 1 {
			m.t.Error("Expected call to ClientMock.Close")
		}
	}

	// if default expectation was set then invocations count should be greater than zero
	if m.CloseMock.defaultExpectation != nil && mm_atomic.LoadUint64(&m.afterCloseCounter) < 1 {
		m.t.Error("Expected call to ClientMock.Close")
	}
	// if func was set then invocations count should be greater than zero
	if m.funcClose != nil && mm_atomic.LoadUint64(&m.afterCloseCounter) < 1 {
		m.t.Error("Expected call to ClientMock.Close")
	}
}

type mClientMockRun struct {
	mock               *ClientMock
	defaultExpectation *ClientMockRunExpectation
	expectations       []*ClientMockRunExpectation

	callArgs []*ClientMockRunParams
	mutex    sync.RWMutex
}

// ClientMockRunExpectation specifies expectation struct of the Client.Run
type ClientMockRunExpectation struct {
	mock    *ClientMock
	params  *ClientMockRunParams
	results *ClientMockRunResults
	Counter uint64
}

// ClientMockRunParams contains parameters of the Client.Run
type ClientMockRunParams struct {
	sentence []string
}

// ClientMockRunResults contains results of the Client.Run
type ClientMockRunResults struct {
	rp1 *routeros.Reply
	err error
}

// Expect sets up expected params for Client.Run
func (mmRun *mClientMockRun) Expect(sentence ...string) *mClientMockRun {
	if mmRun.mock.funcRun != nil {
		mmRun.mock.t.Fatalf("ClientMock.Run mock is already set by Set")
	}

	if mmRun.defaultExpectation == nil {
		mmRun.defaultExpectation = &ClientMockRunExpectation{}
	}

	mmRun.defaultExpectation.params = &ClientMockRunParams{sentence}
	for _, e := range mmRun.expectations {
		if minimock.Equal(e.params, mmRun.defaultExpectation.params) {
			mmRun.mock.t.Fatalf("Expectation set by When has same params: %#v", *mmRun.defaultExpectation.params)
		}
	}

	return mmRun
}

// Inspect accepts an inspector function that has same arguments as the Client.Run
func (mmRun *mClientMockRun) Inspect(f func(sentence ...string)) *mClientMockRun {
	if mmRun.mock.inspectFuncRun != nil {
		mmRun.mock.t.Fatalf("Inspect function is already set for ClientMock.Run")
	}

	mmRun.mock.inspectFuncRun = f

	return mmRun
}

// Return sets up results that will be returned by Client.Run
func (mmRun *mClientMockRun) Return(rp1 *routeros.Reply, err error) *ClientMock {
	if mmRun.mock.funcRun != nil {
		mmRun.mock.t.Fatalf("ClientMock.Run mock is already set by Set")
	}

	if mmRun.defaultExpectation == nil {
		mmRun.defaultExpectation = &ClientMockRunExpectation{mock: mmRun.mock}
	}
	mmRun.defaultExpectation.results = &ClientMockRunResults{rp1, err}
	return mmRun.mock
}

//Set uses given function f to mock the Client.Run method
func (mmRun *mClientMockRun) Set(f func(sentence ...string) (rp1 *routeros.Reply, err error)) *ClientMock {
	if mmRun.defaultExpectation != nil {
		mmRun.mock.t.Fatalf("Default expectation is already set for the Client.Run method")
	}

	if len(mmRun.expectations) > 0 {
		mmRun.mock.t.Fatalf("Some expectations are already set for the Client.Run method")
	}

	mmRun.mock.funcRun = f
	return mmRun.mock
}

// When sets expectation for the Client.Run which will trigger the result defined by the following
// Then helper
func (mmRun *mClientMockRun) When(sentence ...string) *ClientMockRunExpectation {
	if mmRun.mock.funcRun != nil {
		mmRun.mock.t.Fatalf("ClientMock.Run mock is already set by Set")
	}

	expectation := &ClientMockRunExpectation{
		mock:   mmRun.mock,
		params: &ClientMockRunParams{sentence},
	}
	mmRun.expectations = append(mmRun.expectations, expectation)
	return expectation
}

// Then sets up Client.Run return parameters for the expectation previously defined by the When method
func (e *ClientMockRunExpectation) Then(rp1 *routeros.Reply, err error) *ClientMock {
	e.results = &ClientMockRunResults{rp1, err}
	return e.mock
}

// Run implements routeros.Client
func (mmRun *ClientMock) Run(sentence ...string) (rp1 *routeros.Reply, err error) {
	mm_atomic.AddUint64(&mmRun.beforeRunCounter, 1)
	defer mm_atomic.AddUint64(&mmRun.afterRunCounter, 1)

	if mmRun.inspectFuncRun != nil {
		mmRun.inspectFuncRun(sentence...)
	}

	mm_params := &ClientMockRunParams{sentence}

	// Record call args
	mmRun.RunMock.mutex.Lock()
	mmRun.RunMock.callArgs = append(mmRun.RunMock.callArgs, mm_params)
	mmRun.RunMock.mutex.Unlock()

	for _, e := range mmRun.RunMock.expectations {
		if minimock.Equal(e.params, mm_params) {
			mm_atomic.AddUint64(&e.Counter, 1)
			return e.results.rp1, e.results.err
		}
	}

	if mmRun.RunMock.defaultExpectation != nil {
		mm_atomic.AddUint64(&mmRun.RunMock.defaultExpectation.Counter, 1)
		mm_want := mmRun.RunMock.defaultExpectation.params
		mm_got := ClientMockRunParams{sentence}
		if mm_want != nil && !minimock.Equal(*mm_want, mm_got) {
			mmRun.t.Errorf("ClientMock.Run got unexpected parameters, want: %#v, got: %#v%s\n", *mm_want, mm_got, minimock.Diff(*mm_want, mm_got))
		}

		mm_results := mmRun.RunMock.defaultExpectation.results
		if mm_results == nil {
			mmRun.t.Fatal("No results are set for the ClientMock.Run")
		}
		return (*mm_results).rp1, (*mm_results).err
	}
	if mmRun.funcRun != nil {
		return mmRun.funcRun(sentence...)
	}
	mmRun.t.Fatalf("Unexpected call to ClientMock.Run. %v", sentence)
	return
}

// RunAfterCounter returns a count of finished ClientMock.Run invocations
func (mmRun *ClientMock) RunAfterCounter() uint64 {
	return mm_atomic.LoadUint64(&mmRun.afterRunCounter)
}

// RunBeforeCounter returns a count of ClientMock.Run invocations
func (mmRun *ClientMock) RunBeforeCounter() uint64 {
	return mm_atomic.LoadUint64(&mmRun.beforeRunCounter)
}

// Calls returns a list of arguments used in each call to ClientMock.Run.
// The list is in the same order as the calls were made (i.e. recent calls have a higher index)
func (mmRun *mClientMockRun) Calls() []*ClientMockRunParams {
	mmRun.mutex.RLock()

	argCopy := make([]*ClientMockRunParams, len(mmRun.callArgs))
	copy(argCopy, mmRun.callArgs)

	mmRun.mutex.RUnlock()

	return argCopy
}

// MinimockRunDone returns true if the count of the Run invocations corresponds
// the number of defined expectations
func (m *ClientMock) MinimockRunDone() bool {
	for _, e := range m.RunMock.expectations {
		if mm_atomic.LoadUint64(&e.Counter) < 1 {
			return false
		}
	}

	// if default expectation was set then invocations count should be greater than zero
	if m.RunMock.defaultExpectation != nil && mm_atomic.LoadUint64(&m.afterRunCounter) < 1 {
		return false
	}
	// if func was set then invocations count should be greater than zero
	if m.funcRun != nil && mm_atomic.LoadUint64(&m.afterRunCounter) < 1 {
		return false
	}
	return true
}

// MinimockRunInspect logs each unmet expectation
func (m *ClientMock) MinimockRunInspect() {
	for _, e := range m.RunMock.expectations {
		if mm_atomic.LoadUint64(&e.Counter) < 1 {
			m.t.Errorf("Expected call to ClientMock.Run with params: %#v", *e.params)
		}
	}

	// if default expectation was set then invocations count should be greater than zero
	if m.RunMock.defaultExpectation != nil && mm_atomic.LoadUint64(&m.afterRunCounter) < 1 {
		if m.RunMock.defaultExpectation.params == nil {
			m.t.Error("Expected call to ClientMock.Run")
		} else {
			m.t.Errorf("Expected call to ClientMock.Run with params: %#v", *m.RunMock.defaultExpectation.params)
		}
	}
	// if func was set then invocations count should be greater than zero
	if m.funcRun != nil && mm_atomic.LoadUint64(&m.afterRunCounter) < 1 {
		m.t.Error("Expected call to ClientMock.Run")
	}
}

// MinimockFinish checks that all mocked methods have been called the expected number of times
func (m *ClientMock) MinimockFinish() {
	if !m.minimockDone() {
		m.MinimockAsyncInspect()

		m.MinimockCloseInspect()

		m.MinimockRunInspect()
		m.t.FailNow()
	}
}

// MinimockWait waits for all mocked methods to be called the expected number of times
func (m *ClientMock) MinimockWait(timeout mm_time.Duration) {
	timeoutCh := mm_time.After(timeout)
	for {
		if m.minimockDone() {
			return
		}
		select {
		case <-timeoutCh:
			m.MinimockFinish()
			return
		case <-mm_time.After(10 * mm_time.Millisecond):
		}
	}
}

func (m *ClientMock) minimockDone() bool {
	done := true
	return done &&
		m.MinimockAsyncDone() &&
		m.MinimockCloseDone() &&
		m.MinimockRunDone()
}