package dialer

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestAvg(t *testing.T) {
	a := NewAvg()

	t.Log(a.Get())

	sum := 0
	for i := range 100 {
		sum += i
		a.Push(time.Millisecond * time.Duration(i))
	}

	assert.MustEqual(t, time.Millisecond*100, a.Avg())

	t.Log(a.Get())
}

func TestXxx(t *testing.T) {
	MergeDnsError(errors.Join(nil, fmt.Errorf("error")), nil)
}
