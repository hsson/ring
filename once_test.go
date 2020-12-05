package ring

import (
	"errors"
	"testing"
)

func TestOnceErrShouldOnlyRunOnce(t *testing.T) {
	o := onceErr{}

	count := 0

	for i := 0; i < 100; i++ {
		go o.do(func() error {
			count++
			return nil
		})
	}

	if count != 1 {
		t.Errorf("unexpected count, got %v want %v", count, 1)
	}
}

func TestOnceErrShouldReturnError(t *testing.T) {
	o := onceErr{}

	count := 0
	expectedErr := errors.New("some error")

	for i := 0; i < 100; i++ {
		err := o.do(func() error {
			count++
			return expectedErr
		})
		if err != expectedErr {
			t.Errorf("%d: got unexpected err: %v", i, err)
		}
	}

	if count != 1 {
		t.Errorf("unexpected count, got %v want %v", count, 1)
	}
}
