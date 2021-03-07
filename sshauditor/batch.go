package sshauditor

import (
	"context"
	"time"
)

func batch(ctx context.Context, c chan interface{}, size int, maxInterval time.Duration) chan []interface{} {
	oc := make(chan []interface{}, 100)
	go func() {
		defer close(oc)
		var i int
		xs := make([]interface{}, 0, size)
		lastOutput := time.Now()
		for {
			select {
			case x, ok := <-c:
				if !ok {
					goto done
				}
				xs = append(xs, x)
				i++
				if i >= size {
					oc <- xs
					xs = make([]interface{}, 0, size)
					i = 0
					lastOutput = time.Now()
				}
			case <-time.After(10 * time.Millisecond):
				if time.Since(lastOutput) > maxInterval && i > 0 {
					oc <- xs
					xs = make([]interface{}, 0, size)
					i = 0
					lastOutput = time.Now()
				}
			case <-ctx.Done():
				goto done
			}
		}
	done:
		if i > 0 {
			oc <- xs
		}
	}()
	return oc
}
