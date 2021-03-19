package sshauditor

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func TestBatch(t *testing.T) {
	batchInput := make(chan interface{})
	go func() {
		for i := 0; i < 10; i++ {
			batchInput <- i
		}
		close(batchInput)
	}()
	expected := [][]interface{}{
		{0, 1, 2, 3, 4, 5},
		{6, 7, 8, 9},
	}

	i := 0
	for o := range batch(context.TODO(), batchInput, 6, 2*time.Second) {
		if !reflect.DeepEqual(expected[i], o) {
			t.Errorf("Expected %v, got %v", expected[i], o)
		}
		i += 1
	}
}

func TestBatchWithPause(t *testing.T) {
	batchInput := make(chan interface{})
	go func() {
		for i := 0; i < 20; i++ {
			if i == 3 || i == 11 || i == 17 {
				time.Sleep(1 * time.Second)
			}
			batchInput <- i
		}
		close(batchInput)
	}()
	expected := [][]interface{}{
		{0, 1, 2},
		{3, 4, 5, 6, 7, 8},
		{9, 10},
		{11, 12, 13, 14, 15, 16},
		{17, 18, 19},
	}

	i := 0
	for o := range batch(context.TODO(), batchInput, 6, 500*time.Millisecond) {
		if !reflect.DeepEqual(expected[i], o) {
			t.Errorf("Expected %v, got %v", expected[i], o)
		}
		i += 1
	}
}
