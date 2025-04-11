package webt

import (
	"bytes"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDatagramChunker(t *testing.T) {
	h := NewDatagramChunker()
	defer h.Close()
	wg := &sync.WaitGroup{}

	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// generate test random data
			r := rand.New(rand.NewSource(time.Now().UnixNano()))
			original := make([]byte, 1024*(r.Intn(1024)+2)) // at least 2KB
			_, _ = r.Read(original)

			// split to chunks
			chunks := h.Chunk(original)
			require.Greater(t, len(chunks), 1, "expected multiple chunks, got %d", len(chunks))

			// shuffle chunks to simulate out-of-order delivery
			r.Shuffle(len(chunks), func(i, j int) { chunks[i], chunks[j] = chunks[j], chunks[i] })

			// feed shuffled chunks
			for _, chunk := range chunks {
				h.Receive(chunk)
			}

			// read reassembled message
			reassembled, err := h.Read()
			require.NoError(t, err, "unexpected error reading message: %v", err)
			assert.True(t, bytes.Equal(reassembled, original), "reassembled message does not match original")
		}()
	}
	wg.Wait()
}
