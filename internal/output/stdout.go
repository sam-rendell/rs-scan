package output

import (
	"bufio"
	"os"
)

// StdoutWriter streams batched JSONL to stdout.
type StdoutWriter struct {
	batch *batchWriter
	out   *bufio.Writer
}

// NewStdoutWriter creates a writer that batches JSON results and flushes to stdout.
func NewStdoutWriter(batchSize int) *StdoutWriter {
	w := &StdoutWriter{
		out: bufio.NewWriterSize(os.Stdout, 32768),
	}
	w.batch = newBatchWriter(batchSize, func(data []byte) error {
		_, err := w.out.Write(data)
		if err != nil {
			return err
		}
		return w.out.Flush()
	})
	return w
}

func (w *StdoutWriter) Write(res *Result) error {
	return w.batch.write(res)
}

func (w *StdoutWriter) Close() error {
	batchErr := w.batch.close()
	flushErr := w.out.Flush()
	if batchErr != nil {
		return batchErr
	}
	return flushErr
}
