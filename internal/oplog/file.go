package oplog

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// File stores ops as JSON lines, one op per line, append-only.
type File struct{ Path string }

// Load reads every op. A missing file is an empty log.
func (f File) Load() ([]*Op, error) {
	fh, err := os.Open(f.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer fh.Close()

	var ops []*Op
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 64*1024), 16<<20)
	for line := 1; sc.Scan(); line++ {
		b := bytes.TrimSpace(sc.Bytes())
		if len(b) == 0 {
			continue
		}
		var op Op
		if err := json.Unmarshal(b, &op); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", f.Path, line, err)
		}
		ops = append(ops, &op)
	}
	return ops, sc.Err()
}

// Append writes op and fsyncs. It returns the bytes written.
func (f File) Append(op *Op) (int, error) {
	b, err := json.Marshal(op)
	if err != nil {
		return 0, err
	}
	fh, err := os.OpenFile(f.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, err
	}
	defer fh.Close()
	n, err := fh.Write(append(b, '\n'))
	if err != nil {
		return n, err
	}
	return n, fh.Sync()
}
