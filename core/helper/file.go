package helper

import (
	"errors"
	"fmt"
	"os"
)

// ErrFileTooBig is returned when file size is too big.
var ErrFileTooBig = errors.New("file size is too big")

// ReadFileSafeSize reads file and returns its content if file size is less than kbSize.\
func ReadFileSafeSize(filename string, kbSize int64) ([]byte, error) {
	fileInfo, err := os.Stat(filename)
	if err != nil {
		return nil, fmt.Errorf("stat file: %w", err)
	}

	if fileInfo.Size() > kbSize*1024 {
		return nil, fmt.Errorf("%w: %d", ErrFileTooBig, fileInfo.Size())
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	return data, nil
}
