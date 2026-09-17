package scanner

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestNoMatches(t *testing.T) {
	for _, input := range []string{"", "\n\n", "name=example\nport=8080", "secret=unmatched-value"} {
		got, err := testDetector(t).Scan(context.Background(), "fixture", strings.NewReader(input))
		if err != nil || got == nil || len(got) != 0 {
			t.Fatalf("clean scan = %v, %v; want empty findings", got, err)
		}
	}
}

func TestLineEndings(t *testing.T) {
	for _, ending := range []string{"\n", "\r\n"} {
		for _, trailing := range []bool{false, true} {
			input := "normal" + ending + "" + ending + "secret=SYNTHETIC_VALUE"
			if trailing {
				input += ending
			}
			got, err := testDetector(t).Scan(context.Background(), "fixture", strings.NewReader(input))
			if err != nil || len(got) != 1 || got[0].Line != 3 {
				t.Fatalf("ending %q, trailing %v: %v, %v", ending, trailing, got, err)
			}
		}
	}
}

func TestLineSizeBoundaries(t *testing.T) {
	d := testDetector(t)
	for _, size := range []int{64 * 1024, MaxLineBytes - 1, MaxLineBytes, MaxLineBytes + 1} {
		for _, ending := range []string{"", "\n", "\r\n"} {
			prefix := "secret=SYNTHETIC_VALUE "
			input := prefix + strings.Repeat(".", size-len(prefix)) + ending
			got, err := d.Scan(context.Background(), "fixture", strings.NewReader(input))
			if size > MaxLineBytes {
				if !errors.Is(err, ErrLineTooLong) || got != nil {
					t.Fatalf("size %d ending %q: want no findings and ErrLineTooLong; got %v, %v", size, ending, got, err)
				}
			} else if err != nil || len(got) != 1 {
				t.Fatalf("size %d ending %q: got %d findings, %v", size, ending, len(got), err)
			}
		}
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) {
	return 0, errors.New("read failure with SYNTHETIC_PRIVATE source content")
}

func TestReadFailureDiscardsFindingsAndSanitizesError(t *testing.T) {
	r := io.MultiReader(strings.NewReader("secret=SYNTHETIC_VALUE\n"), errorReader{})
	got, err := testDetector(t).Scan(context.Background(), "fixture", r)
	if got != nil || !errors.Is(err, ErrRead) {
		t.Fatalf("failed scan = %v, %v", got, err)
	}
	if strings.Contains(err.Error(), "SYNTHETIC_PRIVATE") {
		t.Fatal("reader error leaked source content")
	}
}

func TestOversizedLineDiscardsEarlierFindings(t *testing.T) {
	input := "secret=SYNTHETIC_VALUE\n" + strings.Repeat("x", MaxLineBytes+1)
	got, err := testDetector(t).Scan(context.Background(), "fixture", strings.NewReader(input))
	if got != nil || !errors.Is(err, ErrLineTooLong) {
		t.Fatalf("failed scan = %v, %v", got, err)
	}
}

type readFunc func([]byte) (int, error)

func (f readFunc) Read(p []byte) (int, error) { return f(p) }

func TestCancelledBeforeRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := readFunc(func([]byte) (int, error) {
		t.Fatal("cancelled scan must not read input")
		return 0, io.EOF
	})
	got, err := testDetector(t).Scan(ctx, "fixture", r)
	if got != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled scan = %v, %v", got, err)
	}
}

func TestCancelledDuringRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := io.MultiReader(strings.NewReader("secret=SYNTHETIC_VALUE\n"), readFunc(func([]byte) (int, error) {
		cancel()
		return 0, io.EOF
	}))
	got, err := testDetector(t).Scan(ctx, "fixture", r)
	if got != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled scan = %v, %v", got, err)
	}
}

func TestUnconfiguredDetectorCannotSucceed(t *testing.T) {
	for _, d := range []*Detector{nil, {}} {
		got, err := d.Scan(context.Background(), "fixture", strings.NewReader("anything"))
		if got != nil || !errors.Is(err, ErrNoRules) {
			t.Fatalf("unconfigured scan = %v, %v", got, err)
		}
	}
}

func TestNilReader(t *testing.T) {
	got, err := testDetector(t).Scan(context.Background(), "fixture", nil)
	if got != nil || !errors.Is(err, ErrRead) {
		t.Fatalf("nil reader scan = %v, %v", got, err)
	}
}
