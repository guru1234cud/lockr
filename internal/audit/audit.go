package audit

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"sync"
	"time"

	"github.com/etherance/lockr/internal/storage"
	"github.com/oklog/ulid/v2"
)

type Entry struct {
	ID            string    `json:"id"`
	Timestamp     time.Time `json:"timestamp"`
	Identity      string    `json:"identity"`
	AuthMethod    string    `json:"auth_method"`
	Operation     string    `json:"operation"`
	Path          string    `json:"path"`
	SecretVersion int       `json:"secret_version,omitempty"`
	SourceIP      string    `json:"source_ip"`
	RequestID     string    `json:"request_id"`
	Status        string    `json:"status"`
	DurationMS    int64     `json:"duration_ms"`
}

type Logger struct {
	db      *storage.DB
	logFile string
	mu      sync.Mutex
	f       *os.File
	entropy *rand.Rand
}

func NewLogger(db *storage.DB, logFile string) (*Logger, error) {
	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	return &Logger{
		db:      db,
		logFile: logFile,
		f:       f,
		entropy: rand.New(rand.NewSource(time.Now().UnixNano())),
	}, nil
}

func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f != nil {
		return l.f.Close()
	}
	return nil
}

func (l *Logger) Log(e Entry) error {
	e.ID = ulid.MustNew(ulid.Timestamp(e.Timestamp), l.entropy).String()
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}

	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("marshal audit entry: %w", err)
	}

	key := fmt.Sprintf("audit/%s/%s", e.Timestamp.Format(time.RFC3339Nano), e.ID)
	if err := l.db.Set(key, data); err != nil {
		return fmt.Errorf("write audit to db: %w", err)
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	_, err = fmt.Fprintf(l.f, "%s\n", data)
	return err
}

type QueryOptions struct {
	Service string
	Since   time.Duration
	Path    string
	Limit   int
}

func (l *Logger) Query(opts QueryOptions) ([]Entry, error) {
	entries, err := l.db.Scan("audit/")
	if err != nil {
		return nil, err
	}

	since := time.Time{}
	if opts.Since > 0 {
		since = time.Now().UTC().Add(-opts.Since)
	}

	var results []Entry
	for _, data := range entries {
		var e Entry
		if err := json.Unmarshal(data, &e); err != nil {
			continue
		}
		if opts.Service != "" && e.Identity != opts.Service {
			continue
		}
		if !since.IsZero() && e.Timestamp.Before(since) {
			continue
		}
		if opts.Path != "" && e.Path != opts.Path {
			continue
		}
		results = append(results, e)
		if opts.Limit > 0 && len(results) >= opts.Limit {
			break
		}
	}
	return results, nil
}
