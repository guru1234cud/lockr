package storage

import (
	"errors"
	"strings"
	"time"

	"github.com/dgraph-io/badger/v4"
)

var ErrNotFound = errors.New("not found")

type DB struct {
	bdb *badger.DB
}

type Options struct {
	DataDir  string
	InMemory bool
}

func Open(opts Options) (*DB, error) {
	dir := opts.DataDir
	if opts.InMemory {
		dir = ""
	}
	bopts := badger.DefaultOptions(dir).
		WithLogger(nil)
	if opts.InMemory {
		bopts = bopts.WithInMemory(true)
	}
	bdb, err := badger.Open(bopts)
	if err != nil {
		return nil, err
	}
	return &DB{bdb: bdb}, nil
}

func (db *DB) Close() error {
	return db.bdb.Close()
}

func (db *DB) Get(key string) ([]byte, error) {
	var val []byte
	err := db.bdb.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(key))
		if err != nil {
			return err
		}
		val, err = item.ValueCopy(nil)
		return err
	})
	if errors.Is(err, badger.ErrKeyNotFound) {
		return nil, ErrNotFound
	}
	return val, err
}

func (db *DB) Set(key string, value []byte) error {
	return db.bdb.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(key), value)
	})
}

func (db *DB) SetWithTTL(key string, value []byte, ttl time.Duration) error {
	return db.bdb.Update(func(txn *badger.Txn) error {
		e := badger.NewEntry([]byte(key), value).WithTTL(ttl)
		return txn.SetEntry(e)
	})
}

func (db *DB) Delete(key string) error {
	return db.bdb.Update(func(txn *badger.Txn) error {
		return txn.Delete([]byte(key))
	})
}

// List returns all keys with the given prefix.
func (db *DB) List(prefix string) ([]string, error) {
	var keys []string
	err := db.bdb.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()
		p := []byte(prefix)
		for it.Seek(p); it.ValidForPrefix(p); it.Next() {
			keys = append(keys, string(it.Item().KeyCopy(nil)))
		}
		return nil
	})
	return keys, err
}

// Scan returns all key-value pairs with the given prefix.
func (db *DB) Scan(prefix string) (map[string][]byte, error) {
	result := make(map[string][]byte)
	err := db.bdb.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		it := txn.NewIterator(opts)
		defer it.Close()
		p := []byte(prefix)
		for it.Seek(p); it.ValidForPrefix(p); it.Next() {
			item := it.Item()
			val, err := item.ValueCopy(nil)
			if err != nil {
				return err
			}
			result[string(item.KeyCopy(nil))] = val
		}
		return nil
	})
	return result, err
}

// ListDirect returns only the immediate children of a path prefix (one level deep).
func (db *DB) ListDirect(prefix string) ([]string, error) {
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	allKeys, err := db.List(prefix)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	var result []string
	for _, k := range allKeys {
		rest := strings.TrimPrefix(k, prefix)
		parts := strings.SplitN(rest, "/", 2)
		child := prefix + parts[0]
		if len(parts) > 1 {
			child += "/"
		}
		if !seen[child] {
			seen[child] = true
			result = append(result, child)
		}
	}
	return result, nil
}

// RunGC runs BadgerDB value log garbage collection.
func (db *DB) RunGC() error {
	return db.bdb.RunValueLogGC(0.5)
}

// Badger exposes the underlying badger.DB for advanced use (e.g. streaming).
func (db *DB) Badger() *badger.DB {
	return db.bdb
}
