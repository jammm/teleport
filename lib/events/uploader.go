/*
Copyright 2018 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package events

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/session"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	log "github.com/sirupsen/logrus"
)

// UploadHandler is a function supplied by the user, it will upload
// the file
type UploadHandler interface {
	// Upload uploads session tarball and returns URL with uploaded file
	// in case of success.
	Upload(ctx context.Context, sessionID session.ID, readCloser io.Reader) (string, error)
	// Download downloads session tarball and writes it to writer
	Download(ctx context.Context, sessionID session.ID, writer io.WriterAt) error
}

// UploaderConfig sets up configuration for uploader service
type UploaderConfig struct {
	// DataDir is data directory for session events files
	DataDir string
	// Clock is the clock replacement
	Clock clockwork.Clock
	// Namespace is logger namespace
	Namespace string
	// ServerID is a server ID
	ServerID string
	// Context is an optional context
	Context context.Context
	// ScanPeriod is a uploader dir scan period
	ScanPeriod time.Duration
	// ConcurrentUploads sets up how many parallel uploads to schedule
	ConcurrentUploads int
	// Handler is upload handler supplied by user
	Handler UploadHandler
	// AuditLog is audit log client
	AuditLog IAuditLog
}

func (cfg *UploaderConfig) CheckAndSetDefaults() error {
	if cfg.ServerID == "" {
		return trace.BadParameter("missing parameter Context")
	}
	if cfg.AuditLog == nil {
		return trace.BadParameter("missing parameter AuditLog")
	}
	if cfg.DataDir == "" {
		return trace.BadParameter("missing parameter DataDir")
	}
	if cfg.Namespace == "" {
		return trace.BadParameter("missing parameter Namespace")
	}
	if cfg.Handler == nil {
		return trace.BadParameter("missing parameter Handler")
	}
	if cfg.ConcurrentUploads <= 0 {
		cfg.ConcurrentUploads = defaults.UploaderConcurrentUploads
	}
	if cfg.ScanPeriod <= 0 {
		cfg.ScanPeriod = defaults.UploaderScanPeriod
	}
	if cfg.Context == nil {
		cfg.Context = context.TODO()
	}
	if cfg.Clock == nil {
		cfg.Clock = clockwork.NewRealClock()
	}
	return nil
}

// NewUploader creates new disk based session logger
func NewUploader(cfg UploaderConfig) (*Uploader, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	ctx, cancel := context.WithCancel(cfg.Context)
	uploader := &Uploader{
		UploaderConfig: cfg,
		Entry: log.WithFields(log.Fields{
			trace.Component: teleport.ComponentAuditLog,
		}),
		cancel:    cancel,
		ctx:       ctx,
		semaphore: make(chan struct{}, cfg.ConcurrentUploads),
		scanDir:   filepath.Join(cfg.DataDir, cfg.ServerID, SessionLogsDir, cfg.Namespace),
	}
	return uploader, nil
}

// Uploader implements a disk based session logger. The imporant
// property of the disk based logger is that it never fails and can be used as
// a fallback implementation behind more sophisticated loggers.
type Uploader struct {
	UploaderConfig

	semaphore chan struct{}
	scanDir   string

	*log.Entry
	cancel context.CancelFunc
	ctx    context.Context
}

func (u *Uploader) Serve() error {
	t := time.NewTicker(u.ScanPeriod)
	defer t.Stop()
	for {
		select {
		case <-u.ctx.Done():
			u.Debugf("Context has closed.")
			return nil
		case <-t.C:
			if err := u.scan(); err != nil {
				if trace.Unwrap(err) != errContext {
					u.Warningf("Uploader scan failed: %v", trace.DebugReport(err))
				}
			}
		}
	}
}

var errContext = fmt.Errorf("context has closed")

func (u *Uploader) takeSemaphore() error {
	select {
	case u.semaphore <- struct{}{}:
		return nil
	case <-u.ctx.Done():
		u.Debugf("Context is closing.")
		return errContext
	}
}

func (u *Uploader) releaseSemaphore() error {
	select {
	case <-u.semaphore:
		return nil
	case <-u.ctx.Done():
		u.Debugf("Context is closing.")
		return errContext
	}
}

func (u *Uploader) removeFiles(sessionID session.ID) error {
	df, err := os.Open(u.scanDir)
	if err != nil {
		return trace.ConvertSystemError(err)
	}
	defer df.Close()
	entries, err := df.Readdir(-1)
	if err != nil {
		return trace.ConvertSystemError(err)
	}
	for i := range entries {
		fi := entries[i]
		if fi.IsDir() {
			continue
		}
		if !strings.HasPrefix(fi.Name(), string(sessionID)) {
			continue
		}
		path := filepath.Join(u.scanDir, fi.Name())
		if err := os.Remove(path); err != nil {
			log.Warningf("Failed to remove %v: %v.", path, trace.DebugReport(err))
		}
		log.Debugf("Removed %v.", path)
	}
	return nil
}

func (u *Uploader) uploadFile(lockFilePath string, sessionID session.ID) error {
	lockFile, err := os.Open(lockFilePath)
	if err != nil {
		return trace.ConvertSystemError(err)
	}
	if err := utils.FSTryWriteLock(lockFile); err != nil {
		return trace.Wrap(err)
	}
	reader, err := NewSessionArchive(u.DataDir, u.ServerID, u.Namespace, sessionID)
	if err != nil {
		return trace.Wrap(err)
	}
	if err := u.takeSemaphore(); err != nil {
		return trace.Wrap(err)
	}
	go func() {
		defer u.releaseSemaphore()
		defer reader.Close()
		defer lockFile.Close()
		defer utils.FSUnlock(lockFile)

		start := time.Now()
		url, err := u.Handler.Upload(u.ctx, sessionID, reader)
		if err != nil {
			u.WithFields(log.Fields{"duration": time.Now().Sub(start), "session-id": sessionID}).Warningf("File upload failed: %v", trace.DebugReport(err))
			return
		}
		u.WithFields(log.Fields{"duration": time.Now().Sub(start), "session-id": sessionID}).Warningf("File upload completed.")
		eventData, err := json.Marshal(EventFields{
			URL: url,
		})
		if err != nil {
			u.Errorf("Failed to marshal upload event: %v. Will retry next time.", trace.DebugReport(err))
			return
		}
		err = u.AuditLog.PostSessionSlice(SessionSlice{
			Namespace: u.Namespace,
			SessionID: string(sessionID),
			Chunks: []*SessionChunk{&SessionChunk{
				// This is the last event in the series
				// so the index is made to be the last index possible
				EventIndex: math.MaxInt64,
				EventType:  SessionUploadEvent,
				Time:       u.Clock.Now().In(time.UTC).UnixNano(),
				Data:       eventData,
			}},
		})
		if err != nil {
			u.Warningf("Failed to post upload event: %v. Will retry next time.", trace.DebugReport(err))
			return
		}
		if err := u.removeFiles(sessionID); err != nil {
			u.Warningf("Failed to remove files: %v.", err)
		}
	}()
	return nil
}

func (u *Uploader) scan() error {
	df, err := os.Open(u.scanDir)
	err = trace.ConvertSystemError(err)
	if err != nil {
		return trace.Wrap(err)
	}
	defer df.Close()
	entries, err := df.Readdir(-1)
	if err != nil {
		return trace.ConvertSystemError(err)
	}
	var count int
	for i := range entries {
		fi := entries[i]
		if fi.IsDir() {
			continue
		}
		if !strings.HasSuffix(fi.Name(), "completed") {
			continue
		}
		parts := strings.Split(fi.Name(), ".")
		if len(parts) < 2 {
			u.Debugf("Uploader, skipping unknown file: %v", fi.Name())
			continue
		}
		sessionID := session.ID(parts[0])
		lockFilePath := filepath.Join(u.scanDir, fi.Name())
		if err := u.uploadFile(lockFilePath, sessionID); err != nil {
			if trace.IsCompareFailed(err) {
				u.Debugf("Uploader detected locked file %v, another process is uploading it.", lockFilePath)
				continue
			}
			return trace.Wrap(err)
		}
		count += 1
	}
	return nil
}

func (u *Uploader) Stop() error {
	u.cancel()
	return nil
}
