package events

import (
	"context"
	"io"
	"time"

	"github.com/gravitational/teleport/lib/session"

	"github.com/gravitational/trace"
)

type ForwardingSessionLogConfig struct {
	SessionID      session.ID
	ServerID       string
	DataDir        string
	RecordSessions bool
	Namespace      string
	ForwardTo      IAuditLog
}

func (s *ForwardingSessionLogConfig) CheckAndSetDefaults() error {
	if s.ForwardTo == nil {
		return trace.BadParameter("missing parameter bucket")
	}
	if s.DataDir == "" {
		return trace.BadParameter("missing data dir")
	}
	return nil
}

func NewForwardingSessionLog(cfg ForwardingSessionLogConfig) (*ForwardingSessionLog, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	diskLogger, err := NewDiskSessionLogger(DiskSessionLoggerConfig{
		SessionID:      cfg.SessionID,
		DataDir:        cfg.DataDir,
		RecordSessions: cfg.RecordSessions,
		Namespace:      cfg.Namespace,
		ServerID:       cfg.ServerID,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &ForwardingSessionLog{
		ForwardingSessionLogConfig: cfg,
		sessionLogger:              diskLogger,
	}, nil
}

// ForwardingSessionLog logs session on local disk and forwards all events
type ForwardingSessionLog struct {
	ForwardingSessionLogConfig
	sessionLogger *DiskSessionLogger
}

// Closer releases connection and resources associated with log if any
func (l *ForwardingSessionLog) Close() error {
	return l.sessionLogger.Finalize()
}

// EmitAuditEvent emits audit event
func (l *ForwardingSessionLog) EmitAuditEvent(eventType string, fields EventFields) error {
	return l.ForwardTo.EmitAuditEvent(eventType, fields)
}

// PostSessionSlice sends chunks of recorded session to the event log
func (l *ForwardingSessionLog) PostSessionSlice(slice SessionSlice) error {
	err := l.sessionLogger.PostSessionSlice(slice)
	if err != nil {
		return trace.Wrap(err)
	}
	// filter out chunks with session print events,
	// as this logger forwards only audit events to the auth server
	var chunks []*SessionChunk
	for _, chunk := range slice.Chunks {
		if chunk.EventType != SessionPrintEvent {
			chunks = append(chunks, chunk)
		}
		if chunk.EventType == SessionEndEvent {
			if err := l.sessionLogger.Finalize(); err != nil {
				return trace.Wrap(err)
			}
		}
	}
	// no chunks to post (all chunks are print events)
	if len(chunks) == 0 {
		return nil
	}
	slice.Chunks = chunks
	err = l.ForwardTo.PostSessionSlice(slice)
	return err
}

// PostSessionChunk returns a writer which SSH nodes use to submit
// their live sessions into the session log
func (l *ForwardingSessionLog) PostSessionChunk(namespace string, sid session.ID, reader io.Reader) error {
	return l.ForwardTo.PostSessionChunk(namespace, sid, reader)
}

// GetSessionChunk returns a reader which can be used to read a byte stream
// of a recorded session starting from 'offsetBytes' (pass 0 to start from the
// beginning) up to maxBytes bytes.
//
// If maxBytes > MaxChunkBytes, it gets rounded down to MaxChunkBytes
func (l *ForwardingSessionLog) GetSessionChunk(namespace string, sid session.ID, offsetBytes, maxBytes int) ([]byte, error) {
	return l.ForwardTo.GetSessionChunk(namespace, sid, offsetBytes, maxBytes)
}

// Returns all events that happen during a session sorted by time
// (oldest first).
//
// after tells to use only return events after a specified cursor Id
//
// This function is usually used in conjunction with GetSessionReader to
// replay recorded session streams.
func (l *ForwardingSessionLog) GetSessionEvents(namespace string, sid session.ID, after int, includePrintEvents bool) ([]EventFields, error) {
	return l.ForwardTo.GetSessionEvents(namespace, sid, after, includePrintEvents)
}

// SearchEvents is a flexible way to find  The format of a query string
// depends on the implementing backend. A recommended format is urlencoded
// (good enough for Lucene/Solr)
//
// Pagination is also defined via backend-specific query format.
//
// The only mandatory requirement is a date range (UTC). Results must always
// show up sorted by date (newest first)
func (l *ForwardingSessionLog) SearchEvents(fromUTC, toUTC time.Time, query string, limit int) ([]EventFields, error) {
	return l.ForwardTo.SearchEvents(fromUTC, toUTC, query, limit)
}

// SearchSessionEvents returns session related events only. This is used to
// find completed session.
func (l *ForwardingSessionLog) SearchSessionEvents(fromUTC time.Time, toUTC time.Time, limit int) ([]EventFields, error) {
	return l.ForwardTo.SearchSessionEvents(fromUTC, toUTC, limit)
}

// WaitForDelivery waits for resources to be released and outstanding requests to
// complete after calling Close method
func (l *ForwardingSessionLog) WaitForDelivery(ctx context.Context) error {
	return l.ForwardTo.WaitForDelivery(ctx)
}
