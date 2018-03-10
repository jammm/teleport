package filesessions

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/session"

	"github.com/gravitational/trace"
	log "github.com/sirupsen/logrus"
)

type Config struct {
	Directory string
}

func (s *Config) CheckAndSetDefaults() error {
	if s.Directory == "" {
		return trace.BadParameter("missing parameter Directory")
	}
	_, err := os.Stat(s.Directory)
	if err != nil {
		return trace.ConvertSystemError(err)
	}
	return nil
}

func NewHandler(cfg Config) (*Handler, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	h := &Handler{
		Entry: log.WithFields(log.Fields{
			trace.Component: teleport.Component(teleport.SchemeFile),
		}),
		Config: cfg,
	}
	return h, nil
}

// Handler handles upload and download
type Handler struct {
	Config
	*log.Entry
}

// Closer releases connection and resources associated with log if any
func (l *Handler) Close() error {
	return nil
}

func (l *Handler) path(sessionID session.ID) string {
	return filepath.Join(l.Directory, string(sessionID)+".tar")
}

func (l *Handler) Download(ctx context.Context, sessionID session.ID, writer io.WriterAt) error {
	path := l.path(sessionID)
	f, err := os.Open(path)
	if err != nil {
		return trace.ConvertSystemError(err)
	}
	defer f.Close()
	_, err = io.Copy(writer.(io.Writer), f)
	if err != nil {
		return trace.Wrap(err)
	}
	return nil
}

func (l *Handler) Upload(ctx context.Context, sessionID session.ID, reader io.Reader) (string, error) {
	path := l.path(sessionID)
	f, err := os.Create(path)
	if err != nil {
		return "", trace.ConvertSystemError(err)
	}
	_, err = io.Copy(f, reader)
	if err != nil {
		return "", trace.Wrap(err)
	}
	return fmt.Sprintf("%v://%v", teleport.SchemeFile, path), nil
}
