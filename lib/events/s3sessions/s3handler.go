package s3sessions

import (
	"context"
	"fmt"
	"io"

	"github.com/gravitational/teleport/lib/session"

	"github.com/gravitational/trace"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	awssession "github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
)

type Config struct {
	Bucket  string
	Region  string
	Session *awssession.Session
}

func (s *Config) CheckAndSetDefaults() error {
	if s.Bucket == "" {
		return trace.BadParameter("missing parameter bucket")
	}
	if s.Session == nil {
		// create an AWS session using default SDK behavior, i.e. it will interpret
		// the environment and ~/.aws directory just like an AWS CLI tool would:
		sess, err := awssession.NewSessionWithOptions(awssession.Options{
			SharedConfigState: awssession.SharedConfigEnable,
		})
		if err != nil {
			return trace.Wrap(err)
		}
		// override the default environment (region + credentials) with the values
		// from the YAML file:
		if s.Region != "" {
			sess.Config.Region = aws.String(s.Region)
		}
		s.Session = sess
	}
	return nil
}

func NewHandler(cfg Config) (*Handler, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	return &Handler{
		Config:     cfg,
		uploader:   s3manager.NewUploader(cfg.Session),
		downloader: s3manager.NewDownloader(cfg.Session),
	}, nil
}

// Handler handles upload and download
type Handler struct {
	Config
	uploader   *s3manager.Uploader
	downloader *s3manager.Downloader
}

// Closer releases connection and resources associated with log if any
func (l *Handler) Close() error {
	return nil
}

func (l *Handler) Download(ctx context.Context, sessionID session.ID, writer io.WriterAt) error {
	path := string(sessionID) + ".tar"
	written, err := l.downloader.DownloadWithContext(ctx, writer, &s3.GetObjectInput{
		Bucket: aws.String(l.Bucket),
		Key:    aws.String(path),
	})
	if err != nil {
		return ConvertS3Error(err)
	}
	if written == 0 {
		return trace.NotFound("recording for %v is not found", sessionID)
	}
	return nil
}

func (l *Handler) Upload(ctx context.Context, sessionID session.ID, reader io.Reader) (string, error) {
	path := string(sessionID) + ".tar"
	_, err := l.uploader.UploadWithContext(ctx, &s3manager.UploadInput{
		Bucket: aws.String(l.Bucket),
		Key:    aws.String(path),
		Body:   reader,
	})
	if err != nil {
		return "", ConvertS3Error(err)
	}
	return fmt.Sprintf("s3://%v/%v", l.Bucket, path), nil
}

// ConvertS3Error wraps S3 error
func ConvertS3Error(err error, args ...interface{}) error {
	if err == nil {
		return nil
	}
	if aerr, ok := err.(awserr.Error); ok {
		switch aerr.Code() {
		case s3.ErrCodeNoSuchKey, s3.ErrCodeNoSuchBucket, s3.ErrCodeNoSuchUpload:
			return trace.NotFound(aerr.Error(), args...)
		case s3.ErrCodeBucketAlreadyExists, s3.ErrCodeBucketAlreadyOwnedByYou:
			return trace.AlreadyExists(aerr.Error(), args...)
		default:
			return trace.BadParameter(aerr.Error(), args...)
		}
	}
	return err
}
