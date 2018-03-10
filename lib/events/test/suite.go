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

package test

import (
	"bytes"
	"context"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/fixtures"
	"github.com/gravitational/teleport/lib/session"

	"gopkg.in/check.v1"
)

func TestFile(t *testing.T) { check.TestingT(t) }

type HandlerSuite struct {
	Handler events.UploadHandler
}

func (s *HandlerSuite) UploadDownload(c *check.C) {
	val := "hello, how is it going? this is the uploaded file"
	id := session.NewID()
	_, err := s.Handler.Upload(context.TODO(), id, bytes.NewBuffer([]byte(val)))
	c.Assert(err, check.IsNil)

	dir := c.MkDir()
	f, err := os.Create(filepath.Join(dir, string(id)))
	c.Assert(err, check.IsNil)
	defer f.Close()

	err = s.Handler.Download(context.TODO(), id, f)
	c.Assert(err, check.IsNil)

	_, err = f.Seek(0, 0)
	c.Assert(err, check.IsNil)

	data, err := ioutil.ReadAll(f)
	c.Assert(err, check.IsNil)
	c.Assert(string(data), check.Equals, val)
}

func (s *HandlerSuite) DownloadNotFound(c *check.C) {
	id := session.NewID()

	dir := c.MkDir()
	f, err := os.Create(filepath.Join(dir, string(id)))
	c.Assert(err, check.IsNil)
	defer f.Close()

	err = s.Handler.Download(context.TODO(), id, f)
	fixtures.ExpectNotFound(c, err)
}
