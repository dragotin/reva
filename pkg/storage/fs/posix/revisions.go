// Copyright 2023 ownCloud GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package posix

import (
	"context"
	"io"

	provider "github.com/cs3org/go-cs3apis/cs3/storage/provider/v1beta1"
	"github.com/cs3org/reva/v2/pkg/errtypes"
)

func (fs *posixfs) ListRevisions(ctx context.Context, ref *provider.Reference) (revisions []*provider.FileVersion, err error) {
	return nil, errtypes.NotSupported("ListRevisions")
}

func (fs *posixfs) DownloadRevision(ctx context.Context, ref *provider.Reference, revisionKey string) (io.ReadCloser, error) {
	return nil, errtypes.NotSupported("DownloadRevision")
}

func (fs *posixfs) RestoreRevision(ctx context.Context, ref *provider.Reference, revisionKey string) (err error) {
	return errtypes.NotSupported("RestoreRevision")
}
