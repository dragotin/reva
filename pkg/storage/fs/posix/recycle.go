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

	provider "github.com/cs3org/go-cs3apis/cs3/storage/provider/v1beta1"
	"github.com/cs3org/reva/v2/pkg/errtypes"
)

func (fs *posixfs) ListRecycle(ctx context.Context, ref *provider.Reference, key, relativePath string) (items []*provider.RecycleItem, err error) {
	return nil, errtypes.NotSupported("ListRecycle")
}

func (fs *posixfs) RestoreRecycleItem(ctx context.Context, ref *provider.Reference, key, relativePath string, restoreRef *provider.Reference) (err error) {
	return errtypes.NotSupported("RestoreRecycleItem")

}

func (fs *posixfs) PurgeRecycleItem(ctx context.Context, ref *provider.Reference, key, relativePath string) (err error) {
	return errtypes.NotSupported("PurgeRecycleItem")
}

func (fs *posixfs) EmptyRecycle(ctx context.Context, ref *provider.Reference) error {
	return errtypes.NotSupported("EmptyRecycle")
}
