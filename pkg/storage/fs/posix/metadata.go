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
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	provider "github.com/cs3org/go-cs3apis/cs3/storage/provider/v1beta1"
	"github.com/cs3org/reva/v2/pkg/appctx"
	ctxpkg "github.com/cs3org/reva/v2/pkg/ctx"
	"github.com/cs3org/reva/v2/pkg/errtypes"

	"github.com/pkg/errors"
	"github.com/pkg/xattr"
)

func parseMTime(v string) (t time.Time, err error) {
	p := strings.SplitN(v, ".", 2)
	var sec, nsec int64
	if sec, err = strconv.ParseInt(p[0], 10, 64); err == nil {
		if len(p) > 1 {
			nsec, err = strconv.ParseInt(p[1], 10, 64)
		}
	}
	return time.Unix(sec, nsec), err
}

func (fs *posixfs) SetArbitraryMetadata(ctx context.Context, ref *provider.Reference, md *provider.ArbitraryMetadata) (err error) {
	n, err := fs.lu.NodeFromResource(ctx, ref)
	if err != nil {
		return errors.Wrap(err, "posixfs: error resolving ref")
	}
	sublog := appctx.GetLogger(ctx).With().Interface("node", n).Logger()

	if !n.Exists {
		err = errtypes.NotFound(filepath.Join(n.Dir, n.Name))
		return err
	}

	ok, err := fs.p.HasPermission(ctx, n, func(rp *provider.ResourcePermissions) bool {
		// TODO add explicit SetArbitraryMetadata grant to CS3 api, tracked in https://github.com/cs3org/cs3apis/issues/91
		return rp.InitiateFileUpload
	})
	switch {
	case err != nil:
		return errtypes.InternalError(err.Error())
	case !ok:
		return errtypes.PermissionDenied(filepath.Join(n.Dir, n.Name))
	}

	nodePath := n.InternalPath()

	errs := []error{}
	// TODO should we really continue updating when an error occurs?
	if md.Metadata != nil {
		if val, ok := md.Metadata["mtime"]; ok {
			delete(md.Metadata, "mtime")
			err := n.SetMtime(ctx, val)
			if err != nil {
				errs = append(errs, errors.Wrap(err, "could not set mtime"))
			}
		}
		// TODO(jfd) special handling for atime?
		// TODO(jfd) allow setting birth time (btime)?
		// TODO(jfd) any other metadata that is interesting? fileid?
		// TODO unset when file is updated
		// TODO unset when folder is updated or add timestamp to etag?
		if val, ok := md.Metadata["etag"]; ok {
			delete(md.Metadata, "etag")
			err := n.SetEtag(ctx, val)
			if err != nil {
				errs = append(errs, errors.Wrap(err, "could not set etag"))
			}
		}
		if val, ok := md.Metadata[_favoriteKey]; ok {
			delete(md.Metadata, _favoriteKey)
			u := ctxpkg.ContextMustGetUser(ctx)

			if uid := u.GetId(); uid != nil {
				if err := n.SetFavorite(uid, val); err != nil {
					sublog.Error().Err(err).
						Interface("user", u).
						Msg("could not set favorite flag")
					errs = append(errs, errors.Wrap(err, "could not set favorite flag"))
				}
			} else {
				sublog.Error().Interface("user", u).Msg("user has no id")
				errs = append(errs, errors.Wrap(errtypes.UserRequired("userrequired"), "user has no id"))
			}
		}
	}
	for k, v := range md.Metadata {
		attrName := metadataPrefix + k
		if err = xattr.Set(nodePath, attrName, []byte(v)); err != nil {
			errs = append(errs, errors.Wrap(err, "posixfs: could not set metadata attribute "+attrName+" to "+k))
		}
	}

	switch len(errs) {
	case 0:
		return fs.tp.Propagate(ctx, n)
	case 1:
		// TODO Propagate if anything changed
		return errs[0]
	default:
		// TODO Propagate if anything changed
		// TODO how to return multiple errors?
		return errors.New("multiple errors occurred, see log for details")
	}
}

func (fs *posixfs) UnsetArbitraryMetadata(ctx context.Context, ref *provider.Reference, keys []string) (err error) {
	n, err := fs.lu.NodeFromResource(ctx, ref)
	if err != nil {
		return errors.Wrap(err, "posixfs: error resolving ref")
	}
	sublog := appctx.GetLogger(ctx).With().Interface("node", n).Logger()

	if !n.Exists {
		err = errtypes.NotFound(filepath.Join(n.Dir, n.Name))
		return err
	}

	ok, err := fs.p.HasPermission(ctx, n, func(rp *provider.ResourcePermissions) bool {
		// TODO use SetArbitraryMetadata grant to CS3 api, tracked in https://github.com/cs3org/cs3apis/issues/91
		return rp.InitiateFileUpload
	})
	switch {
	case err != nil:
		return errtypes.InternalError(err.Error())
	case !ok:
		return errtypes.PermissionDenied(filepath.Join(n.Dir, n.Name))
	}

	nodePath := n.InternalPath()
	errs := []error{}
	for _, k := range keys {
		switch k {
		case _favoriteKey:
			u := ctxpkg.ContextMustGetUser(ctx) // FIXME: Previous impl. has added to errs while this panics

			// the favorite flag is specific to the user, so we need to incorporate the userid
			if uid := u.GetId(); uid != nil {
				fa := fmt.Sprintf("%s%s@%s", favPrefix, uid.GetOpaqueId(), uid.GetIdp())
				if err := xattr.Remove(nodePath, fa); err != nil {
					sublog.Error().Err(err).
						Interface("user", u).
						Str("key", fa).
						Msg("could not unset favorite flag")
					errs = append(errs, errors.Wrap(err, "could not unset favorite flag"))
				}
			} else {
				sublog.Error().
					Interface("user", u).
					Msg("user has no id")
				errs = append(errs, errors.Wrap(errtypes.UserRequired("userrequired"), "user has no id"))
			}

		default:
			if err = xattr.Remove(nodePath, metadataPrefix+k); err != nil {
				// a non-existing attribute will return an error, which we can ignore
				// (using string compare because the error type is syscall.Errno and not wrapped/recognizable)
				if e, ok := err.(*xattr.Error); !ok || !(e.Err.Error() == "no data available" ||
					// darwin
					e.Err.Error() == "attribute not found") {
					sublog.Error().Err(err).
						Str("key", k).
						Msg("could not unset metadata")
					errs = append(errs, errors.Wrap(err, "could not unset metadata"))
				}
			}
		}
	}
	switch len(errs) {
	case 0:
		return fs.tp.Propagate(ctx, n)
	case 1:
		// TODO Propagate if anything changed
		return errs[0]
	default:
		// TODO Propagate if anything changed
		// TODO how to return multiple errors?
		return errors.New("multiple errors occurred, see log for details")
	}
}
