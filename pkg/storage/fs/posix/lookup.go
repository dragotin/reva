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
	"strings"

	provider "github.com/cs3org/go-cs3apis/cs3/storage/provider/v1beta1"
	"github.com/cs3org/reva/v2/pkg/appctx"
	ctxpkg "github.com/cs3org/reva/v2/pkg/ctx"
	"github.com/cs3org/reva/v2/pkg/errtypes"
	"github.com/cs3org/reva/v2/pkg/storage/utils/templates"
)

// Lookup implements transformations from filepath to node and back
type Lookup struct {
	Options *Options
}

// NodeFromResource takes in a request path or request id and converts it to a Node
func (lu *Lookup) NodeFromResource(ctx context.Context, ref *provider.Reference) (*Node, error) {

	if ref.ResourceId != nil {
		// check if a storage space reference is used
		// currently, the decomposed fs uses the root node id as the space id
		n, err := lu.NodeFromID(ctx, ref.ResourceId)
		if err != nil {
			return nil, err
		}
		// is this a relative reference?
		if ref.Path != "" {
			p := filepath.Clean(ref.Path)
			if p != "." && p != "/" {
				// walk the relative path
				n, err = lu.WalkPath(ctx, n, p, func(ctx context.Context, n *Node) error { return nil })
				if err != nil {
					return nil, err
				}
				n.SpaceID = ref.ResourceId.SpaceId
			}
		}
		return n, nil
	}

	// reference is invalid
	return nil, fmt.Errorf("invalid reference %+v. resource_id must be set", ref)

}

// NodeFromID returns the internal path for the id
func (lu *Lookup) NodeFromID(ctx context.Context, id *provider.ResourceId) (n *Node, err error) {
	if id == nil {
		return nil, fmt.Errorf("invalid resource id %+v", id)
	}
	if id.OpaqueId == "" {
		// The Resource references the root of a space
		return lu.NodeFromSpaceID(ctx, id.SpaceId)
	}
	return ReadNode(ctx, lu, id.SpaceId, id.OpaqueId, nil)
}

// NodeFromSpaceID converts a resource id into a Node
func (lu *Lookup) NodeFromSpaceID(ctx context.Context, spaceID string) (n *Node, err error) {
	node, err := ReadNode(ctx, lu, spaceID, spaceID, nil)
	if err != nil {
		return nil, err
	}

	node.SpaceRoot = node
	return node, nil
}

// Path returns the relative external path for node
func (lu *Lookup) Path(ctx context.Context, n *Node) (p string, err error) {
	var root *Node
	if root, err = lu.HomeOrRootNode(ctx); err != nil {
		return
	}
	for n.ID() != root.ID() {
		p = filepath.Join(n.Name, p)
		if n, err = n.Parent(); err != nil {
			appctx.GetLogger(ctx).
				Error().Err(err).
				Str("path", p).
				Interface("node", n).
				Msg("Path()")
			return
		}
	}
	return
}

// RootNode returns the root node of the storage
func (lu *Lookup) RootNode(ctx context.Context) (node *Node, err error) {
	return &Node{
		lu:     lu,
		id:     "root",
		Dir:    "",
		Name:   "",
		Exists: true,
	}, nil
}

// HomeNode returns the home node of a user
func (lu *Lookup) HomeNode(ctx context.Context) (node *Node, err error) {
	if !lu.Options.EnableHome {
		return nil, errtypes.NotSupported("posixfs: home supported disabled")
	}

	if node, err = lu.RootNode(ctx); err != nil {
		return
	}
	lum := lu.mustGetUserLayout(ctx)
	node, err = lu.WalkPath(ctx, node, lum, nil)
	return
}

// WalkPath calls n.Child(segment) on every path segment in p starting at the node r
// If a function f is given it will be executed for every segment node, but not the root node r
func (lu *Lookup) WalkPath(ctx context.Context, r *Node, p string, f func(ctx context.Context, n *Node) error) (*Node, error) {
	segments := strings.Split(strings.Trim(p, "/"), "/")
	var err error
	for i := range segments {
		if r, err = r.Child(segments[i]); err != nil {
			return r, err
		}
		// if an intermediate node is missing return not found
		if !r.Exists && i < len(segments)-1 {
			return r, errtypes.NotFound(segments[i])
		}
		if f != nil {
			if err = f(ctx, r); err != nil {
				return r, err
			}
		}
	}
	return r, nil
}

// HomeOrRootNode returns the users home node when home support is enabled.
// it returns the storages root node otherwise
func (lu *Lookup) HomeOrRootNode(ctx context.Context) (node *Node, err error) {
	if lu.Options.EnableHome {
		return lu.HomeNode(ctx)
	}
	return lu.RootNode(ctx)
}

func (lu *Lookup) mustGetUserLayout(ctx context.Context) string {
	u := ctxpkg.ContextMustGetUser(ctx)
	return templates.WithUser(u, lu.Options.UserLayout)
}

// TODO move to node?
//func (lu *Lookup) toInternalPath(id string) string {
//	return filepath.Join(lu.Options.Root, "nodes", id)
//}
