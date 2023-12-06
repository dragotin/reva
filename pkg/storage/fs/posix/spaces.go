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
	"encoding/json"
	"os"
	"path/filepath"

	userv1beta1 "github.com/cs3org/go-cs3apis/cs3/identity/user/v1beta1"
	provider "github.com/cs3org/go-cs3apis/cs3/storage/provider/v1beta1"
	types "github.com/cs3org/go-cs3apis/cs3/types/v1beta1"
	"github.com/cs3org/reva/v2/pkg/errtypes"
	"github.com/cs3org/reva/v2/pkg/storagespace"

	v1beta11 "github.com/cs3org/go-cs3apis/cs3/rpc/v1beta1"
	ocsconv "github.com/cs3org/reva/v2/pkg/conversions"
	"github.com/cs3org/reva/v2/pkg/storage/utils/decomposedfs/metadata/prefixes"
	"github.com/cs3org/reva/v2/pkg/utils"
	"github.com/google/uuid"
)

func (fs *posixfs) storageSpaceFromNode(ctx context.Context, n *Node, checkPermissions bool) (*provider.StorageSpace, error) {
	// user := ctxpkg.ContextMustGetUser(ctx)
	ssID, err := storagespace.FormatReference(
		&provider.Reference{
			ResourceId: &provider.ResourceId{
				SpaceId:  n.SpaceRoot.SpaceID,
				OpaqueId: n.SpaceRoot.ID()},
		},
	)
	if err != nil {
		return nil, err
	}
	var sname string
	// if sname, err = n.SpaceRoot.XattrString(ctx, prefixes.SpaceNameAttr); err != nil {
	// FIXME: Is that a severe problem?
	// sublog.Debug().Err(err).Msg("space does not have a name attribute")
	// }

	grantMapJSON, err := json.Marshal("")
	grantExpirationMapJSON, err := json.Marshal("")
	groupMapJSON, err := json.Marshal("")

	space := &provider.StorageSpace{
		Opaque: &types.Opaque{
			Map: map[string]*types.OpaqueEntry{
				"grants": {
					Decoder: "json",
					Value:   grantMapJSON,
				},
				"grants_expirations": {
					Decoder: "json",
					Value:   grantExpirationMapJSON,
				},
				"groups": {
					Decoder: "json",
					Value:   groupMapJSON,
				},
			},
		},
		Id: &provider.StorageSpaceId{OpaqueId: ssID},
		Root: &provider.ResourceId{
			SpaceId:  n.SpaceRoot.SpaceID,
			OpaqueId: n.SpaceRoot.ID(),
		},
		Name: sname,
		// SpaceType is read from xattr below
		// Mtime is set either as node.tmtime or as fi.mtime below
	}

	return space, nil
}

// CreateStorageSpace is a copy from the decomposedFS, do not expect to work yet.
func (fs *posixfs) CreateStorageSpace(ctx context.Context, req *provider.CreateStorageSpaceRequest) (*provider.CreateStorageSpaceResponse, error) {
	ctx = context.WithValue(ctx, utils.SpaceGrant, struct{}{})

	// "everything is a resource" this is the unique ID for the Space resource.
	spaceID := uuid.New().String()
	// allow sending a space id
	if reqSpaceID := utils.ReadPlainFromOpaque(req.Opaque, "space_id"); reqSpaceID != "" {
		spaceID = reqSpaceID
	}
	// allow sending a space description
	description := utils.ReadPlainFromOpaque(req.Opaque, "description")

	// root, err := node.ReadNode(ctx, fs.lu, spaceID, spaceID, true, nil, false) // will fall into `Exists` case below
	// switch {
	// case err != nil:
	// 	return nil, err
	// case !fs.p.CreateSpace(ctx, spaceID):
	// 	return nil, errtypes.PermissionDenied(spaceID)
	// case root.Exists:
	// 	return nil, errtypes.AlreadyExists("Posixfs: spaces: space already exists")
	// }
	owner := req.GetOwner()
	oname := owner.GetUsername()

	// check and/or create a directory node
	rootDir := filepath.Join(fs.lu.Options.Root, req.Type, oname)
	relRootDir := filepath.Join(req.Type, oname)
	spaceRoot := &Node{lu: fs.lu, SpaceID: spaceID, owner: owner.GetId(), Dir: relRootDir, Name: "/"}

	spaceRoot.SpaceRoot = spaceRoot

	// if the root dir exists, it can be assumed that the space already exists
	if _, err := os.Stat(rootDir); os.IsNotExist(err) {

		// createNode creates the dir and writes some metadata.
		// maybe there should be more metadata added, ie. OwnerIDAttr and such
		if err := createNode(
			spaceRoot,
			&userv1beta1.UserId{
				OpaqueId: owner.GetId().GetOpaqueId(),
			},
		); err != nil {
			return nil, err
		}
	}

	// now the directory exists in any case. Read the node and return the space type.

	/*
		ownerType := req.GetOwner().Id.GetType()
		ownerIdp := req.GetOwner().Id.GetIdp()
		if req.GetOwner() != nil && owner != nil {
			// root.SetOwner(req.GetOwner().GetId())
		} else {
			// root.SetOwner(&userv1beta1.UserId{OpaqueId: spaceID, Type: userv1beta1.UserType_USER_TYPE_SPACE_OWNER})
		}
	*/
	metadata := make(map[string][]byte)
	metadata[prefixes.OwnerTypeAttr] = []byte(utils.UserTypeToString(owner.GetId().Type))
	// always mark the space root node as the end of propagation
	metadata[prefixes.PropagationAttr] = []byte("1")
	metadata[prefixes.NameAttr] = []byte(req.Name)
	metadata[prefixes.SpaceNameAttr] = []byte(req.Name)
	metadata[prefixes.TreesizeAttr] = []byte("0")

	if req.Type != "" {
		metadata[prefixes.SpaceTypeAttr] = []byte(req.Type)
	}

	if description != "" {
		metadata[prefixes.SpaceDescriptionAttr] = []byte(description)
	}

	if err := spaceRoot.writeMetadataMap(metadata); err != nil {
		return nil, err
	}

	// Write index
	// err = fs.updateIndexes(ctx, &provider.Grantee{
	// 	Type: provider.GranteeType_GRANTEE_TYPE_USER,
	// 	Id:   &provider.Grantee_UserId{UserId: req.GetOwner().GetId()},
	// }, req.Type, root.ID)
	// if err != nil {
	// 	return nil, err
	// }

	ctx = context.WithValue(ctx, utils.SpaceGrant, struct{ SpaceType string }{SpaceType: req.Type})
	if req.Type != _spaceTypePersonal {
		if err := fs.AddGrant(ctx, &provider.Reference{
			ResourceId: &provider.ResourceId{
				SpaceId:  spaceID,
				OpaqueId: spaceID,
			},
		}, &provider.Grant{
			Grantee: &provider.Grantee{
				Type: provider.GranteeType_GRANTEE_TYPE_USER,
				// Id: &provider.Grantee_UserId{
				//	UserId: u.Id,
				// },
			},
			Permissions: ocsconv.NewManagerRole().CS3ResourcePermissions(),
		}); err != nil {
			return nil, err
		}
	}
	space, err := fs.storageSpaceFromNode(ctx, spaceRoot, true)
	if err != nil {
		return nil, err
	}

	resp := &provider.CreateStorageSpaceResponse{
		Status: &v1beta11.Status{
			Code: v1beta11.Code_CODE_OK,
		},
		StorageSpace: space,
	}
	return resp, nil

}

func (fs *posixfs) DeleteStorageSpace(ctx context.Context, req *provider.DeleteStorageSpaceRequest) error {

	return errtypes.NotSupported("posixfs: not implemented DeleteStorageSpace")

}

// ListStorageSpaces returns a list of StorageSpaces.
// The list can be filtered by space type or space id.
// Spaces are persisted with symlinks in /spaces/<type>/<spaceid> pointing to ../../nodes/<nodeid>, the root node of the space
// The spaceid is a concatenation of storageid + "!" + nodeid
func (fs *posixfs) ListStorageSpaces(ctx context.Context, filter []*provider.ListStorageSpacesRequest_Filter, unrestricted bool) ([]*provider.StorageSpace, error) {
	// TODO check filters
	return nil, errtypes.NotSupported("posixfs: not implemented ListStorageSpaces")

}

func (fs *posixfs) UpdateStorageSpace(ctx context.Context, req *provider.UpdateStorageSpaceRequest) (*provider.UpdateStorageSpaceResponse, error) {
	return nil, errtypes.NotSupported("posixfs: not implemented UpdateStorageSpaces")
}
