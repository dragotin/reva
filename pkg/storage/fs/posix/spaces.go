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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	userv1beta1 "github.com/cs3org/go-cs3apis/cs3/identity/user/v1beta1"
	provider "github.com/cs3org/go-cs3apis/cs3/storage/provider/v1beta1"
	types "github.com/cs3org/go-cs3apis/cs3/types/v1beta1"
	"github.com/cs3org/reva/v2/pkg/errtypes"
	"github.com/cs3org/reva/v2/pkg/storagespace"
	"github.com/pkg/errors"
	"github.com/pkg/xattr"

	v1beta11 "github.com/cs3org/go-cs3apis/cs3/rpc/v1beta1"
	ocsconv "github.com/cs3org/reva/v2/pkg/conversions"
	"github.com/cs3org/reva/v2/pkg/logger"
	"github.com/cs3org/reva/v2/pkg/storage/utils/decomposedfs/metadata/prefixes"
	"github.com/cs3org/reva/v2/pkg/utils"
	"github.com/google/uuid"
)

const (
	_spaceTypePersonal = "personal"
	_spaceTypeProject  = "project"
	spaceTypeShare     = "share"
	spaceTypeAny       = "*"
	spaceIDAny         = "*"
	_personalSpaceRoot = "users"
	_projectSpaceRoot  = "projects"

	quotaUnrestricted = 0
)

func (fs *posixfs) storageSpaceFromNode(ctx context.Context, n *Node, checkPermissions bool) (*provider.StorageSpace, error) {
	// user := ctxpkg.ContextMustGetUser(ctx)
	var err error

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

	var sname, stype string

	// get the space name
	if name, lerr := xattr.Get(n.InternalPath(), prefixes.SpaceNameAttr); lerr != nil {
		sname = string("unknown")
	} else {
		sname = string(name)
	}

	// space type string
	if mytype, lerr := xattr.Get(n.InternalPath(), prefixes.SpaceTypeAttr); lerr != nil {
		stype = string("unknown")
	} else {
		stype = string(mytype)
	}

	grantMapJSON := []byte("{}")
	grantExpirationMapJSON := []byte("{}")
	groupMapJSON := []byte("{}")

	space := &provider.StorageSpace{
		Opaque: &types.Opaque{
			Map: map[string]*types.OpaqueEntry{
				"spaceAlias": {
					Decoder: "plain",
					Value:   []byte(fmt.Sprintf("%s/%s", stype, sname)),
				},
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
		Name:  sname,
		Owner: &userv1beta1.User{Id: n.Owner()},

		// SpaceType is read from xattr below
		// Mtime is set either as node.tmtime or as fi.mtime below
	}
	// we set the space mtime to the root item mtime
	// override the stat mtime with a tmtime if it is present
	var tmtime time.Time
	if tmt, err := n.GetTMTime(); err == nil {
		tmtime = tmt
		un := tmt.UnixNano()
		space.Mtime = &types.Timestamp{
			Seconds: uint64(un / 1000000000),
			Nanos:   uint32(un % 1000000000),
		}
	} else if fi, err := os.Stat(n.InternalPath()); err == nil {
		// fall back to stat mtime
		tmtime = fi.ModTime()
		un := fi.ModTime().UnixNano()
		space.Mtime = &types.Timestamp{
			Seconds: uint64(un / 1000000000),
			Nanos:   uint32(un % 1000000000),
		}
	}

	etag, err := n.CalculateEtag(tmtime)
	if err != nil {
		return nil, err
	}
	space.Opaque.Map["etag"] = &types.OpaqueEntry{
		Decoder: "plain",
		Value:   []byte(etag),
	}

	space.Quota = &provider.Quota{
		QuotaMaxBytes: quotaUnrestricted,
		QuotaMaxFiles: quotaUnrestricted, // TODO MaxUInt64? = unlimited? why even max files? 0 = unlimited?
	}

	var total uint64 = 0
	var used uint64 = 0
	var remaining uint64 = 0

	space.Opaque = utils.AppendPlainToOpaque(space.Opaque, "quota.total", strconv.FormatUint(total, 10))
	space.Opaque = utils.AppendPlainToOpaque(space.Opaque, "quota.used", strconv.FormatUint(used, 10))
	space.Opaque = utils.AppendPlainToOpaque(space.Opaque, "quota.remaining", strconv.FormatUint(remaining, 10))

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

	// Home node considers the user template
	// spaceRoot, err := fs.lu.HomeNode(ctx)
	// spaceRoot.SpaceID = spaceID
	// spaceRoot.id = spaceID

	// if err != nil {
	//	return nil, err
	// }

	spaceRoot := &Node{lu: fs.lu, SpaceID: spaceID, owner: owner.GetId(), Dir: _personalSpaceRoot, Name: "einstein"}

	spaceRoot.SpaceRoot = &Node{lu: fs.lu, SpaceID: spaceID, owner: owner.GetId(), Dir: _personalSpaceRoot, Name: "einstein"}

	// if the root dir exists, it can be assumed that the space already exists
	if _, err := os.Stat(spaceRoot.InternalPath()); os.IsNotExist(err) {
		if err = os.MkdirAll(spaceRoot.InternalPath(), 0700); err != nil {
			return nil, errors.Wrap(err, "posixfs: error creating node")
		}

		var ino uint64
		// get the inode
		ino, err := fs.GetInodeByPath(ctx, spaceRoot.InternalPath())
		if (err != nil) || (ino == 0) {
			return nil, errors.Wrap(err, "posixfs: error getting inode")
		}

		metadata := make(map[string][]byte)
		metadata[ownerIDAttr] = []byte(owner.Id.OpaqueId)
		metadata[ownerIDPAttr] = []byte(owner.Id.Idp)

		spaceRoot.id = fmt.Sprintf("%d:%s", ino, spaceID)
		// try to store it
		metadata[idAttr] = []byte(spaceRoot.id)
		metadata[spaceIdAttr] = []byte(spaceRoot.id)

		/*
			ownerType := req.GetOwner().Id.GetType()
			ownerIdp := req.GetOwner().Id.GetIdp()
			if req.GetOwner() != nil && owner != nil {
				// root.SetOwner(req.GetOwner().GetId())
			} else {
				// root.SetOwner(&userv1beta1.UserId{OpaqueId: spaceID, Type: userv1beta1.UserType_USER_TYPE_SPACE_OWNER})
			}
		*/
		metadata[ownerTypeAttr] = []byte(utils.UserTypeToString(owner.GetId().Type))
		// always mark the space root node as the end of propagation
		metadata[prefixes.PropagationAttr] = []byte("1")
		metadata[nameAttr] = []byte(owner.Username)
		metadata[prefixes.SpaceNameAttr] = []byte(owner.Username)
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
	if (err != nil) || (space == nil) {
		return nil, err
	}

	space.SpaceType = req.Type
	var mdKeys []string

	rp, err := fs.p.AssemblePermissions(ctx, spaceRoot)
	switch {
	case err != nil:
		return nil, err

	}

	space.RootInfo, err = spaceRoot.AsResourceInfo(ctx, rp, mdKeys)
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
	var (
		spaceID       = spaceIDAny
		nodeID        = spaceIDAny
		requestedUser *userv1beta1.UserId
	)

	log := logger.New()
	spaceTypes := map[string]struct{}{}

	for i := range filter {
		switch filter[i].Type {
		case provider.ListStorageSpacesRequest_Filter_TYPE_SPACE_TYPE:
			switch filter[i].GetSpaceType() {
			case "+mountpoint":
				// TODO include mount poits
			case "+grant":
				// TODO include grants
			default:
				spaceTypes[filter[i].GetSpaceType()] = struct{}{}
			}
		case provider.ListStorageSpacesRequest_Filter_TYPE_ID:
			_, spaceID, nodeID, _ = storagespace.SplitID(filter[i].GetId().OpaqueId)
			if strings.Contains(nodeID, "/") {
				return []*provider.StorageSpace{}, nil
			}
		case provider.ListStorageSpacesRequest_Filter_TYPE_USER:
			// TODO: refactor this to GetUserId() in cs3
			requestedUser = filter[i].GetUser()
		case provider.ListStorageSpacesRequest_Filter_TYPE_OWNER:
			// TODO: improve further by not evaluating shares
			requestedUser = filter[i].GetOwner()
		}
	}
	if len(spaceTypes) == 0 {
		spaceTypes[spaceTypeAny] = struct{}{}
	}

	log.Debug().Str("RequestedUserID", requestedUser.GetOpaqueId()).Msg("ListStorageSpaces")
	// authenticatedUserID := ctxpkg.ContextMustGetUser(ctx).GetId().GetOpaqueId()

	// Checks for permissions to list spaces of other users
	// if !fs.p.ListSpacesOfUser(ctx, requestedUserID) {
	//	return nil, errtypes.PermissionDenied(fmt.Sprintf("user %s is not allowed to list spaces of other users", authenticatedUserID))
	// }

	// checkNodePermissions := fs.MustCheckNodePermissions(ctx, unrestricted)

	spaces := []*provider.StorageSpace{}

	if spaceID != spaceIDAny && nodeID != spaceIDAny {
		// try directly reading the node
		n, err := ReadNode(ctx, fs.lu, spaceID, nodeID, nil) // permission to read disabled space is checked later
		if err != nil {
			log.Error().Err(err).Str("id", nodeID).Msg("could not read node")
			return nil, err
		}
		if !n.Exists {
			// return empty list
			return spaces, nil
		}
		space, err := fs.storageSpaceFromNode(ctx, n, true)
		if err != nil {
			return nil, err
		}
		// filter space types
		_, ok1 := spaceTypes[spaceTypeAny]
		_, ok2 := spaceTypes[space.SpaceType]
		if ok1 || ok2 {
			spaces = append(spaces, space)
		}
		// TODO: filter user id
		return spaces, nil
	}

	if requestedUser != nil {
		if _, ok := spaceTypes[spaceTypeAny]; ok {
			// TODO do not hardcode dirs
			spaceTypes = map[string]struct{}{
				"personal": {},
				"project":  {},
				"share":    {},
			}
		}

		if _, ok := spaceTypes[_spaceTypePersonal]; ok {
			persDir := filepath.Join(fs.lu.Options.Root, _personalSpaceRoot)
			entries, err := os.ReadDir(persDir)

			if err != nil {
				log.Error().Err(err).Str("dir", persDir).Msg("could not read dir")
			}

			for _, e := range entries {
				fileSpaceId, err2 := xattr.Get(filepath.Join(persDir, e.Name()), spaceIdAttr)
				if err2 != nil {
					log.Error().Err(err).Str("dir", persDir).Msg("could not read dir")
				} else {
					// split id which consists of <inode>:<uuid>
					var spaceRoot *Node
					if spaceRoot, err = ReadSpaceNode(ctx, fs.lu, string(fileSpaceId)); err != nil {
						return nil, err
					}
					spaceRoot.owner = requestedUser
					spaceRoot.SpaceRoot.owner = requestedUser

					space, err := fs.storageSpaceFromNode(ctx, spaceRoot, false)
					if err != nil {
						return nil, err
					}
					space.SpaceType = _spaceTypePersonal

					spaces = append(spaces, space)
					break
				}
			}
		}

	}

	return spaces, nil
}

func (fs *posixfs) UpdateStorageSpace(ctx context.Context, req *provider.UpdateStorageSpaceRequest) (*provider.UpdateStorageSpaceResponse, error) {
	return nil, errtypes.NotSupported("posixfs: not implemented UpdateStorageSpaces")
}
