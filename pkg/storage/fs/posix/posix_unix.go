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

//go:build !windows
// +build !windows

package posix

import (
	"context"
	"syscall"

	provider "github.com/cs3org/go-cs3apis/cs3/storage/provider/v1beta1"
)

func (fs *posixfs) GetQuota(ctx context.Context, ref *provider.Reference) (uint64, uint64, uint64, error) {
	node, err := fs.lu.HomeOrRootNode(ctx)
	if err != nil {
		return 0, 0, 0, err
	}

	stat := syscall.Statfs_t{}
	file := node.InternalPath()
	err = syscall.Statfs(file, &stat)
	if err != nil {
		return 0, 0, 0, err
	}
	total := stat.Blocks * uint64(stat.Bsize)                // Total data blocks in filesystem
	used := (stat.Blocks - stat.Bavail) * uint64(stat.Bsize) // Free blocks available to unprivileged user
	var have_no_idea_what_it_is uint64
	return total, used, have_no_idea_what_it_is, nil
}

func (fs *posixfs) GetInodeByPath(ctx context.Context, p string) (uint64, error) {
	stat := syscall.Stat_t{}
	err := syscall.Stat(p, &stat)
	if err != nil {
		return 0, err
	}
	return stat.Ino, nil
}

func (fs *posixfs) GetInode(ctx context.Context, ref *provider.Reference) (uint64, error) {
	node, err := fs.lu.NodeFromResource(ctx, ref)
	if err != nil {
		return 0, err
	}
	return fs.GetInodeByPath(ctx, node.InternalPath())
}
