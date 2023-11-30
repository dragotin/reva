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

//go:build windows
// +build windows

package posix

import (
	"context"

	"golang.org/x/sys/windows"
)

func (fs *posixfs) GetQuota(ctx context.Context) (uint64, uint64, error) {
	var free, total, avail uint64

	node, err := fs.lu.HomeOrRootNode(ctx)
	if err != nil {
		return 0, 0, err
	}

	pathPtr, err := windows.UTF16PtrFromString(node.InternalPath())
	if err != nil {
		return 0, 0, err
	}
	err = windows.GetDiskFreeSpaceEx(pathPtr, &avail, &total, &free)
	if err != nil {
		return 0, 0, err
	}

	used := total - free
	return total, used, nil
}
