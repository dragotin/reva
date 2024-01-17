The posix storage driver is trying to make an existing posix compatible filesystem available in CS3.

It has to make several tradeoffs:
- While files and directories haven an inode that could be used to make lookups via `find /path/to/root -inum 123` this has several limitations
  - inodes are reused: when you delete a file and create a new file it might have the same inode
  - inodes nood to be cached to have a fast lookup.
    - depending on the number of files, this might not be an issue
    - lookups by fileid rely on this
  - the path could be used as the fileid. which would make shares path based - might be acceptible. _@butonic dropbox does this afair_

- there is no trash
  - we could try to support the freedesktop org trash spec

- there are no versions
  - we could use snapshots on filesystems that support it, similar to rsnapshots hourly, daily, weekly, monthly, yearly, read only backups
  - we could use rcs for individual files or git/svn/cvs for folders ... 

- probably more

## Storage Layouts and Ids

Every resource in the posix driver is supposed to have the following Ids in the xattrs:

user.posix.id: <Id> The resource Id of the space
user.posix.spaceid: <Id> The space Id of the resource

The <Id> consists of the inode and a UUID, delimited by a colon. 
Example: user.posix.id="184179045:4c510ada-c86b-4815-8820-42cdf82c3d51"




For space Roots, both ids are identical.
