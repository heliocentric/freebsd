Branches
=============================
feature/fusefs-backport
----------------------
Backport of fusefs from HEAD to 9-STABLE branches.

feature/blocksize
------------------------
Consistant and logical device size support

feature/dhclient-tzcode
------------------------
Add support for dhcp options for timzeone tcode and pcodes


Branch Structure
================================
Each branch contains at minimum two branches, patch and origin. origin is the inital branch of the project, which never changes (and is used to synchronize changes to upstream freebsd). patch is the primary 
changes, applied relative to origin. There will also be sub-branches, following the same toplevel structure, for -STABLE and -RELEASE branches.

For example:
* feature/blocksize/origin -> master as of commit 9d2347ae
* feature/blocksize/patch -> primary codebase for feature/blocksize
* feature/blocksize/master -> blocksize mfc'd to master
* feature/blocksize/stable/9 -> blocksize mfc'd to 9-STABLE
* feature/blocksize/releng/9.2 -> blocksize mfc'd to 9.2-RELEASE

