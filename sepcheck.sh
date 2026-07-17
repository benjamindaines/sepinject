#!/bin/bash
import ROM_ROOT
findRoot() {
	local dir=$(pwd)

	while [[ "$dir" != "/" ]]; do
		dir=$(dirname "$dir")
		[[ -d "$dir"/super ]] && { \
			#echo "$dir"
			printf "%s" "$dir"/super/lp_images
			return 0
		}
	done
	return 1
}

[[ ! -d "super" ]] && { \
	ROM_ROOT=$(findRoot)
	export ROM_ROOT
} || \
	ROM_ROOT=super/lp_images

secilc -M true -G -N -c 30 "$ROM_ROOT/system/fs_tree/system/etc/selinux/plat_sepolicy.cil" "$ROM_ROOT/system_ext/fs_tree/etc/selinux/system_ext_sepolicy.cil" "$ROM_ROOT/vendor/fs_tree/etc/selinux/vendor_sepolicy.cil" "$ROM_ROOT/vendor/fs_tree/etc/selinux/plat_pub_versioned.cil" -o /tmp/check.bin || \

#secilc -M true -G -N -c 30 super/lp_images/system/fs_tree/system/etc/selinux/plat_sepolicy.cil super/lp_images/system_ext/fs_tree/etc/selinux/system_ext_sepolicy.cil super/lp_images/vendor/fs_tree/etc/selinux/vendor_sepolicy.cil super/lp_images/vendor/fs_tree/etc/selinux/plat_pub_versioned.cil -o /tmp/check.bin || \
	printf "\n\nsecilc failed for some reason.  Make sure you have it installed.  You may need to edit this file and adjust the paths to match your filesystem layout.  Also, the above error message could be informative.\n"

