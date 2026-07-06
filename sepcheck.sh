#!/bin/bash
secilc -M true -G -N -c 30 super/lp_images/system/fs_tree/system/etc/selinux/plat_sepolicy.cil super/lp_images/system_ext/fs_tree/etc/selinux/system_ext_sepolicy.cil super/lp_images/vendor/fs_tree/etc/selinux/vendor_sepolicy.cil super/lp_images/vendor/fs_tree/etc/selinux/plat_pub_versioned.cil -o /tmp/check.bin || \
	printf "\n\nsecilc failed for some reason.  Make sure you have it installed.  You may need to edit this file and adjust the paths to match your filesystem layout.  Also, the above error message could be informative.\n"

