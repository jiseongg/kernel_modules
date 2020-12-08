
error () {
	echo >&2 "$@"
	exit 1
}

[ "$#" -eq 1 ] || \
 	error "error: file system name must be passed by an argument."

fs_name=$1

echo -e "\nSetting environment on ${fs_name}...\n"

new_dir=${PWD}/${fs_name}
diskfile=${new_dir}/diskfile
mount_dir=${new_dir}/${fs_name}_dir

mkdir ${new_dir}
dd if=/dev/zero of=${diskfile} bs=1024 count=200000
mkfs.${fs_name} ${diskfile}

echo -e "\nfile system made!\n"

loop_cnt=$(find /dev -name 'loop[0-9]*' | wc -l)
loop_dev="/dev/loop${loop_cnt}"
sudo bash -c 'losetup $0 $1' ${loop_dev} ${diskfile}

mkdir ${mount_dir}
sudo bash -c 'mount -t $0 $1 $2' ${fs_name} ${loop_dev} ${mount_dir}

echo -e "\nmount succeeded!\n"

