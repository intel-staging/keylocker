LOCAL_CRYPTSETUP=./cryptsetup

echo ""
echo "####################################"
echo "# start of dm-crypt test for $1"
echo "####################################"
echo "# 1. file (container) creation "
echo "####################################"
echo ""
rm -f ./test
fallocate -l 16M ./test

echo "####################################"
echo "# 2. convert the file as encryptable (virtual) disk block "
echo "####################################"
echo ""
sudo $LOCAL_CRYPTSETUP --cipher=capi:xts-aes-aesni-plain -v -y \
luksFormat ./test
file ./test

echo "####################################"
echo "# 3. format the virtual disk block with ext4 "
echo "####################################"
echo ""
sudo $LOCAL_CRYPTSETUP luksOpen ./test volume1 -v
sudo mkfs.ext4 -j /dev/mapper/volume1

echo "####################################"
echo "# 3. mount the disk block "
echo "####################################"
echo ""
sudo mount /dev/mapper/volume1 ./mnt
df -h

echo "####################################"
echo "# 4. copying test file (this is test file)"
echo "####################################"
echo ""
echo "this is test file" > test_file
sudo mv test_file ./mnt/

echo "####################################"
echo "# 5. umount and close the block (as encrypted)"
echo "####################################"
echo ""
sudo umount ./mnt
sudo $LOCAL_CRYPTSETUP luksClose volume1 -v

echo "####################################"
echo "# 6. wait 5 sec and mount and cat the file"
echo "####################################"
echo ""
sudo $LOCAL_CRYPTSETUP luksOpen ./test volume1 -v
sudo mount /dev/mapper/volume1 ./mnt
sudo cat ./mnt/test_file
sudo umount ./mnt

echo "####################################"
echo "# 7. dump extra information"
echo "####################################"

sudo dmsetup table --showkeys /dev/mapper/volume1
sudo $LOCAL_CRYPTSETUP luksDump  --dump-master-key ./test -v
#rm -rf ./test

echo "####################################"
echo "# 8. switch to kl and dump"
echo "####################################"
sudo $LOCAL_CRYPTSETUP luksChangeCipher --cipher=capi:xts-aes-aeskl-plain ./test
sudo $LOCAL_CRYPTSETUP luksDump  --dump-master-key ./test -v

sudo mount /dev/mapper/volume1 ./mnt
sudo cat ./mnt/test_file
sudo umount ./mnt

echo "####################################"
echo "# end of test"
echo "####################################"
sudo $LOCAL_CRYPTSETUP luksClose volume1 -v
