#find -type f -exec md5sum '{}' \;

#grep -Fwf ioc sum.txt


output=/home/'CHANGE ME'/hashcheckV2/overall_server/md5/Output/md5_"$HOSTNAME"_output.txt
ioc=/home/'CHANGE ME'/hashcheckV2/overall_server/md5/ioc
result=/home/'CHANGE ME'/hashcheckV2/overall_server/md5/Results/md5_"$HOSTNAME"_result.txt
DATE=`date "+%d%m%Y_%H%M_%S"`
IMDA="IOC-2022-13"

# Generate out all md5 hash from /tmp and /usr save as $output

date >> $output
hostname -i >> $output
hostname >> $output
echo "directory hash value in this server showing below :" >> $output
echo "-----------------------------------" >> $output
find /tmp /etc /usr /apps -type f -exec md5sum '{}' \; >> $output
