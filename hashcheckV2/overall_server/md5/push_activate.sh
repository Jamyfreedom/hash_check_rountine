for HOST in $(cat ipaddr.txt);

do
sshpass -f "/home/'CHANGE ME'/passkey.txt" ssh -t 'CHANGE ME'@$HOST 'sudo -S /home/'CHANGE ME'/hashcheckV2/overall_server/md5/hashchecksum.sh'

done
