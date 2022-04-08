#To check if any new hash from Alienvault and sync new hash to file

function check_sync {

IOCFILE=/root/alienv/iocs/otx-hash-iocs.txt
IOCFILE2=/root/alienv/iocs/otx-hash-iocs2.txt
IOCFILE3=/home/'CHANGE_ME'/Alienvault_hash/Alienvault_hash_raw.ioc
IOCFILE4=/home/'CHANGE_ME'/Alienvault_hash/Malicious_topic.txt
LOGFILE=/home/'CHANGE_ME'/Alienvault_hash/alien_sync.log
SYNC=$(awk 'FNR==NR {a[$0]++; next} !($0 in a)' $IOCFILE2 $IOCFILE)

echo " " >> $LOGFILE

# Command return string
if [[ -n $SYNC ]]
 then
   echo "Yes update"
   echo $(date) ------------------------------ >> $IOCFILE3
   echo $(date) >> $IOCFILE4
   awk 'FNR==NR {a[$0]++; next} !($0 in a)' $IOCFILE2 $IOCFILE | awk  -F "'" '{print$2}' | uniq >> $IOCFILE4
   echo "$(date) [INFO] Printing Unique IOC title from otc-hash-ioc2.txt to Malicious_topic.txt" >> $LOGFILE
   awk 'FNR==NR {a[$0]++; next} !($0 in a)' $IOCFILE2 $IOCFILE >> $IOCFILE3
   echo "$(date) [INFO] Syncing complete from otc-hash-iocs2.txt to Alienvault_hash_raw.ioc" >> $LOGFILE
   echo "----------------------------------------" >> $IOCFILE4
   awk 'FNR==NR {a[$0]++; next} !($0 in a)' $IOCFILE2 $IOCFILE >> $IOCFILE2
#   cat $IOCFILE3 >> $IOCFILE2
   echo "Weekly sync is done.Please go to /home/tpgvapt1/Alienvault_hash path to check the latest hash from Alienvault. "alien_sync.log" for more details."| mail -s "Alientvault hash update completed" jiale.sim@tpgtelecom.com.sg daren.lee@tpgtelecom.com.sg jack.lai@tpgtelecom.com.sg
   echo "$(date) [INFO] Sent weekly reminde email to jiale.sim , daren.lee and jack.lai" >> $LOGFILE
   mkdir /home/'CHANGE_ME'/Alienvault_hash/Done/$(date +\%d-\%m-\%y_\%H\%M)

else
  echo $(date)  ------------------------------- >> $IOCFILE3
  echo "NO NEW UPDATE" >> $IOCFILE3
  echo "No new update is available." | mail -s "Alienvault hash no update this week" 'CHANGE_ME'@gmail.com # change to your email or company email 
  echo "$(date) [ALERT] Error Occured OR No new data to feed." >> $LOGFILE
  echo $(date)  ------------------------------- >> $IOCFILE4
  echo "NO NEW UPDATE" >> $IOCFILE4
fi



}




#Categorised various type of malicious hash to corresponding file

function hash_1 {

MD5=$(cat $IOCFILE3 | awk -F";" '{print $1}' | awk 'length($0) == 32')
SHA1=$(cat $IOCFILE3 | awk -F";" '{print $1}' | awk 'length($0) == 40')
SHA256=$(cat $IOCFILE3 | awk -F";" '{print $1}'| awk 'length($0) == 64')
DATE=$(date "+%d%m%Y_%H%M")

if [ -e "$IOCFILE3" ]
then

# MD5 OR MD4 , 32 length , 128 bits
# SHA1 , 40 length , 160 bits
# SHA256 , 64 length , 256 bits

echo "$MD5" > /home/'CHANGE_ME'/Alienvault_hash/alienvault_ioc/"$DATE"_alienv_md5.ioc
echo "$SHA1" > /home/'CHANGE_ME'/Alienvault_hash/alienvault_ioc/"$DATE"_alienv_sha1.ioc
echo "$SHA256" > /home/'CHANGE_ME'/Alienvault_hash/alienvault_ioc/"$DATE"_alienv_sha256.ioc

else
 echo "$(date) [ALERT] Unable to proceed due to no Alienvault main raw file." >> $LOGFILE
fi


}




# Find out if Alient vault hash exist in weekly hash integration routine and alert SOC by email.

function hash_2 {

FINDMD5=$(find /home/'CHANGE_ME'/Alienvault_hash/alienvault_ioc -type f -name "*md5*")
FINDSHA256=$(find /home/'CHANGE_ME'/Alienvault_hash/alienvault_ioc -type f -name "*sha256*")
FINDSHA1=$(find /home/'CHANGE_ME'/Alienvault_hash/alienvault_ioc -type f -name "*sha1*")
result=/home/'CHANGE_ME'/Alienvault_hash/alienvault_ioc/result_hash.ioc
OUTPUTMD5=/home/'CHANGE_ME'/hashcheckV2/overall_server/md5/Output/*
OUTPUTSHA1=/home/'CHANGE_ME'/hashcheckV2/overall_server/sha1/Output/*
OUTPUTSHA256=/home/'CHANGE_ME'/hashcheckV2/overall_server/sha256/Output/*


if [ -n "$FINDMD5" ]
then
  # COMPARE all file hash if match then put it at $result
  date >> $result
  echo $FINDMD5 >> $result
  echo "Match found result show below (if any) :" >> $result
  awk 'FNR==NR{a[$1];next}($1 in a){print}' $FINDMD5 $OUTPUTMD5 >> $result
  outputmd5result=$(awk 'FNR==NR{a[$1];next}($1 in a){print}' $FINDMD5 $OUTPUTMD5)
  echo " " >> $result
     if [ -n "$outputmd5result" ]  # the result string is not null and return result
     then
        echo "$(date) [ALERT] 'MD5' compare found something please check!" >> $LOGFILE
        echo "Process Done" | mail -s "Potential malicious MD5 found - Alienvault" 'CHANGE_ME'.gmail.com # change to your email or company email

     else
        echo "$(date) [INFO] Completed compare all 'MD5' hashes on all server" >> $LOGFILE
     fi
else
   echo "$(date) [ALERT] No update OR Unable categorised 'MD5' and compare hashes on all server. Please check" >>  $LOGFILE
fi




if [ -n "$FINDSHA256" ]
then
  echo $FINDSHA256 >> $result
  echo "Match found result show below (if any) :" >> $result
  awk 'FNR==NR{a[$1];next}($1 in a){print}' $FINDSHA256 $OUTPUTSHA256 >> $result
  outputsha256result=$(awk 'FNR==NR{a[$1];next}($1 in a){print}' $FINDSHA256 $OUTPUTSHA256)
  echo " " >> $result
    if [ -n "$outputsha256result" ]
    then
       echo "$(date) [ALERT] 'SHA256' compare found something please check!" >> $LOGFILE
       echo "Process Done" | mail -s "Potential malicious SHA256 found - Alienvault" 'CHANGE_ME'.gmail.com # change to your email or company email

    else
       echo "$(date) [INFO] Completed compare all 'SHA256' hashes on all server" >> $LOGFILE
    fi
else
  echo "$(date) [ALERT] No update OR Unable categorised 'SHA256' and compare hashes on all server. Please check" >> $LOGFILE

fi

if [ -n "$FINDSHA1" ]
then
  echo $FINDSHA1 >> $result
  echo "Match found result show below (if any) :" >> $result
  awk 'FNR==NR{a[$1];next}($1 in a){print}' $FINDSHA1 $OUTPUTSHA1 >> $result
  outputsha1result=$(awk 'FNR==NR{a[$1];next}($1 in a){print}' $FINDSHA1 $OUTPUTSHA1)
  echo " " >> $result

  echo "--------------------------------------------" >> $result
    if [ -n "$outputsha1result" ]
    then
       echo "$(date) [ALERT] 'SHA1' compare found something please check!" >> $LOGFILE
       echo "Process Done" | mail -s "Potential malicious SHA1 found - Alienvault" 'CHANGE_ME'.gmail.com # change to your email or company email
    else
        echo "$(date) [INFO] Completed compare all 'SHA1' hashes on all server" >> $LOGFILE
    fi
else
  echo "$(date) [ALERT] No update OR Unable categorised 'SHA1' and compare hashes on all server. Please check" >> $LOGFILE

fi


cp $result /home/'CHANGE_ME'/Alienvault_hash/Done//$(date +\%d-\%m-\%y_\%H\%M)_result.ioc

}



#Delete the processed and completed all type hash file for future update

function delete_hash {

find /home/'CHANGE_ME'/Alienvault_hash/alienvault_ioc/ -mtime +5.5 -type f -name "*alienv*" -delete

echo "$(date) [INFO] All hash ioc file longer then 5.5 days deleted" >> $LOGFILE

}



check_sync
hash_1
delete_hash   # Delete old existing hash before run to avoid script crash
hash_2
