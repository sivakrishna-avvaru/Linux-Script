#!/bin/bash -xv
################################################################################
#	Author   : Abhilash Dd Chaitanya and Ashutosh Mishra                        #
#	Email    : achaitan@in.ibm.com, ashmishn@in.ibm.com                         #
#	Reviewed and Modified : Ashutosh Mishra(ashmishn@in.ibm.com	        		#
#	Platform : Linux (RHEL-6/7,CentOS-6/7,OracleLinux-6/7)     					#
#	Script   : Shell script					                					#
#	Title    : Health check script for Linux                                	#	     
################################################################################

if [ -f hc_scan_parameter ]
then

rm -rf temp_shadow temp_shadow1 temp1_shadow temp_shadow2 temp-ud psw_temp temp_uid temp_uid1 temp_gid temp_gid1 pasd_temp p5 p4 p3 p2 p1 p6 p7 f1 t1 temp_pam.so file1 log_file1 log_file2 world-writable-test temp_id

clear
pause(){
  read -p "Press [Enter] key to continue..." fackEnterKey
}


z=`hostname`
fqdn=`hostname --fqdn`
ipAddress=`hostname -i` 
osName=`cat /etc/redhat-release `
c=`date | awk '{print $1"-"$2"-"$3"-"$6"-"$4}'`
timestamp=`date '+%m-%d-%Y-%H-%M-%S-%N'`

# please provide the below details while customising the Scan script.
#-------------------------------------------------------------------
accountName="Ford Motors"
accountID="NCC-V1N"
customisedDate="03-02-2021"
scanVersion="V1.1"
LinuxtechSpecVersion="Linux V7.2"
SSHtechSpecVersion="SSH v5.0"
SudotechSpecVersion="Sudo v6.0"
#-------------------------------------------------------------------

echo "FQDN" >>en1
echo "IP-ADDRESS" >>en2
echo "OS-NAME" >>en3
echo "TIMESTAMP" >> en4
echo "SECTION-HEADING" >>p1
echo "SYSTEM-VALUE/PARAMETER" >>p2
echo "CURRENT-VALUE" >>p3
echo "SECTION-ID" >>p7
echo "HOST-NAME" >>p6
echo "TEST-RESULT" >>p4
echo "SCAN-DATE" >>p5

serv=`whereis service |awk '{print $2}'`

PASS_MAX_DAYS=`cat hc_scan_parameter |grep ^PASS_MAX_DAYS |awk '{print $2}'`
PASS_MIN_DAYS=`cat hc_scan_parameter |grep ^PASS_MIN_DAYS |awk '{print $2}'`
PASS_MIN_LENGTH=`cat hc_scan_parameter |grep ^PASS_MIN_LENGTH |awk '{print $2}'`
DIGIT=`cat hc_scan_parameter |grep ^DIGIT |awk '{print $2}'`
UPPER_CASE=`cat hc_scan_parameter |grep ^UPPER_CASE |awk '{print $2}'`
LOWER_CASE=`cat hc_scan_parameter |grep ^LOWER_CASE |awk '{print $2}'`
OTHER_CHAR=`cat hc_scan_parameter |grep ^OTHER_CHAR |awk '{print $2}'`
LOG_ROTATE=`cat hc_scan_parameter |grep ^LOG_ROTATE |awk '{print $2}'`
PAM_REMEMBER=`cat hc_scan_parameter |grep ^PAM_REMEMBER |awk '{print $2}'`
UMASK_VAL=`cat hc_scan_parameter |grep ^UMASK_VAL |awk '{print $2}'`
UMASK_BASHRC_VAL=`cat hc_scan_parameter |grep ^UMASK_BASHRC_VAL |awk '{print $2}'`
PERMITROOTLOGIN=`cat hc_scan_parameter |grep ^PERMITROOTLOGIN |awk '{print $2}'`
PERMITEMPTYPASSWORDS=`cat hc_scan_parameter |grep ^PERMITEMPTYPASSWORDS |awk '{print $2}'`
PERMITUSERENVIRONMENT=`cat hc_scan_parameter |grep ^PERMITUSERENVIRONMENT |awk '{print $2}'`
TCPKEEPALIVE=`cat hc_scan_parameter |grep ^TCPKEEPALIVE |awk '{print $2}'`
MAXSTARTUPS=`cat hc_scan_parameter |grep ^MAXSTARTUPS |awk '{print $2}'`
MAXAUTHTRIES=`cat hc_scan_parameter |grep ^MAXAUTHTRIES |awk '{print $2}'`
LOGINGRACETIME=`cat hc_scan_parameter |grep ^LOGINGRACETIME |awk '{print $2}'`
KEYREGENERATIONINTERVAL=`cat hc_scan_parameter |grep ^KEYREGENERATIONINTERVAL |awk '{print $2}'`
LOGLEVEL=`cat hc_scan_parameter |grep ^LOGLEVEL |awk '{print $2}'`
GATEWAYPORTS=`cat hc_scan_parameter |grep ^GATEWAYPORTS |awk '{print $2}'`
STRICTMODES=`cat hc_scan_parameter |grep ^STRICTMODES |awk '{print $2}'`
PRINTMOTD=`cat hc_scan_parameter |grep ^PRINTMOTD |awk '{print $2}'`
LOG_ROTATE_WEEK=`cat hc_scan_parameter |grep ^LOG_ROTATE_WEEK |awk '{print $2}'`
LOG_ROTATE_MONTH=`cat hc_scan_parameter |grep ^LOG_ROTATE_MONTH |awk '{print $2}'`
SHARED_ID_VAULTED=`cat hc_scan_parameter |grep ^SHARED_ID_VAULTED |awk '{print $2}'`
############################################################################################################
# 		echo "$fqdn" >>en1
#    	echo "$ipAddress" >>en2
#       echo "$osName" >>en3
#		echo "$timestamp" >>en4	
############################################################################################################

#IZ.1.1.1.1:AD.1.1.1.1:PASS_MAX_DAYS
sz=`cat /etc/login.defs |grep -v "#"| grep ^PASS_MAX_DAYS | awk '{print $2}' |uniq`
if [ "$sz" != "$PASS_MAX_DAYS" ] ; then
	echo "Password Requirements" >>p1
	echo "PASS_MAX_DAYS value in /etc/login.defs" >>p2
	echo "$sz"  >>p3
	echo "no" >>p4
	echo "AD.1.1.1.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
else
	echo "Password Requirements" >>p1
	echo "PASS_MAX_DAYS value in /etc/login.defs" >>p2
	echo "$sz" >>p3
	echo "yes" >>p4
	echo "AD.1.1.1.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
###########################################################################################################
#IZ.1.1.1.2:AD.1.1.1.2:Fifth field of /etc/shadow
cat /etc/passwd | egrep -v "/sbin/nologin|sync|shutdown|halt|/bin/false" | awk -F":" '{print $1}' >temp_passwd
for i in `cat temp_passwd` ; do
sk=`chage -l $i |grep "^Maximum" |sed -e 's/://g' |awk '{print $8}'`
        if [ "$sk" != "$PASS_MAX_DAYS" ] ; then
                echo "Password Requirements" >>p1
                echo "PASS_MAX_DAYS" >>p2
		echo "Fifth field of /etc/shadow is not set as "$PASS_MAX_DAYS" for id $i" >>p3
		echo "AD.1.1.1.2" >>p7
		echo "no" >>p4
echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	else
                echo "Password Requirements" >>p1
                echo "PASS_MAX_DAYS" >>p2
		echo "Fifth field of /etc/shadow is set as "$PASS_MAX_DAYS" for id $i" >>p3
		echo "yes" >>p4
		echo "AD.1.1.1.2" >>p7
echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
        fi
done
rm -rf temp_passwd
###########################################################################################################
#IZ.1.1.2.0:AD.1.1.2.0
if [ -f /etc/pam.d/password-auth ] ; then
	flag=0
	sk=`cat /etc/pam.d/password-auth |grep ^password |egrep 'requisite|required' |grep pam_cracklib.so |grep "minlen=$PASS_MIN_LENGTH" |grep "dcredit=$DIGIT" |grep "ucredit=$UPPER_CASE"  |grep "lcredit=$LOWER_CASE" |grep "ocredit=$OTHER_CHAR" |grep 'reject_username' |wc -c`
	sl=`cat /etc/pam.d/password-auth |grep ^password |egrep 'requisite|required' |grep pam_pwquality.so |grep "minlen=$PASS_MIN_LENGTH" |grep "dcredit=$DIGIT" |grep "ucredit=$UPPER_CASE"  |grep "lcredit=$LOWER_CASE" |grep "ocredit=$OTHER_CHAR" |wc -c`
	if [ $sk -gt 0 ] || [ $sl -gt 0 ] ; then
		flag=1
	else
		cat /etc/security/pwquality.conf |grep -v '^#' |grep -q "minlen\s*=\s*$PASS_MIN_LENGTH"
		if [ $? -eq 0 ] ; then
			cat /etc/security/pwquality.conf |grep -v '^#' |grep -q "ucredit\s*=\s*$UPPER_CASE"
			if [ $? -eq 0 ] ; then
				cat /etc/security/pwquality.conf |grep -v '^#' |grep -q "ocredit\s*=\s*$OTHER_CHAR"
				if [ $? -eq 0 ] ; then
					cat /etc/security/pwquality.conf |grep -v '^#' |grep -q "dcredit\s*=\s*$DIGIT"
					if [ $? -eq 0 ] ; then
						cat /etc/security/pwquality.conf |grep -v '^#' |grep -q "lcredit\s*=\s*$LOWER_CASE"
						if [ $? -eq 0 ] ; then
							flag=1
						fi
					fi
				fi
			fi
		fi
	fi
	if [ $flag == 1 ] ; then
		echo "Password Requirements" >>p1
		echo "PASS_MIN_LEN-password_complexity" >>p2
		echo "no-violation-for-minlen-in-/etc/pam.d/password-auth" >> p3
		echo "AD.1.1.2.0">>p7
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	    echo "$fqdn" >>en1
    	echo "$ipAddress" >>en2
    	echo "$osName" >>en3
		echo "$timestamp" >>en4
	else
		echo "AD.1.1.2.0" >>p7
		echo "Password Requirements" >>p1
		echo "PASS_MIN_LEN-password_complexity" >>p2
		echo "Password-minlen-violation-in-/etc/pam.d/password-auth" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
    	echo "$fqdn" >>en1
    	echo "$ipAddress" >>en2
    	echo "$osName" >>en3
		echo "$timestamp" >>en4
	fi
else
	echo "AD.1.1.2.0" >>p7
	echo "Password Requirements" >>p1
	echo "PASS_MIN_LEN-password_complexity" >>p2
	echo "File-Not-Exist /etc/pam.d/password-auth" >> p3
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
if [ -f /etc/pam.d/system-auth ] ; then
	flag=0
	sk=`cat /etc/pam.d/system-auth |grep ^password |egrep 'requisite|required' |grep pam_cracklib.so |grep "minlen=$PASS_MIN_LENGTH" |grep "dcredit=$DIGIT" |grep "ucredit=$UPPER_CASE"  |grep "lcredit=$LOWER_CASE" |grep "ocredit=$OTHER_CHAR" |grep 'reject_username' |wc -c`
	sl=`cat /etc/pam.d/system-auth |grep ^password |egrep 'requisite|required' |grep pam_pwquality.so |grep "minlen=$PASS_MIN_LENGTH" |grep "dcredit=$DIGIT" |grep "ucredit=$UPPER_CASE"  |grep "lcredit=$LOWER_CASE" |grep "ocredit=$OTHER_CHAR" |wc -c`
	if [ $sk -gt 0 ] || [ $sl -gt 0 ] ; then
		flag=1
	else
		cat /etc/security/pwquality.conf |grep -v '^#' |grep -q "minlen\s*=\s*$PASS_MIN_LENGTH"
		if [ $? -eq 0 ] ; then
			cat /etc/security/pwquality.conf |grep -v '^#' |grep -q "ucredit\s*=\s*$UPPER_CASE"
			if [ $? -eq 0 ] ; then
				cat /etc/security/pwquality.conf |grep -v '^#' |grep -q "ocredit\s*=\s*$OTHER_CHAR"
				if [ $? -eq 0 ] ; then
					cat /etc/security/pwquality.conf |grep -v '^#' |grep -q "dcredit\s*=\s*$DIGIT"
					if [ $? -eq 0 ] ; then
						cat /etc/security/pwquality.conf |grep -v '^#' |grep -q "lcredit\s*=\s*$LOWER_CASE"
						if [ $? -eq 0 ] ; then
							flag=1
						fi
					fi
				fi
			fi
		fi
	fi
	if [ $flag == 1 ] ; then
		echo "Password Requirements" >>p1
		echo "PASS_MIN_LEN-password_complexity" >>p2
		echo "no-violation-for-minlen-in-/etc/pam.d/system-auth" >> p3
		echo "AD.1.1.2.0">>p7
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
    	echo "$fqdn" >>en1
    	echo "$ipAddress" >>en2
    	echo "$osName" >>en3
		echo "$timestamp" >>en4
	else
		echo "AD.1.1.2.0" >>p7
		echo "Password Requirements" >>p1
		echo "PASS_MIN_LEN-password_complexity" >>p2
		echo "Password-minlen-violation-in-/etc/pam.d/system-auth" >> p3
		echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	fi
else
	echo "AD.1.1.2.0" >>p7
	echo "Password Requirements" >>p1
	echo "PASS_MIN_LEN-password_complexity" >>p2
	echo "File-Not-Exist /etc/pam.d/system-auth" >> p3
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
############################################################################################################
#AD.1.1.2.1:IZ.1.1.2.1:2nd field of /etc/shadow
cat /etc/shadow | awk -F":" '{print $1}' >temp_shadow2
for i in `cat temp_shadow2` ; do
        sk1=`passwd -S $i |awk '{print $2}'`
        if [ "$sk1" == "NP" ] ; then
		echo "Password Requirements" >>p1
        echo "password specification within /etc/shadow" >>p2
		echo "A null password is assigned for user '$i'" >>p3
		echo "no" >>p4
		echo "AD.1.1.2.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	else
		echo "Password Requirements" >>p1
        echo "password specification within /etc/shadow" >>p2
		echo "User '$i' has no null value in second field of /etc/shadow" >>p3
		echo "AD.1.1.2.1" >>p7
		echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
        fi
done

#############################################################################################################
#IZ.1.1.3.1:AD.1.1.3.1:PASS_MIN_DAYS
sm=`cat /etc/login.defs | grep -v "#"| grep ^PASS_MIN_DAYS  | awk '{print $2}' |uniq`
if [ "$sm" != "$PASS_MIN_DAYS" ] ; then
	echo "Password Requirements" >>p1
	echo "PASS_MIN_DAYS value in /etc/login.defs" >>p2
	echo "$sm" >>p3
	echo "no" >>p4
	echo "AD.1.1.3.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
else
	echo "Password Requirements" >>p1
	echo "PASS_MIN_DAYS value in /etc/login.defs" >>p2
	echo "$sm" >>p3
	echo "yes" >>p4
	echo "AD.1.1.3.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
############################################################################################################
#IZ.1.1.3.2:AD.1.1.3.2:4th field of /etc/shadow
allNull=()
noNull=()
cat /etc/passwd | egrep -v "/sbin/nologin|sync|shutdown|halt|/bin/false" | awk -F":" '{print $1}' >temp_passwd
for i in `cat temp_passwd` ; do
	sk=`chage -l $i |grep "^Minimum" |sed -e 's/://g' |awk '{print $8}'`
	if [ "$sk" == "$PASS_MIN_DAYS" ] ; then
		noNull+=("$i")
	else
		allNull+=("$i")
	fi
done
allNull=$(IFS=, ; echo "${allNull[*]}")
noNull=$(IFS=, ; echo "${noNull[*]}")
if [ "$allNull" != "" ] ; then
	echo "Password Requirements" >>p1
	echo "Per-userid_Minimum_Password_Age" >>p2
	echo "Field 4 of /etc/shadow is not set as '$PASS_MIN_DAYS' for id $allNull" >>p3
	echo "no" >>p4
	echo "AD.1.1.3.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
if [ "$noNull" != "" ] ; then
	echo "Password Requirements" >>p1
	echo "Per-userid_Minimum_Password_Age" >>p2
	echo "Field 4 of /etc/shadow is set as '$PASS_MIN_DAYS' for id $noNull" >>p3
	echo "AD.1.1.3.2" >>p7
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
rm -rf temp_passwd

##############################################################################################################
#IZ.1.1.4.1:AD.1.1.4.1:pam-settings
if [ -f /etc/pam.d/system-auth ] ; then
	E=`cat /etc/pam.d/system-auth |grep -v '#' |grep ^password |egrep 'required|sufficient' |grep pam_unix.so |grep remember=$PAM_REMEMBER |egrep 'use_authtok|sha512|md5|shadow'`
	if [ $? -eq 0 ] ; then
		echo "Password Requirements" >>p1
		echo "prevent_reuse_of_lat_eight_passwords" >>p2
		echo "pam_unix.so_remember value_set-in-/etc/pam.d/system-auth" >>p3
		echo "yes" >> p4
		echo "AD.1.1.4.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
		echo "Password Requirements" >>p1
		echo "prevent_reuse_of_lat_eight_passwords" >>p2
		echo "pam_unix.so_remember value_not_set-in-/etc/pam.d/system-auth" >>p3
		echo "no" >> p4
		echo "AD.1.1.4.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	fi
else
		echo "Password Requirements" >>p1
		echo "prevent_reuse_of_lat_eight_passwords" >>p2
		echo "File-not-found-/etc/pam.d/system-auth. Please check the entry in /etc/pam.d/login, /etc/pam.d/passwd, /etc/pam.d/sshd and /etc/pam.d/su" >>p3
		echo "no" >> p4
		echo "AD.1.1.4.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
if [ -f /etc/pam.d/password-auth ] ; then
	E=`cat /etc/pam.d/password-auth |grep -v '#' |grep ^password |egrep 'required|sufficient' |grep pam_unix.so |grep remember=$PAM_REMEMBER |egrep 'use_authtok|sha512|md5|shadow'`
	if [ $? -eq 0 ] ; then
		echo "Password Requirements" >>p1
		echo "prevent_reuse_of_lat_eight_passwords" >>p2
		echo "pam_unix.so_remember value_set-in-/etc/pam.d/password-auth" >>p3
		echo "yes" >> p4
		echo "AD.1.1.4.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
		echo "Password Requirements" >>p1
		echo "prevent_reuse_of_lat_eight_passwords" >>p2
		echo "pam_unix.so_remember value_not_set-in-/etc/pam.d/password-auth" >>p3
		echo "no" >> p4
		echo "AD.1.1.4.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	fi
else
		echo "Password Requirements" >>p1
		echo "prevent_reuse_of_lat_eight_passwords" >>p2
		echo "File-not-found-/etc/pam.d/password-auth. Please check the entry in /etc/pam.d/login, /etc/pam.d/passwd, /etc/pam.d/sshd and /etc/pam.d/su" >>p3
		echo "no" >> p4
		echo "AD.1.1.4.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi

#############################################################################################################


#IZ.1.1.6.0:AD.1.1.6.0:loginretries value in password-auth and system-auth
if [ -f /etc/pam.d/system-auth ]  ; then
sk=`cat /etc/pam.d/system-auth |grep -v '#' | grep ^auth |grep required | egrep -w "pam_tally.so deny=5 |pam_tally2.so deny=5" |wc -l`
sl=`cat /etc/pam.d/system-auth |grep -v '#' | grep ^account |grep required | egrep -w "pam_tally.so |pam_tally2.so" |wc -l`
	if [ $sk -gt 0 ] && [ $sl -gt 0 ] ; then
		echo "Password Requirements" >>p1
		echo "loginretries" >>p2
		echo "Consecutive failed login attempts is set in /etc/pam.d/system-auth" >>p3
		echo "AD.1.1.6.0" >>p7
		echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	else
		echo "Password Requirements" >>p1
		echo "loginretries" >>p2
		echo "Consecutive failed login attempts is not set in /etc/pam.d/system-auth" >>p3
		echo "AD.1.1.6.0" >>p7
		echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	fi
else
		echo "Password Requirements" >>p1
		echo "loginretries" >>p2
		echo "File not found /etc/pam.d/system-auth" >>p3
		echo "AD.1.1.6.0" >>p7
		echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
if [ -f /etc/pam.d/password-auth ]  ; then
sk=`cat /etc/pam.d/password-auth |grep -v '#' | grep ^auth |grep required | egrep -w "pam_tally.so deny=5 |pam_tally2.so deny=5" |wc -l`
sl=`cat /etc/pam.d/password-auth |grep -v '#' | grep ^account |grep required | egrep -w "pam_tally.so |pam_tally2.so" |wc -l`
	if [ $sk -gt 0 ] && [ $sl -gt 0 ] ; then
		echo "Password Requirements" >>p1
		echo "loginretries" >>p2
		echo "Consecutive failed login attempts is set in /etc/pam.d/password-auth" >>p3
		echo "AD.1.1.6.0" >>p7
		echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	else
		echo "Password Requirements" >>p1
		echo "loginretries" >>p2
		echo "Consecutive failed login attempts is not set in /etc/pam.d/password-auth" >>p3
		echo "AD.1.1.6.0" >>p7
		echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	fi
else
		echo "Password Requirements" >>p1
		echo "loginretries" >>p2
		echo "File not found /etc/pam.d/system-auth" >>p3
		echo "AD.1.1.6.0" >>p7
		echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
#############################################################################################################
#IZ.1.1.7.1:AD.1.1.7.1
szkl=`passwd -S root |awk '{print $2}'`
sk=`chage -l root |grep "^Maximum" |sed -e 's/://g' |awk '{print $8}'`
if [ "$szkl" == "PS" ] && [ "$sk" == "$PASS_MAX_DAYS" ] ; then
		echo "AD.1.1.7.1" >>p7
		echo "Password Requirements" >>p1
		echo "Password and expiry settings for ROOT" >>p2
		echo "root_passwd_is_set and expiry period set as $PASS_MAX_DAYS" >> p3
		echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
else
		echo "AD.1.1.7.1" >>p7
		echo "Password Requirements" >>p1
		echo "Password and expiry settings for ROOT" >>p2
		echo "root_passwd setting is incorrect. Please check root password expiry and password status" >> p3
		echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
#########################################################################################################
#IZ.1.1.7.2:AD.1.1.7.2
sz=`cat /etc/ssh/sshd_config | grep -i "^PermitRootLogin" | awk '{print $2}' |uniq`
if [ "$sz" == "$PERMITROOTLOGIN" ] ; then
		echo "Password Requirements" >>p1
        echo "ROOT" >>p2
		echo "Interactive-root-login-is-disabled" >> p3
		echo "yes" >>p4
		echo "AD.1.1.7.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
else
		echo "Password Requirements" >>p1
        echo "ROOT" >>p2
		echo "Interactive-root-login-is-enabled" >> p3
        echo "no" >>p4
		echo "AD.1.1.7.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
###########################################################################################################

#IZ.1.1.8.2:AD.1.1.8.2:UID-validation
cat /etc/passwd | awk -F":" '{print $3}'| sort  | uniq -cd | awk '{print $2}'> temp_uid
sp=`cat temp_uid | wc -c`
if [ "$sp" == 0 ] ; then
		echo "Password Requirements" >>p1
		echo "UID_validation" >>p2
		echo  "No_duplicate_uid_value_for_users_in_/etc/passwd" >>p3
		echo "yes" >>p4
		echo "AD.1.1.8.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
else
		for i in `cat temp_uid` ; do
		echo "Password Requirements" >>p1
		echo "uid_validation" >>p2
		echo "Duplicate-uid-value-for-UID-$i" >>p3
		echo "no" >>p4
		echo "AD.1.1.8.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
		done
fi

#####################################################################################################
#AD.1.1.9.0:IZ.1.1.9.0:AD.1.1.9.1:IZ.1.1.9.1:non-expiry-passwords
cat /etc/passwd | egrep -v "/sbin/nologin|sync|shutdown|halt|/bin/false" |awk -F: '{print $1}' > sys-user-info
for i in `cat sys-user-info` ; do
sk=`passwd -S $i |awk '{print $2}'`
if [ "$sk" == "PS" ] || [ "$sk" == "NP" ] ; then
	chage -l $i | grep -w 99999 
	if [ $? -eq 0 ] ; then
		echo "Password Requirements" >>p1
		echo "Non-expiring passwords" >>p2
		echo "Expiry_passwd_value_not_exist_for_$i" >> p3
		echo "no" >>p4
		echo "AD.1.1.9.0:AD.1.1.9.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	else
		echo "Password Requirements" >>p1
		echo "Non-expiring passwords" >>p2
		echo "Expiry_passwd_value_exist_for_$i" >> p3
		echo "yes" >>p4
		echo "AD.1.1.9.0:AD.1.1.9.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	fi
else
		echo "Password Requirements" >>p1
		echo "Non-expiring passwords" >>p2
		echo "Not applicable as user ID $i is locked" >> p3
		echo "yes" >>p4
		echo "AD.1.1.9.0:AD.1.1.9.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
done
rm -rf sys-user-info
#####################################################################################################
#IZ.1.1.11.1:AD.1.1.11.1:AD.1.1.13.1.0:AD.1.1.13.2:IZ.1.1.13.2:IZ.1.1.13.1:Non-expiring ID's
for i in `cat /etc/passwd | egrep -v "/sbin/nologin|sync|shutdown|halt|/bin/false" | awk -F":" '{print $1}'` ; do
	sk=`chage -l $i | grep "Password expires" |sed -e 's/://' | awk '{ print $3}'`
	if [ "$sk" == "never" ] ; then
		sk1=`passwd -S $i |awk '{print $2}'`
		if [ "$sk1" == "LK" ] ; then
		  echo "Password Requirements" >>p1
		  echo "direct_or_remote_login" >>p2
		  echo "User $i has non-expiring password but the account is locked" >>p3
		  echo "yes" >>p4
		  echo "AD.1.1.11.1:AD.1.1.13.1.0:AD.1.1.13.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
		else
		  echo "Password Requirements" >>p1
		  echo "direct_or_remote_login" >>p2
		  echo "User $i has non-expiring password but the account is not locked" >>p3
		  echo "no" >>p4
		  echo "AD.1.1.11.1:AD.1.1.13.1.0:AD.1.1.13.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
		fi
	else
		echo "Password Requirements" >>p1
		echo "direct_or_remote_login" >>p2
		echo "User $i has expiry password set" >>p3
		echo "yes" >>p4
		echo "AD.1.1.11.1:AD.1.1.13.1.0:AD.1.1.13.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4        
	fi
done


###########################################################################################################
#IZ.1.1.12.1:AD.1.1.12.1:2nd field of /etc/shadow
for i in `cat /etc/passwd | egrep -v "/sbin/nologin|sync|shutdown|halt|/bin/false" | awk -F":" '{print $1}'` ; do
	sk=`passwd -S $i |awk '{print $2}'`
	if [ "$sk" == "NP" ] ; then
			echo "Password Requirements" >>p1
                	echo "Copy of passwd file containing the encrypted passwords" >>p2
			echo "The ID $i has no password set" >>p3
			echo "AD.1.1.12.1" >>p7
			echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	else
	if [ "$sk" == "LK" ] ; then
		sk3=`chage -l $i | grep "Password expires" |sed -e 's/://' | awk '{ print $3}'`
		if [ "$sk3" == "never" ] ; then
			echo "Password Requirements" >>p1
                	echo "Copy of passwd file containing the encrypted passwords" >>p2
			echo "The id $i is a locked account but password is set as never expire" >>p3
			echo "AD.1.1.12.1" >>p7
			echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
		else
			echo "Password Requirements" >>p1
                	echo "Copy of passwd file containing the encrypted passwords" >>p2
			echo "The id $i is a locked account and password is set as expire" >>p3
			echo "AD.1.1.12.1" >>p7
			echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
		fi
	else
	if [ "$sk" == "PS" ] ; then
		sk1=`passwd -S $i |awk '{print $11}' |cut -c1-5`
		if [ "$sk1" == "crypt" ] ; then
			echo "Password Requirements" >>p1
                	echo "Copy of passwd file containing the encrypted passwords" >>p2
			echo "The id $i has encrypted password settings" >>p3
			echo "AD.1.1.12.1" >>p7
			echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
		else
			echo "Password Requirements" >>p1
                	echo "Copy of passwd file containing the encrypted passwords" >>p2
			echo "The id $i has non-encrypted password settings" >>p3
			echo "AD.1.1.12.1" >>p7
			echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
		fi
	fi
	fi
	fi
done


#######################################################################################################
#AD.1.8.6.1
sk=`which pam_tally2`
if [ $? -ne 0 ] ; then
	str6=$(stat -c "%a %n" /var/log/faillog |awk '{print $1}')
	if [ "$str6" == "600" ] ; then
			echo "Protecting Resources - OSRs" >>p1
			echo "/var/log/faillog" >>p2
			echo "/var/log/faillog-Permission-is-valid" >> p3
			echo "yes" >>p4
			echo "AD.1.8.6.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	else
			echo "Protecting Resources - OSRs" >>p1
			echo "/var/log/faillog" >>p2
			echo "/var/log/faillog-Permission-is-invalid" >> p3
			echo "no" >>p4
			echo "AD.1.8.6.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	fi
else
			echo "Protecting Resources - OSRs" >>p1
			echo "/var/log/faillog" >>p2
			echo "Not applicable as pam_tally2 is in use" >> p3
			echo "Not_Applicable" >>p4
			echo "AD.1.8.6.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi


###########################################################################################################
#AD.1.1.10.1:IZ.1.1.10.1
for i in `cat /etc/passwd | egrep -v "/sbin/nologin|sync|shutdown|halt|/bin/false" | awk -F":" '{print $1}'` ; do
sk=`chage -l $i | grep "Password expires" |sed -e 's/://' | awk '{ print $3}'`
if [ "$sk" == "never" ] ; then
	sl=`getent passwd $i |awk -F: '{print $7}'`
	if [ "$sl" == "/sbin/nologin" ] || [ "$sl" == "/bin/false" ] ; then
		echo "Password Requirements" >>p1
		echo "direct_or_remote_login" >>p2
		echo "User $i has a valid shell $sl" >>p3
		echo "yes" >>p4
		echo "AD.1.1.10.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	else
		echo "Password Requirements" >>p1
		echo "direct_or_remote_login" >>p2
		echo "User $i has invalid shell $sl as it is set as never expired" >>p3
		echo "no" >>p4
		echo "AD.1.1.10.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	fi
else
		echo "Password Requirements" >>p1
		echo "direct_or_remote_login" >>p2
		echo "User $i has valid shell $sl" >>p3
		echo "yes" >>p4
		echo "AD.1.1.10.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
done
#######################################################################################################3
#AD.1.1.13.3:AD.1.1.10.2:IZ.1.1.13.3:IZ.1.1.10.2:FTP filecheck
ftpRPM=`rpm -q vsftpd`
if [ $? -ne 0 ] ; then
	echo "Password Requirements" >>p1
	echo "Restrict ftp access" >>p2
	echo "AD.1.1.13.3:AD.1.1.10.2" >>p7
	echo "Base package vsftpd is not installed" >> p3
	echo "Not_Applicable" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
else
	for i in `cat /etc/passwd | egrep -v "/sbin/nologin|sync|shutdown|halt|/bin/false" | awk -F":" '{print $1}'` ; do
		sk=`chage -l $i | grep "Password expires" |sed -e 's/://' | awk '{ print $3}'`
		if [ "$sk" == "never" ] ; then
			sk=`passwd -S $i |awk '{print $2}'`
			if [ "$sk" == "NP" ] || [ "$sk" == "PS" ] ; then
				if [ -f /etc/ftpusers ] || [ -f /etc/vsftpd.ftpusers ] || [ -f /etc/vsftpd/ftpusers ] ; then
					smt=`cat /etc/ftpusers |grep $i |wc -l`
					smr=`cat /etc/vsftpd.ftpusers |grep $i |wc -l`
					smt1=`cat /etc/vsftpd/ftpusers |grep $i |wc -l`
					if [ $smt -eq 0 ] || [ $smr -eq 0 ] || [ $smt1 -eq 0 ] ; then
						echo "Password Requirements" >>p1
						echo "Restrict ftp access" >>p2
						echo "AD.1.1.13.3:AD.1.1.10.2" >>p7
						echo "ftp_file_exist-but-never-expiry id $i is not mentioned in ftp file" >> p3
						echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
					else
						echo "Password Requirements" >>p1
						echo "Restrict ftp access" >>p2
						echo "ftp_file_exist-with-never-expiry-id $i" >> p3
						echo "yes" >>p4
						echo "AD.1.1.13.3:AD.1.1.10.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
					fi
				else
					echo "Password Requirements" >>p1
					echo "Restrict ftp access" >>p2
					echo "AD.1.1.13.3:AD.1.1.10.2" >>p7
					echo "ftp_file_doesnt-exist" >> p3
					echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
				fi
			else
				echo "Password Requirements" >>p1
				echo "Restrict ftp access" >>p2
				echo "AD.1.1.13.3:AD.1.1.10.2" >>p7
				echo "The ID $i is set as never expiry but ID is locked" >> p3
				echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
			fi
		else
			echo "Password Requirements" >>p1
			echo "Restrict ftp access" >>p2
			echo "AD.1.1.13.3:AD.1.1.10.2" >>p7
			echo "ID $i has correct password expiry settings" >> p3
			echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
		fi
	done
fi
############################################################################################################
#IZ.1.1.11.1:AD.1.1.11.1:AD.1.1.13.1.0:AD.1.1.13.2:IZ.1.1.13.2:IZ.1.1.13.1:Non-expiring ID's
for i in `cat /etc/passwd | egrep -v "/sbin/nologin|sync|shutdown|halt|/bin/false" | awk -F":" '{print $1}'` ; do
	sk=`chage -l $i | grep "Password expires" |sed -e 's/://' | awk '{ print $3}'`
	if [ "$sk" == "never" ] ; then
		sk1=`passwd -S $i |awk '{print $2}'`
		if [ "$sk1" == "LK" ] ; then
		  echo "Password Requirements" >>p1
		  echo "direct_or_remote_login" >>p2
		  echo "User $i has non-expiring password but the account is locked" >>p3
		  echo "yes" >>p4
		  echo "AD.1.1.13.1.0:AD.1.1.13.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
		else
		  echo "Password Requirements" >>p1
		  echo "direct_or_remote_login" >>p2
		  echo "User $i has non-expiring password but the account is not locked" >>p3
		  echo "no" >>p4
		  echo "AD.1.1.13.1.0:AD.1.1.13.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
		fi
	else
		echo "Password Requirements" >>p1
		echo "direct_or_remote_login" >>p2
		echo "User $i has expiry password set" >>p3
		echo "yes" >>p4
		echo "AD.1.1.13.1.0:AD.1.1.13.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4        
	fi
done
#############################################################################################################


#IZ.1.1.13.4:AD.1.1.13.4:PAM-yes
sk=`cat /etc/ssh/sshd_config |grep -v '#' |grep ^UsePAM |awk '{print $2}'`
if [ "$sk" == "yes" ] ; then
	echo "Password Requirements" >>p1
	echo "/etc/ssh/sshd_config" >>p2
	echo "UsePAM_yes_is_valid" >> p3
	echo "yes" >>p4
	echo "AD.1.1.13.4" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
else
	echo "Password Requirements" >>p1
	echo "/etc/ssh/sshd_config" >>p2
	echo "AD.1.1.13.4" >>p7
	echo "UsePAM_yes_is_invalid" >> p3
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi

#############################################################################################################

#AD.1.2.2:file-check
if [ -f /var/log/wtmp ] ; then
	echo "Logging" >>p1
	echo "/var/log/wtmp" >>p2
	echo "/var/log/wtmp_exist" >> p3
	echo "yes" >>p4
	echo "AD.1.2.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
else
	echo "Logging" >>p1
	echo "/var/log/wtmp" >>p2
	echo "/var/log/wtmp_doesnt_exist" >> p3
	echo "no" >>p4
	echo "AD.1.2.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
#########################################################################################################
#AD.1.2.3.1:file-check	
if [ -f /var/log/messages ] ; then
	echo "Logging" >>p1
	echo "/var/log/messages" >>p2
	echo "/var/log/messsages_exist" >> p3
	echo "yes" >>p4
	echo "AD.1.2.3.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
else
	echo "Logging" >>p1
	echo "AD.1.2.3.1" >>p7
	echo "/var/log/messages" >>p2
	echo "/var/log/messages_doesnt_exist" >> p3
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
######################################################################################################

#IZ.1.2.4.2;AD.1.2.4.2 - updated
grep -v '^\s*#' /etc/pam.d/system-auth | grep pam_tally2.so
grep -v '^\s*#' /etc/pam.d/password-auth | grep pam_tally2.so
if [ $? -eq 0 ] || [ $? -eq 0 ] ; then
	if [ -f /var/log/tallylog ] ; then
	echo "Logging" >>p1
	echo "/var/log/tallylog" >>p2
	echo "file-exists-/var/log/tallylog">>p3
	echo "yes" >>p4
	echo "AD.1.2.4.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
else
	echo "Logging" >>p1
	echo "/var/log/tallylog-permissions" >>p2
	echo "missing-file-/var/log/tallylog">>p3
	echo "no" >>p4
	echo "AD.1.2.4.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
else
	echo "Logging" >>p1
	echo "/var/log/tallylog-permissions" >>p2
	echo "missing-file-/var/log/tallylog">>p3
	echo "no" >>p4
	echo "AD.1.2.4.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
################################################################################################
#AD.1.2.5:file-check
szk=`cat /etc/redhat-release | awk '{print $1}'`
if [ "$szk" == "Red" ] ; then
	if [ -f /var/log/secure ] ; then
		echo "Logging" >>p1
		echo "/var/log/secure" >>p2
		echo "File /var/log/secure exist" >> p3
		echo "yes" >>p4
		echo "AD.1.2.5" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	else
		echo "Logging" >>p1
		echo "/var/log/secure" >>p2
		echo "File /var/log/secure not exist" >> p3
		echo "no" >>p4
		echo "AD.1.2.5" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	fi
else
	if [ -f /var/log/auth.log ] ; then
		echo "Logging" >>p1
		echo "/var/log/auth.log" >>p2
		echo "File /var/log/auth.log exist" >> p3
		echo "yes" >>p4
		echo "AD.1.2.5" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	else
		echo "Logging" >>p1
		echo "/var/log/auth.log" >>p2
		echo "File /var/log/auth.log not exist" >> p3
		echo "no" >>p4
		echo "AD.1.2.5" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	fi
fi

################################################################################################

#AD.1.4.1
sk=`cat /etc/pam.d/other |grep ^auth |grep required |grep pam_deny.so |wc -l`
sl=`cat /etc/pam.d/other |grep ^account |grep required |grep pam_deny.so |wc -l`
if [ $sk -gt 0 ] && [ $sl -gt 0 ] ; then
	echo "System Settings" >>p1
	echo "/etc/pam.d/other" >>p2
	echo "auth-required-account-required-has-pam_deny.so in file /etc/pam.d/other" >>p3
	echo "yes" >>p4
	echo "AD.1.4.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
else
	if [ $sk -eq 0 ]  ; then
		echo "System Settings" >>p1
		echo "/etc/pam.d/other" >>p2
		echo "auth-required-doesnt-have-pam_deny.so in file /etc/pam.d/other" >>p3
		echo "no" >>p4
		echo "AD.1.4.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	else
		echo "System Settings" >>p1
		echo "/etc/pam.d/other" >>p2
		echo "auth-required-has-pam_deny.so in file /etc/pam.d/other" >>p3
		echo "yes" >>p4
		echo "AD.1.4.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	fi
	if [ $sl -eq 0 ] ; then
			echo "System Settings" >>p1
			echo "/etc/pam.d/other" >>p2
			echo "account-required-doesnt-have-pam_deny.so in file /etc/pam.d/other" >>p3
			echo "no" >>p4
			echo "AD.1.4.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	else
			echo "System Settings" >>p1
			echo "/etc/pam.d/other" >>p2
			echo "account-required-has-pam_deny.so in file /etc/pam.d/other" >>p3
			echo "yes" >>p4
			echo "AD.1.4.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	fi
fi

#################################################################################################
#AD.1.4.5:AD.1.5.1.1:AD.1.5.1.2:AD.1.5.1.3:AD.1.5.1.4:AD.1.5.1.5:AD.1.5.1.6:AD.1.5.1.7:AD.1.5.1.8
fz1=`service vsftpd status |grep running |wc -c`
fz2=`ls -l /etc/vsftpd/vsftpd.conf |wc -c`
	if [ $fz1 -gt 0 ] || [ $fz2 -gt 0 ] ; then
		sl=`cat /etc/vsftpd/vsftpd.conf |grep ^anonymous_enable |awk -F= '{print $2}'`
		if [ "$sl" == "yes" ] ; then
			echo "Network Settingss" >> p1
			echo "Anonymous FTP System Settings" >>p2
			echo "FTP service is running and anonymous FTP is enabled. Please modify the settings as per techspec." >>p3
			echo "AD.1.5.1.1:AD.1.5.1.2:AD.1.5.1.3:AD.1.5.1.4:AD.1.5.1.5:AD.1.5.1.6:AD.1.5.1.7:AD.1.5.1.8">>p7
			echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
		else
			echo "Network Settingss" >> p1
			echo "Anonymous FTP System Settings" >>p2
			echo "FTP service is running but anonymous FTP is disabled" >>p3
			echo "AD.1.5.1.1:AD.1.5.1.2:AD.1.5.1.3:AD.1.5.1.4:AD.1.5.1.5:AD.1.5.1.6:AD.1.5.1.7:AD.1.5.1.8">>p7
			echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
		fi
	else
			echo "Network Settingss" >> p1
			echo "Anonymous FTP System Settings" >>p2
			echo "FTP is not configured" >>p3
			echo "AD.1.5.1.1:AD.1.5.1.2:AD.1.5.1.3:AD.1.5.1.4:AD.1.5.1.5:AD.1.5.1.6:AD.1.5.1.7:AD.1.5.1.8">>p7
			echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	fi
#####################################################################################################
#AD.1.5.2.1;AD.1.5.2.2:TFTP filecheck
rpm -qa |egrep "tftp-server|tftp"
if [ $? -ne 0 ] ; then
		echo "Network Settings" >>p1
		echo "TFTP System Setting" >>p2
		echo "AD.1.5.2.1:AD.1.5.2.2" >>p7
		echo "Base package tftp or tftp-server is not installed" >> p3
		echo "Not_Applicable" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
else
		echo "Network Settings" >>p1
		echo "TFTP System Setting" >>p2
		echo "AD.1.5.2.1:AD.1.5.2.2" >>p7
		echo "Base package tftp or tftp-server is installed. Please check the Techspec for additional check" >> p3
		echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
#########################################################################################################
#AD.1.5.3.1
sl=`which service`
sl1=`$sl nfs status`
if [ $? -eq 0 ] ; then
	szm=$(stat -c "%a %n" /etc/exports |awk '{print $1}')
	if [ $? -eq 0 ] && [ "$szm" == "644" ] ; then
		echo "Network Settingss" >>p1
		echo "/etc/exports" >>p2
		echo "NFS service is running and file permission is correct" >> p3
		echo "yes" >>p4
		echo "AD.1.5.3.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	else
		echo "Network Settingss" >>p1
		echo "/etc/exports" >>p2
		echo "NFS service is running and file permission is incorrect" >> p3
		echo "no" >>p4
		echo "AD.1.5.3.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	fi
else
	szm=$(stat -c "%a %n" /etc/exports |awk '{print $1}')
	if [ $? -eq 0 ] && [ "$szm" == "644" ] ; then
		echo "Network Settingss" >>p1
		echo "/etc/exports" >>p2
		echo "NFS service is not running and file permission is correct" >> p3
		echo "yes" >>p4
		echo "AD.1.5.3.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	else
		echo "Network Settingss" >>p1
		echo "/etc/exports" >>p2
		echo "NFS service is not running and file permission is incorrect" >> p3
		echo "no" >>p4
		echo "AD.1.5.3.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	fi
fi
############################################################################################################
#AD.1.5.4.1
if [ -f /etc/hosts.equiv ] ; then
	echo "Network Settings" >>p1
	echo "/etc/hosts.equiv" >>p2
	echo "/etc/hosts.equiv-file-exist" >> p3
	echo "AD.1.5.4.1" >>p7
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
else
	echo "Network Settings" >>p1
	echo "/etc/hosts.equiv" >>p2
	echo "/etc/hosts.equiv-file-not-exist" >> p3
	echo "AD.1.5.4.1" >>p7
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
########################################################################################
#AD.1.5.4.2
skl=`which arch`
sll=`$skl`
if [ "$sll" == "x86_64" ] ; then
  if [ -f /etc/pam.d/rlogin ] || [ -f  /etc/pam.d/rsh ] ; then
	sm=`grep -i "/lib64/security/pam_rhosts_auth.so" /etc/pam.d/rlogin |wc -c`
	sn=`grep -i "/lib64/security/pam_rhosts_auth.so" /etc/pam.d/rsh |wc -c`
	if [ $sm -ne 0 ] || [ $sn -ne 0 ]  ; then
		sa=`grep -i "no_hosts_equiv" /etc/pam.d/rlogin |wc -c`
		sb=`grep -i "no_hosts_equiv" /etc/pam.d/rsh |wc -c`
		if [ $sa -ne 0 ] || [ $sb -ne 0 ] ; then
			echo "Network Settingss" >>p1
			echo "/etc/pam.d-and-etc/pam.d/rlogin" >>p2
			echo "Required-settings-found-in-file-/etc/pam.d/rlogin-and-/etc/pam.d/rsh" >> p3
			echo "yes" >>p4
			echo "AD.1.5.4.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
		else
			echo "Network Settingss" >>p1
			echo "/etc/pam.d-and-etc/pam.d/rlogin" >>p2
			echo "Required-settings-not-found-in-file-/etc/pam.d/rlogin-and-/etc/pam.d/rsh" >> p3
			echo "no" >>p4
			echo "AD.1.5.4.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
		fi
	else
			echo "Network Settingss" >>p1
			echo "/etc/pam.d-and-etc/pam.d/rlogin" >>p2
			echo "no_hosts_equiv parameter not exist in-file-/etc/pam.d/rlogin-and-/etc/pam.d/rsh" >> p3
			echo "no" >>p4
			echo "AD.1.5.4.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	fi
  else
	echo "Network Settingss" >>p1
	echo "/etc/pam.d/rsh-and-/etc/pam.d/rlogin" >>p2
	echo "file-/etc/pam.d/rlogin-and-/etc/pam.d/rsh-not-exists" >> p3
	echo "AD.1.5.4.2" >>p7
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
  fi
else
	echo "Network Settingss" >>p1
	echo "/etc/pam.d/rsh-and-/etc/pam.d/rlogin" >>p2
	echo "This is not 64 bit kernel system" >> p3
	echo "AD.1.5.4.2" >>p7
	echo "Not_Applicable" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
###########################################################################################################
#AD.1.5.5:rexd daemon
if [ -f /etc/inetd.conf ] || [ -f /etc/xinetd.d/xinted.conf ] ; then
	sk=`cat /etc/inetd.conf | grep -v "#" | grep -i ^rexd |wc -l`
	sl=`cat /etc/xinetd.d/xinted.conf | grep -v "#" | grep -i ^rexd |wc -l`
	if [ $sk -gt 0 ] || [ $sl -gt 0 ] ; then
		echo "Network Settingss" >>p1
		echo "rexd daemon" >>p2
		echo "rexd deamon is runnig" >> p3
		echo "no" >>p4
		echo  "AD.1.5.5">>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	else
		echo "Network Settingss" >>p1
		echo "rexd daemon" >>p2
		echo "rexd deamon is not runnig" >> p3
		echo "yes" >>p4
		echo  "AD.1.5.5">>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	fi
else
		echo "Network Settingss" >>p1
		echo "rexd daemon" >>p2
		echo "File /etc/inetd.conf or /etc/xinetd.d/xinted.conf not exists " >> p3
		echo "yes" >>p4
		echo  "AD.1.5.5">>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
##########################################################################################################

#AD.1.5.7
if [ $(rpm -qa xorg-x11* | wc -l) -eq 0 ] ; then
	echo "Network Settings" >>p1
	echo "X-server access control" >>p2
	echo "X-server packages not installed" >>p3
	echo "Not_Applicable" >>p4
	echo "AD.1.5.7" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
else
sk=`which xhost`
if [ $? -eq 0 ] ; then
	$sk
	if [ $? -eq 0 ] ; then
		$sk |grep enabled
		if [ $? -eq 0 ] ; then
			echo "Network Settings" >>p1
			echo "X-server access control" >>p2
			echo "X-server packages installed and Access control is enabled via xhost" >>p3
			echo "yes" >>p4
			echo "AD.1.5.7" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	    else
			echo "Network Settings" >>p1
			echo "X-server access control" >>p2
			echo "Access control is disabled via xhost. Please check xhost command output and run 'xhost -'" >>p3
			echo "no" >>p4
			echo "AD.1.5.7" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
		fi
	else
		echo "Network Settings" >>p1
		echo "X-server access control" >>p2
		echo "X-server packages installed but xhost is not enabled or disabled" >>p3
		echo "yes" >>p4
		echo "AD.1.5.7" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	fi	
else
	echo "Network Settings" >>p1
	echo "X-server access control" >>p2
	echo "X-server packages installed but Xhost command not found" >>p3
	echo "yes" >>p4
	echo "AD.1.5.7" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
fi
##################################################################################################
#AD.1.5.8.1,AD.1.5.8.2,AD.1.5.8.3,AD.1.5.8.4,AD.1.5.8.5,AD.1.5.8.6,AD.1.5.8.7,AD.1.5.8.8,AD.1.5.9.1,AD.1.5.9.2,AD.1.5.9.3,AD.1.5.9.4,AD.1.5.9.5,AD.1.5.9.6,AD.1.5.9.7,AD.1.5.9.8,AD.1.5.9.9,AD.1.5.9.10,AD.1.5.9.11,AD.1.5.9.12,AD.1.5.9.13,AD.1.5.9.14,AD.1.5.9.15,AD.1.5.9.16,AD.1.5.9.17
sp=`which service`
sy=`$sp xinetd status`
if [ $? -eq 0 ] ; then
	sk=`ls /etc/xinetd.d |wc -l`
	if [ $sk -gt 0 ] ; then
	ls -ltr /etc/xinetd.d/ |grep -v "nrpe" |awk '{print $9}' |grep -v '^$' >xinetd_file
	for i in `cat xinetd_file` ; do
		sj=`cat /etc/xinetd.d/$i |grep -v '#' |grep disable |awk -F= '{print $2}' |sed -e 's/ //g'`
		if [ "$sj" == "yes" ] ; then
			echo "Network Settings" >>p1
			echo "Denial of Service through xinetd or inetd" >>p2
			echo "Service $i is disabled in /etc/xinetd.d" >>p3
			echo "yes" >>p4
			echo "AD.1.5.9.1:AD.1.5.9.2:AD.1.5.9.3:AD.1.5.9.4:AD.1.5.9.6:AD.1.5.9.7:AD.1.5.9.8:AD.1.5.9.9:AD.1.5.9.10:AD.1.5.9.11:AD.1.5.9.12:AD.1.5.9.14" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
		else
			echo "Network Settings" >>p1
			echo "Denial of Service through xinetd or inetd" >>p2
			echo "Service $i is enabled in /etc/xinetd.d" >>p3
			echo "no" >>p4
			echo "AD.1.5.9.1:AD.1.5.9.2:AD.1.5.9.3:AD.1.5.9.4:AD.1.5.9.6:AD.1.5.9.7:AD.1.5.9.8:AD.1.5.9.9:AD.1.5.9.10:AD.1.5.9.11:AD.1.5.9.12:AD.1.5.9.14" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
		fi
	done
	else
			echo "Network Settings" >>p1
			echo "Denial of Service through xinetd or inetd" >>p2
			echo "No service available in /etc/xinetd.d" >>p3
			echo "yes" >>p4
			echo "AD.1.5.9.1:AD.1.5.9.2:AD.1.5.9.3:AD.1.5.9.4:AD.1.5.9.6:AD.1.5.9.7:AD.1.5.9.8:AD.1.5.9.9:AD.1.5.9.10:AD.1.5.9.11:AD.1.5.9.12:AD.1.5.9.14" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	fi
else
			echo "Network Settings" >>p1
			echo "Denial of Service through xinetd or inetd" >>p2
			echo "xinetd service is not running" >>p3
			echo "yes" >>p4
			echo "AD.1.5.9.1:AD.1.5.9.2:AD.1.5.9.3:AD.1.5.9.4:AD.1.5.9.6:AD.1.5.9.7:AD.1.5.9.8:AD.1.5.9.9:AD.1.5.9.10:AD.1.5.9.11:AD.1.5.9.12:AD.1.5.9.14" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
rm -rf xinetd_file

########################################################################################################
#AD.1.5.9.23
sl=`which service`
sl1=`$sl telnetd status`
	if [ $? -eq 0 ] ; then
		echo "Network Settings" >>p1
		echo "telnet-service" >>p2
		echo "telnet-is-enabled" >>p3
		echo "no" >>p4
		echo "AD.1.5.9.23" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	else
		echo "Network Settings" >>p1
		echo "telnet-service" >>p2
		echo "telnet-is-disabled" >>p3
		echo "yes" >>p4
		echo "AD.1.5.9.23" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	fi
##########################################################################################################
#AD.1.5.10.1
rpm -q ypserv ypbind portmap yp-tools
if [ $? -eq 0 ] ; then
	sl=`which service`
	$sl yppasswdd status
	if [ $? -eq 0 ] ; then
			echo "Network Settings" >>p1
			echo "yppasswdd-daemon" >>p2
			echo "yppasswdd-daemon-is-running" >>p3
			echo "no" >>p4
			echo "AD.1.5.10.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	else
			echo "Network Settings" >>p1
			echo "yppasswdd-daemon" >>p2
			echo "yppasswdd-daemon-is-not-running" >>p3
			echo "yes" >>p4
			echo "AD.1.5.10.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	fi
else
	echo "Network Settings" >>p1
	echo "yppasswdd-daemon" >>p2
	echo "NIS packages not installed." >>p3
	echo "yes" >>p4
	echo "AD.1.5.10.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
#######################################################################################################
#AD.1.5.10.2:AD.1.5.11
sz=`rpm -q ypserv ypbind portmap yp-tools`
if [ $? -eq 0 ] ; then
	sl=`which service`
	sl1=`$sl ypserv status`
	if [ $? -eq 0 ] ; then
		echo "Network Settings" >>p1
		echo "NIS and NIS+ maps" >>p2
		echo "NIS-is-enabled_verify-the-map-files" >>p3
		echo "no" >>p4
		echo "AD.1.5.10.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	else
		echo "Network Settings" >>p1
		echo "NIS and NIS+ maps" >>p2
		echo "NIS-is-disabled" >>p3
		echo "yes" >>p4
		echo "AD.1.5.10.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	fi
else
		echo "Network Settings" >>p1
		echo "NIS and NIS+ maps" >>p2
		echo "NIS packages not installed" >>p3
		echo "yes" >>p4
		echo "AD.1.5.10.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
##################################################################################################
#AD.1.5.12.4:IZ.1.5.12.4
sl=`which service`
sl1=`$sl sendmail status`
if [ $? -eq 0 ] ; then
		echo "Network Settings" >>p1
		echo "sendmail-service" >>p2
		echo "sendmail-service-is-running: check the settings" >>p3
		echo "no" >>p4
		echo "AD.1.5.12.4" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4 
else
		echo "Network Settings" >>p1
		echo "sendmail-service" >>p2
		echo "sendmail-service-is-not-running" >>p3
		echo "yes" >>p4
		echo "AD.1.5.12.4" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
#########################################################################################
#AD.1.8.1.2;AD.1.8.1.3
echo "/etc/init.d,/etc/rc.d,/etc/cron.d,/var/spool/cron/tabs/root,/opt,/var,/usr/local,/tmp,/etc,/usr,/,/etc/security/opasswd,/etc/shadow,/etc/passwd,/etc,/var/log,/var/log/faillog,/var/log/tallylog,/var/log/wtmp,/var/log/secure,/var/log/lastlog,/var/log/cron,/var/log/btmp,/var/log/hist,/var/log/sa,/var/log/maillog,/var/log/auth.log,/var/tmp,/var/log/messages,/etc/profile.d/IBMsinit.sh,/etc/profile.d/IBMsinit.csh,/etc/inittab,/var/spool/cron/root,/etc/crontab,/etc/xinetd.conf" > temp
tr "," "\n" < temp > temp1
for i in `cat temp1` ; do
if [ -f $i ] || [ -d $i ] ; then
	sz=`cat /etc/redhat-release |awk '{print $7}'`
	BC=`which bc`
	if (( $($BC <<< "$sz<7") > 0 )) ; then
	sj=`ls -ld $i |awk '{print $3}'`
	sk=`ls -ld $i |awk '{print $4}'`
	sl=`id -u $sj`
	sm=`getent group $sk |awk -F: '{print $3}'`
		if [ $sl -le 99 ] || [[ $sl -ge 101 && $sl -le 499 ]] ; then
			echo "Protecting Resources - OSRs" >>p1
			echo "User Ownership" >>p2
			echo "The file $i is owned by $sj - Permission is Valid" >>p3
			echo "yes" >>p4
			echo "AD.1.8.1.2:AD.1.8.1.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
		else
			echo "Protecting Resources - OSRs" >>p1
			echo "User Ownership" >>p2
			echo "The file $i is owned by $sj - Permission is invalid" >>p3
			echo "no" >>p4
			echo "AD.1.8.1.2:AD.1.8.1.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
		fi
		if [ $sm -le 99 ] || [[ $sm -ge 101 && $sm -le 499 ]] ; then
			echo "Protecting Resources - OSRs" >>p1
			echo "User Ownership" >>p2
			echo "Group owner of file $i is $sk - Permission is Valid" >>p3
			echo "yes" >>p4
			echo "AD.1.8.1.2:AD.1.8.1.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
		else
			echo "Protecting Resources - OSRs" >>p1
			echo "User Ownership" >>p2
			echo "Group owner of file $i is $sk - Permission is invalid" >>p3
			echo "no" >>p4
			echo "AD.1.8.1.2:AD.1.8.1.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
		fi
	else
	sz=`cat /etc/redhat-release |awk '{print $7}'`
	BC=`which bc`
	if (( $($BC <<< "$sz>=7") > 0 )) ; then
	sj=`ls -ld $i |awk '{print $3}'`
	sk=`ls -ld $i |awk '{print $4}'`
	sl=`id -u $sj`
	sm=`getent group $sk |awk -F: '{print $3}'`
		if [ $sl -le 99 ] || [[ $sl -ge 101 && $sl -le 499 ]] ; then
			echo "Protecting Resources - OSRs" >>p1
			echo "User Ownership" >>p2
			echo "The file $i is owned by $sj - Permission is Valid" >>p3
			echo "yes" >>p4
			echo "AD.1.8.1.2:AD.1.8.1.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
		else
			echo "Protecting Resources - OSRs" >>p1
			echo "User Ownership" >>p2
			echo "The file $i is owned by $sj - Permission is invalid" >>p3
			echo "no" >>p4
			echo "AD.1.8.1.2:AD.1.8.1.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
		fi
		if [ $sm -le 99 ] || [[ $sm -ge 101 && $sm -le 499 ]] ; then
			echo "Protecting Resources - OSRs" >>p1
			echo "User Ownership" >>p2
			echo "Group owner of file $i is $sk - Permission is Valid" >>p3
			echo "yes" >>p4
			echo "AD.1.8.1.2:AD.1.8.1.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
		else
			echo "Protecting Resources - OSRs" >>p1
			echo "User Ownership" >>p2
			echo "Group owner of file $i is $sk - Permission is invalid" >>p3
			echo "no" >>p4
			echo "AD.1.8.1.2:AD.1.8.1.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
		fi
	else
			echo "Protecting Resources - OSRs" >>p1
			echo "User Ownership" >>p2
			echo "Not applicable as it is not for RHEL6 or RHEL7" >>p3
			echo "Not_Applicable" >>p4
			echo "AD.1.8.1.2:AD.1.8.1.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	fi
	fi
else
			echo "Protecting Resources - OSRs" >>p1
			echo "User Ownership" >>p2
			echo "Not applicable as file $i not exist" >>p3
			echo "Not_Applicable" >>p4
			echo "AD.1.8.1.2:AD.1.8.1.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
done

###########################################################################################
#AD.1.8.2.1
if [ -f ~root/.rhosts ] ; then
	sz=$(stat -c "%a %n" ~root/.rhosts |awk '{print $1}')
	sk=`ls -ld ~root/.rhosts |awk '{print $4}'`
	if [ "$sz" == "600" ] && [ "$sk" == "root" ] ; then
		echo "Protecting Resources - OSRs" >>p1
		echo "~root/.rhosts" >>p2
		echo "The-file-is-read-write-only-by-root" >>p3
		echo "yes" >>p4
		echo "AD.1.8.2.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "~root/.rhosts" >>p2
		echo "The-file-permission-is-set-incorrect" >>p3
		echo "no" >>p4
		echo "AD.1.8.2.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	fi
else
		echo "Protecting Resources - OSRs" >>p1
		echo "~root/.rhosts" >>p2
		echo "The-file-is-not-available" >>p3
		echo "yes" >>p4
		echo "AD.1.8.2.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
########################################################################################
#AD.1.8.2.2
if [ -f ~root/.netrc ] ; then
	sz=$(stat -c "%a %n" ~root/.netrc |awk '{print $1}')
	sk=`ls -ld ~root/.rhosts |awk '{print $4}'`
	if [ "$sz" == "600" ] && [ "$sk" == "root" ] ; then
		echo "Protecting Resources - OSRs" >>p1
		echo "~root/.netrc" >>p2
		echo "The-file-is-read-write-only-by-root" >>p3
		echo "yes" >>p4
		echo "AD.1.8.2.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "~root/.netrc" >>p2
		echo "The-file-permission-is-set-incorrect" >>p3
		echo "no" >>p4
		echo "AD.1.8.2.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	fi
else
		echo "Protecting Resources - OSRs" >>p1
		echo "~root/.netrc" >>p2
		echo "The-file-is-not-available" >>p3
		echo "yes" >>p4
		echo "AD.1.8.2.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
######################################################################################
#AD.1.8.3.1
str=`ls -ld / |awk '{print $1}' |cut -c9`
str1=`getfacl / |grep other |awk -F"::" '{print $2}' |cut -c 2`
sp=`getfacl / |grep other`
if [ "$str" == "w" ] || [ "$str1" == "w" ] ; then
		echo "Protecting Resources - OSRs" >>p1
		echo "/-dir-permission" >>p2
		echo "/-dir-is-writtable-by-others and ACL for / is set as '$sp'" >>p3
		echo "no" >>p4
		echo "AD.1.8.3.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
else
		echo "Protecting Resources - OSRs" >>p1
		echo "/-dir-permission" >>p2
		echo "/-dir-permission-is-correctly-set" >>p3
		echo "yes" >>p4
		echo "AD.1.8.3.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
#####################################################################################
#AD.1.8.3.3
str=`ls -ld /etc |awk '{print $1}' |cut -c9`
if [ "$str" == "w" ] ; then
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc-dir-permission" >>p2
		echo "/etc-dir-is-writtable-by-others" >>p3
		echo "no" >>p4
		echo "AD.1.8.3.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
else
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc-dir-permission" >>p2
		echo "/etc-dir-permission-is-correctly-set" >>p3
		echo "yes" >>p4
		echo "AD.1.8.3.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
######################################################################################
#AD.1.8.4.1
if [ -f /etc/security/opasswd ] ; then
str=$(stat -c "%a %n" /etc/security/opasswd |awk '{print $1}')
if [ "$str" == "600" ] ; then
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/security/opasswd-permission" >>p2
		echo "/etc/security/opasswd-permission-is-correctly-set" >>p3
		echo "yes" >>p4
		echo "AD.1.8.4.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
else
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/security/opasswd-permission" >>p2
		echo "/etc/security/opasswd-permission-is-incorrect" >>p3
		echo "no" >>p4
		echo "AD.1.8.4.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
else
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/security/opasswd-permission" >>p2
		echo "/etc/security/opasswd file not exist" >>p3
		echo "no" >>p4
		echo "AD.1.8.4.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
###################################################################################
#AD.1.8.5.1
str=`ls -ld /var |awk '{print $1}' |cut -c9`
if [ "$str" == "w" ] ; then
		echo "Protecting Resources - OSRs" >>p1
		echo "/var-dir-permission" >>p2
		echo "/var-dir-is-writtable-by-others" >>p3
		echo "no" >>p4
		echo "AD.1.8.5.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
else
		echo "Protecting Resources - OSRs" >>p1
		echo "/var-dir-permission" >>p2
		echo "/var-dir-permission-is-correctly-set" >>p3
		echo "yes" >>p4
		echo "AD.1.8.5.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
##################################################################################
#AD.1.8.5.2
find /var/log -type d -perm /o+w \! -perm -1000 >world-writable-test
sk=`cat world-writable-test |wc -l`
if [ $sk -gt 0 ] ; then
for i in `cat world-writable-test |grep -v "/bin/slogin"` ; do
	echo "Protecting Resources - OSRs" >>p1
	echo "/var/log and it's sub-directories permissions" >>p2
	echo "Permission is invalid for $i" >> p3
	echo "no" >>p4
	echo "AD.1.8.5.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
done
else
	echo "Protecting Resources - OSRs" >>p1
	echo "/var/log and it's sub-directories permissions" >>p2
	echo "Permission-is-valid for /var/log and it's sub-directories" >> p3
	echo "yes" >>p4
	echo "AD.1.8.5.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
rm -rf world-writable-test
#################################################################################

#AD.1.8.6.2
sk=`which pam_tally2`
if [ $? -eq 0 ] ; then
	str6=$(stat -c "%a %n" /var/log/tallylog |awk '{print $1}')
	if [ "$str6" == "600" ] ; then
			echo "Protecting Resources - OSRs" >>p1
			echo "/var/log/tallylog" >>p2
			echo "/var/log/tallylog-Permission-is-valid" >> p3
			echo "yes" >>p4
			echo "AD.1.8.6.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	else
			echo "Protecting Resources - OSRs" >>p1
			echo "/var/log/tallylog" >>p2
			echo "/var/log/tallylog-Permission-is-invalid" >> p3
			echo "no" >>p4
			echo "AD.1.8.6.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	fi
else
			echo "Protecting Resources - OSRs" >>p1
			echo "/var/log/tallylog" >>p2
			echo "Not applicable as pam_tally2 is not in use" >> p3
			echo "Not_Applicable" >>p4
			echo "AD.1.8.6.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
#################################################################################
#AD.1.8.7.1
str1=`ls -ld /var/log/messages | awk '{print $1}' | cut -c6`
str2=`ls -ld /var/log/messages | awk '{print $1}' | cut -c9`
#str5=$(stat -c "%a %n" /var/log/messages |awk '{print $1}')
#if [ "$str5" == "600" ] || [ "$str5" == "644" ] || [ "$str5" == "755" ]
if [ "$str1" != "w" ] && [ "$str2" != "w" ] ; then
	echo "Protecting Resources - OSRs" >>p1
	echo "/var/log/messages-permissions" >>p2
	echo "/var/log/messages-permissions is set correct" >> p3
	echo "yes" >>p4
	echo "AD.1.8.7.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
else
	echo "Protecting Resources - OSRs" >>p1
	echo "/var/log/messages-permissions" >>p2
	echo "AD.1.8.7.1" >>p7
	echo "/var/log/messages-permissions is not set correct" >> p3
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
################################################################################
#AD.1.8.7.2
str1=`ls -ld /var/log/wtmp | awk '{print $1}' | cut -c9`
if [ "$str1" != "w" ] ; then
		echo "Protecting Resources - OSRs" >>p1
		echo "/var/log/wtmp-permission" >>p2
		echo "Permission-is-valid" >> p3
		echo "yes" >>p4
		echo "AD.1.8.7.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
else
		echo "Protecting Resources - OSRs" >>p1
		echo "/var/log/wtmp-permission" >>p2
		echo "Permission-is-invalid" >> p3
		echo "no" >>p4
		echo "AD.1.8.7.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
################################################################################
#AD.1.8.8
szk=`cat /etc/redhat-release | awk '{print $1}'`
if [ "$szk" == "Red" ] ; then
	if [ -f /var/log/secure ] ; then
	str1=`ls -ld /var/log/secure | awk '{print $1}' | cut -c6`
	str2=`ls -ld /var/log/secure | awk '{print $1}' | cut -c9`
		if [ "$str1" != "w" ] || [ "$str2" != "w" ] ; then
			echo "Protecting Resources - OSRs" >>p1
			echo "/var/log/secure" >>p2
			echo "Permission-is-valid" >> p3
			echo "yes" >>p4
			echo "AD.1.8.8" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
		else
			echo "Protecting Resources - OSRs" >>p1
			echo "/var/log/secure" >>p2
			echo "Permission-is-invalid" >> p3
			echo "no" >>p4
			echo "AD.1.8.8" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
		fi
	else
			echo "Protecting Resources - OSRs" >>p1
			echo "/var/log/secure" >>p2
			echo "File /var/log/secure not found" >> p3
			echo "no" >>p4
			echo "AD.1.8.8" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	fi
else
	if [ -f /var/log/auth.log ] ; then
	str6=`ls -ld /var/log/auth.log | awk '{print $1}' | cut -c9`
		if [ "$str6" != "w" ] ; then
			echo "Protecting Resources - OSRs" >>p1
			echo "/var/log/auth.log" >>p2
			echo "Permission-is-valid" >> p3
			echo "yes" >>p4
			echo "AD.1.8.8" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
		else
			echo "Protecting Resources - OSRs" >>p1
			echo "/var/log/auth.log" >>p2
			echo "Permission-is-invalid" >> p3
			echo "no" >>p4
			echo "AD.1.8.8" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
		fi
	else
			echo "Protecting Resources - OSRs" >>p1
			echo "/var/log/auth.log" >>p2
			echo "File /var/log/auth.log not found" >> p3
			echo "no" >>p4
			echo "AD.1.8.8" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	fi
fi
############################################################################################
#AD.1.8.9
str7=$(stat -c "%a %n" /tmp |awk '{print $1}')
if [ "$str7" == "1777" ] ; then
	echo "Protecting Resources - OSRs" >>p1
	echo "/tmp-dir-permission" >>p2
	echo "/tmp-dir-permission-is-valid" >> p3
	echo "yes" >>p4
	echo "AD.1.8.9" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
else
	echo "Protecting Resources - OSRs" >>p1
	echo "/tmp-dir-permission" >>p2
	echo "/tmp-dir-permission-is-invalid" >> p3
	echo "AD.1.8.9" >>p7
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
###########################################################################################
#AD.1.8.10
if [ -f /etc/snmpd.conf ] || [ -f /etc/snmp/snmpd.conf ] || [ -f /etc/snmpd/snmpd.conf ] ; then
str1=$(stat -c "%a %n" /etc/snmpd.conf |awk '{print $1}')
str2=$(stat -c "%a %n" /etc/snmp/snmpd.conf |awk '{print $1}')
str3=$(stat -c "%a %n" /etc/snmpd/snmpd.conf |awk '{print $1}')
	if [ "$str1" == "640" ] || [ "$str2" == "640" ] || [ "$str3" == "640" ] ; then
		echo "Protecting Resources - OSRs" >>p1
		echo "snmpd.conf-permission" >>p2
		echo "snmpd.conf-permission-is-valid" >> p3
		echo "yes" >>p4
		echo "AD.1.8.10" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "snmpd.conf-permission" >>p2
		echo "snmpd.conf-permission-is-invalid" >> p3
		echo "no" >>p4
		echo "AD.1.8.10" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	fi
else
		echo "Protecting Resources - OSRs" >>p1
		echo "snmpd.conf-permission" >>p2
		echo "snmpd.conf-file-not-exist" >> p3
		echo "yes" >>p4
		echo "AD.1.8.10" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
##########################################################################################
#AD.1.8.11
str7=$(stat -c "%a %n" /var/tmp |awk '{print $1}')
if [ "$str7" == "1777" ] ; then
	echo "Protecting Resources - OSRs" >>p1
	echo "/var/tmp-permission" >>p2
	echo "/var/tmp-permission-is-valid" >> p3
	echo "yes" >>p4
	echo "AD.1.8.11" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
else
	echo "Protecting Resources - OSRs" >>p1
	echo "/var/tmp-permission" >>p2
	echo "/var/tmp-permission-is-invalid" >> p3
	echo "AD.1.8.11" >>p7
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
#########################################################################################
#AD.1.8.8:AD.1.8.9:AD.1.8.12.1.1:AD.1.8.12.1.2:AD.1.8.12.2:AD.1.8.12.3:AD.1.8.12.4:AD.1.8.13.3:AD.1.8.13.4:AD.1.8.14.2:AD.1.8.14.3:AD.1.8.15.2:AD.1.8.15.3:AD.1.8.17.2:AD.1.8.17.3:AD.1.8.18.2:IZ.1.8.18.2:AD.1.8.18.3:IZ.1.8.18.3:AD.1.8.19.2:AD.1.8.19.3:AD.1.8.20.2:IZ.1.8.20.2:AD.1.8.20.3:IZ.1.8.20.3:AD.1.9.1.1:AD.1.8.21.2:AD.1.8.21.3:AD.1.8.22.1:IZ.1.8.22.1:AD.1.8.22.2:IZ.1.8.22.2:AD.1.8.22.3:IZ.1.8.22.3:AD.1.8.22.4:AD.1.8.13.1.2:IZ.1.8.13.1.2:IZ.1.8.22.4
find /usr/local -type f -perm /o+w \! -perm -1000 >world-writable-test
find /usr/local -type d -perm /o+w \! -perm -1000 >>world-writable-test
find /var -type f -perm /o+w \! -perm -1000 >>world-writable-test
find /var -type d -perm /o+w \! -perm -1000 >>world-writable-test
find /etc -type f -perm /o+w \! -perm -1000 >>world-writable-test
find /etc -type d -perm /o+w \! -perm -1000 >>world-writable-test
find /opt -type f -perm /o+w \! -perm -1000 >>world-writable-test
find /opt -type d -perm /o+w \! -perm -1000 >>world-writable-test
find /tmp -type f -perm /o+w \! -perm -1000 >>world-writable-test
find /tmp -type d -perm /o+w \! -perm -1000 >>world-writable-test
sk=`cat world-writable-test |wc -l`
if [ $sk -gt 0 ] ; then
	for i in `cat world-writable-test` ; do
		echo "Protecting Resources - OSRs" >>p1
		echo "File-Directory-write-permissions-for-others" >>p2
		echo "$i" >> p3
		echo "No" >>p4
		echo "AD.1.8.8:AD.1.8.9:AD.1.8.14.2:AD.1.8.14.3:AD.1.8.15.2:AD.1.8.15.3:AD.1.8.18.2:AD.1.8.18.3:AD.1.8.20.2:AD.1.8.13.1.2:AD.1.8.20.3:AD.1.8.22.1:AD.1.8.22.2:AD.1.8.22.3:AD.1.8.22.4:AD.1.8.19.2:AD.1.8.19.3:AD.1.8.21.2:AD.1.8.21.3:AD.1.8.12.1.1:AD.1.8.12.1.2:AD.1.8.12.2:AD.1.8.12.3:AD.1.8.12.4" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	done
else
	echo "Protecting Resources - OSRs" >>p1
	echo "File-Directory-write-permissions-for-others" >>p2
	echo "$i" >> p3
	echo "Yes" >>p4
	echo "AD.1.8.8:AD.1.8.9:AD.1.8.14.2:AD.1.8.14.3:AD.1.8.15.2:AD.1.8.15.3:AD.1.8.18.2:AD.1.8.18.3:AD.1.8.20.2:AD.1.8.13.1.2:AD.1.8.20.3:AD.1.8.22.1:AD.1.8.22.2:AD.1.8.22.3:AD.1.8.22.4:AD.1.8.19.2:AD.1.8.19.3:AD.1.8.21.2:AD.1.8.21.3:AD.1.8.12.1.1:AD.1.8.12.1.2:AD.1.8.12.2:AD.1.8.12.3:AD.1.8.12.4" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
rm -rf world-writable-test
#########################################################################################

#AD.1.8.12.6
if [ -f /etc/profile.d/IBMsinit.sh ] ; then
str4=`ls -l /etc/profile.d/IBMsinit.sh | awk '{print $1}' | cut -c9`
str5=`ls -l /etc/profile.d/IBMsinit.sh | awk '{print $1}' | cut -c6`
str6=`ls -l /etc/profile.d/IBMsinit.sh | awk '{print $3}'`
str7=`ls -l /etc/profile.d/IBMsinit.sh | awk '{print $4}'`
	if [ "$str4" != "w" ] && [ "$str5" != "w" ] && [ "$str6" == "root" ] && [ "$str7" == "root" ] ; then
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/profile.d/IBMsinit.sh-permissions" >>p2
		echo "/etc/profile.d/IBMsinit.sh-permission-is-valid" >> p3
		echo "yes" >>p4
		echo "AD.1.8.12.6" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/profile.d/IBMsinit.sh-permissions" >>p2
		echo "/etc/profile.d/IBMsinit.sh-permission-is-not-valid" >> p3
		echo "no" >>p4
		echo "AD.1.8.12.6" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	fi
else
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/profile.d/IBMsinit.sh-permissions" >>p2
		echo "/etc/profile.d/IBMsinit.sh-file-not-exist" >> p3
		echo "no" >>p4
		echo "AD.1.8.12.6" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
########################################################################################
#AD.1.8.12.7
if [ -f /etc/profile.d/IBMsinit.csh ] ; then
str4=`ls -l /etc/profile.d/IBMsinit.csh | awk '{print $1}' | cut -c9`
str5=`ls -l /etc/profile.d/IBMsinit.csh | awk '{print $1}' | cut -c6`
str6=`ls -l /etc/profile.d/IBMsinit.csh | awk '{print $3}'`
str7=`ls -l /etc/profile.d/IBMsinit.csh | awk '{print $4}'`
	if [ "$str4" != "w" ] && [ "$str5" != "w" ] && [ "$str6" == "root" ] && [ "$str7" == "root" ] ; then
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/profile.d/IBMsinit.csh-permissions" >>p2
		echo "/etc/profile.d/IBMsinit.csh-permission-is-valid" >> p3
		echo "yes" >>p4
		echo "AD.1.8.12.7" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/profile.d/IBMsinit.csh-permissions" >>p2
		echo "/etc/profile.d/IBMsinit.csh-permission-is-not-valid" >> p3
		echo "no" >>p4
		echo "AD.1.8.12.7" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	fi
else
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/profile.d/IBMsinit.csh-permissions" >>p2
		echo "/etc/profile.d/IBMsinit.csh-file-not-exist" >> p3
		echo "no" >>p4
		echo "AD.1.8.12.7" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
####################################################################################

#AD.1.8.14.1
sk=`cat /var/spool/cron/root |grep -v '#' |grep -v '^$' |awk '{print $6}' |wc -l`
if [ $sk -gt 0 ] ; then
cat /var/spool/cron/root |grep -v '#' |grep -v '^$' |awk '{print $6}' >t1
while IFS= read -r line ; do
        sk1=`echo $line |cut -c 1`
        if [ "$sk1" == "/" ] ; then
                echo "Protecting Resources - OSRs" >>p1
                echo "/var/spool/cron/root" >>p2
		echo "Full-path-is-specified-for-command- $line in-/var/spool/cron/root" >>p3
		echo "AD.1.8.14.1" >>p7
		echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	else
                echo "Protecting Resources - OSRs" >>p1
                echo "/var/spool/cron/root" >>p2
		echo "Full-path-is-not-specified-for-command- $line in-/var/spool/cron/root" >>p3
		echo "no" >>p4
		echo "AD.1.8.14.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
        fi
done <t1
else
		echo "Protecting Resources - OSRs" >>p1
                echo "/var/spool/cron/root" >>p2
		echo "No entry found in-/var/spool/cron/root" >>p3
		echo "AD.1.8.14.1" >>p7
		echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
rm -rf t1
###########################################################################################
#AD.1.8.15.1
cat /etc/crontab |grep -v '#' |egrep -v 'SHELL|PATH|MAILTO|HOME' |grep -v '^$' |awk '{print $6}' >t1
if [ $? -ne 0 ] ; then
while IFS= read -r line ; do
        sk1=`echo $line |cut -c 1`
        if [ "$sk1" == "/" ] ; then
                echo "Protecting Resources - OSRs" >>p1
                echo "/etc/crontab" >>p2
		echo "Full-path-is-specified-for-command- $line in-/etc/crontab" >>p3
		echo "AD.1.8.15.1" >>p7
		echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	else
                echo "Protecting Resources - OSRs" >>p1
                echo "/etc/crontab" >>p2
		echo "Full-path-is-not-specified-for-command- $line in-/etc/crontab" >>p3
		echo "no" >>p4
		echo "AD.1.8.15.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
        fi
done <t1
else
		echo "Protecting Resources - OSRs" >>p1
                echo "/etc/crontab" >>p2
		echo "No-cron-entry-found-in-/etc/crontab" >>p3
		echo "yes" >>p4
		echo "AD.1.8.15.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
rm -rf t1
#############################################################################################

#AD.1.8.20.1:IZ.1.8.20.1
ls -l /etc/cron.d |awk '{print $9}' |grep -v '^$' >file1
for i in `cat file1`
do
sk2=`cat /etc/cron.d/$i |grep -v '#' |grep -v '^$' |egrep -v 'SHELL|PATH|MAILTO|HOME|run-parts' |awk '{print $7}'| wc -l` >file2
if [ "$sk2" -ne "0" ]
then
        echo "Protecting Resources - User Resources" >>p1
        echo "/etc/cron.d/-directory-structure" >>p2
        echo "Full-path-is-specified-for-command- $line in-/etc/cron.d/$i" >>p3
        echo "AD.1.8.20.1" >>p7
        echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
        
else
		echo "Protecting Resources - User Resources" >>p1
        echo "/etc/cron.d/-directory-structure" >>p2
        echo "Full-path-is-specified-for-command- $line in-/etc/cron.d/$i" >>p3
        echo "AD.1.8.20.1" >>p7
        echo "No" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
        

fi
done
rm -rf t1 file2
########################################################################################
#AD.1.9.1.2
sk=`cat /etc/bashrc |grep -v '#'  |sed -n '/$UID -gt 199/,/fi/p' |head -2 |grep umask |awk '{print $2}'`
if [ "$sk" == "077" ] ; then
        echo "Protecting Resources - User Resources" >>p1
        echo "umask-value-in-/etc/bashrc" >>p2
		echo "umask-value-set-as-$sk" >>p3
		echo "AD.1.9.1.2" >>p7
		echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
else
        echo "Protecting Resources - User Resources" >>p1
        echo "umask-value-in-/etc/bashrc" >>p2
		echo "umask-value-set-incorrect-as $sk" >>p3
		echo "no" >>p4
		echo "AD.1.9.1.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
######################################################################################
#AD.1.9.1.2.1:IZ.1.9.1.2.1
#cat /etc/login.defs |grep -v '#' |grep UMASK |uniq
E=`cat /etc/login.defs |grep -v '#' |grep UMASK`
if [ "$E" != "" ] ; then
	cat /etc/login.defs |grep -v '#' |grep UMASK >t1
	while IFS= read -r line ; do
		sk1=`echo $line | awk '{print $2}'`
		if [ "$sk1" == "$UMASK_VAL" ] ; then
			echo "Protecting Resources - User Resources" >>p1
			echo "umask-value-in-/etc/login.defs" >>p2
			echo "umask-value-set-as-$line" >>p3
			echo "AD.1.9.1.2.1" >>p7
			echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
		else
			echo "Protecting Resources - User Resources" >>p1
			echo "umask-value-in-/etc/login.defs" >>p2
			echo "umask-value-set-as-$line" >>p3
			echo "no" >>p4
			echo "AD.1.9.1.2.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
		fi
	done <t1
else
	echo "Protecting Resources - User Resources" >>p1
	echo "umask-value-in-/etc/login.defs" >>p2
	echo "umask-value-is-not-set-in-/etc/login.defs" >>p3
	echo "no" >>p4
	echo "AD.1.9.1.2.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
rm -rf t1
#####################################################################################
#AD.1.9.1.3
if [ -f /etc/profile.d/IBMsinit.sh ] ; then
	cat /etc/profile.d/IBMsinit.sh |sed -n '/if/,/fi/p' |grep -v '#' |grep -i umask
	if [ $? -eq 0 ] ; then
		cat /etc/profile.d/IBMsinit.sh |grep -v '#' |grep -i umask >t1
		while IFS= read -r line ; do
		sk1=`echo $line | awk '{print $2}'`
	       		if [ "$sk1" == "077" ] ; then
		        	echo "Protecting Resources - User Resources" >>p1
		        	echo "umask-value-in-/etc/profile.d/IBMsinit.sh" >>p2
				echo "umask-value-set-as-$line" >>p3
				echo "AD.1.9.1.3" >>p7
				echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
			else
		        	echo "Protecting Resources - User Resources" >>p1
		        	echo "umask-value-in-/etc/profile.d/IBMsinit.sh" >>p2
				echo "umask-value-set-as-$line" >>p3
				echo "no" >>p4
				echo "AD.1.9.1.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
			fi	
		done <t1
	else
		echo "Protecting Resources - User Resources" >>p1
                echo "umask-value-in-/etc/profile.d/IBMsinit.sh" >>p2
		echo "umask entry not exist in /etc/profile.d/IBMsinit.sh" >>p3
		echo "no" >>p4
		echo "AD.1.9.1.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	fi
else
		echo "Protecting Resources - User Resources" >>p1
                echo "umask-value-in-/etc/profile.d/IBMsinit.sh" >>p2
		echo "File-doesnt-exist-/etc/profile.d/IBMsinit.sh" >>p3
		echo "no" >>p4
		echo "AD.1.9.1.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
rm -rf t1
#################################################################################
#AD.1.9.1.4
if [ -f /etc/profile.d/IBMsinit.csh ] ; then
	cat /etc/profile.d/IBMsinit.csh |sed -n '/if/,/endif/p' |grep -v '#' |grep -i umask
	if [ $? -eq 0 ] ; then
		cat /etc/profile.d/IBMsinit.csh |grep -v '#' |grep -i umask >t1
		while IFS= read -r line ; do
		sk1=`echo $line | awk '{print $2}'`
  	 		if [ "$sk1" == "077" ] ; then
				echo "Protecting Resources - User Resources" >>p1
				echo "umask-value-in-/etc/profile.d/IBMsinit.csh" >>p2
				echo "umask-value-set-as-$sk1" >>p3
				echo "AD.1.9.1.4" >>p7
				echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
			else
				echo "Protecting Resources - User Resources" >>p1
				echo "umask-value-in-/etc/profile.d/IBMsinit.csh" >>p2
				echo "umask-value-set-as-$sk1" >>p3
				echo "no" >>p4
				echo "AD.1.9.1.4" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
			fi	
		done <t1
	else
		echo "Protecting Resources - User Resources" >>p1
		echo "umask-value-in-/etc/profile.d/IBMsinit.csh" >>p2
		echo "umask-value not exist in /etc/profile.d/IBMsinit.csh" >>p3
		echo "no" >>p4
		echo "AD.1.9.1.4" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
else
		echo "Protecting Resources - User Resources" >>p1
		echo "umask-value-in-/etc/profile.d/IBMsinit.csh" >>p2
		echo "File-doesnt-exist-/etc/profile.d/IBMsinit.csh" >>p3
		echo "no" >>p4
		echo "AD.1.9.1.4" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
rm -rf t1
################################################################################
#AD.1.9.1.5:IBMsinit.sh
if [ -f /etc/profile.d/IBMsinit.sh ] ; then
cat /etc/profile  |grep '.*/etc/profile.d/IBMsinit.sh'
if [ $? -eq 0 ] ; then
		echo "Protecting Resources - User Resources" >>p1
        echo "/etc/profile " >>p2
		echo "/etc/profile.d/IBMsinit.sh_is_enabled" >>p3
		echo "AD.1.9.1.5">>p7
		echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
else
		echo "Protecting Resources - User Resources" >>p1
        echo "/etc/profile " >>p2
		echo "/etc/profile.d/IBMsinit.sh_is_not_enabled" >>p3
		echo "AD.1.9.1.5">>p7
		echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
else
		echo "Protecting Resources - User Resources" >>p1
        echo "/etc/profile " >>p2
		echo "File /etc/profile.d/IBMsinit.sh not exists" >>p3
		echo "AD.1.9.1.5">>p7
		echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
################################################################################
#AD.1.9.1.6:IBMsinit.csh
if [ -f /etc/profile.d/IBMsinit.csh ] ; then
cat /etc/csh.login | grep 'source.*/etc/profile.d/IBMsinit.csh'
if [ $? -eq 0 ] ; then
		echo "Protecting Resources - User Resources" >>p1
        echo "/etc/csh.login " >>p2
		echo "/etc/profile.d/IBMsinit.csh_is_enabled" >>p3
		echo "AD.1.9.1.6">>p7
		echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
else
		echo "Protecting Resources - User Resources" >>p1
        echo "/etc/csh.login" >>p2
		echo "/etc/profile.d/IBMsinit.csh_is_not_enabled" >>p3
		echo "AD.1.9.1.6">>p7
		echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
else
		echo "Protecting Resources - User Resources" >>p1
        echo "/etc/csh.login" >>p2
		echo "/etc/profile.d/IBMsinit.csh file not exists" >>p3
		echo "AD.1.9.1.6">>p7
		echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
##################################################################################
#AD.1.9.1.7
echo "/etc/skel/.cshrc,/etc/skel/.login,/etc/skel/.profile,/etc/skel/.bashrc,/etc/skel/.bash_profile,/etc/skel/.bash_login,/etc/skel/.tcshrc" >temp
tr "," "\n" < temp > temp1
for i in `cat temp1` ; do
if [ -f $i ] ; then
	cat $i | grep -v '#' |grep -i umask
	if [ $? -eq 0 ] ; then
	cat $i |grep -v '#' |grep -i umask >t1
	while IFS= read -r line ; do
      		sk1=`echo $line | awk '{print $2}'`
      		if [ "$sk1" == "$UMASK_VAL" ] ; then
         	echo "Protecting Resources - User Resources" >>p1
       		echo "Default UMASK value in skeleton files" >>p2
			echo "umask-value-set-as-$line for $i" >>p3
			echo "AD.1.9.1.7" >>p7
			echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
		else
          	echo "Protecting Resources - User Resources" >>p1
            echo "Default UMASK value in skeleton files" >>p2
			echo "umask-value-set-as-$line for $i" >>p3
			echo "no" >>p4
			echo "AD.1.9.1.7" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
       		fi
	done <t1
	else
			echo "Protecting Resources - User Resources" >>p1
                        echo "Default UMASK value in skeleton files" >>p2
                        echo "umask-value-is-not-set for $i" >>p3
                        echo "no" >>p4
                        echo "AD.1.9.1.7" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	fi
else
			echo "Protecting Resources - User Resources" >>p1
                        echo "Default UMASK value in skeleton files" >>p2
                        echo "File $i not exist on the server" >>p3
                        echo "yes" >>p4
                        echo "AD.1.9.1.7" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
done
rm -rf t1 temp temp1
#################################################################################
#AD.2.1.1,AD.2.1.2,AV.2.1.1.2,AV.2.1.1.3,AV.2.1.1.4,AV.1.7.2
ss=`cat /etc/ssh/sshd_config | grep ^Ciphers |wc -c`
if [ $ss -ne 0 ] ; then
	sl=`cat /etc/ssh/sshd_config | grep ^Ciphers | egrep -i 'des|64' |wc -c`
	if [ $sl -ne 0 ] ; then
		echo "Encryption" >>p1
		echo "Ciphers-value-in-file-/etc/ssh/sshd_config" >>p2
		echo "des-and-64-bit-algorithm-exist-in-ciphers" >>p3
		echo "no" >> p4
		echo "AD.2.1.1:AD.2.1.2:AV.2.1.1.2:AV.2.1.1.3:AV.2.1.1.4:AV.1.7.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
		echo "Encryption" >>p1
		echo "Ciphers-value-in-file-/etc/ssh/sshd_config" >>p2
		echo "des-and-64-bit-algorithm-not-exist-in-ciphers" >>p3
		echo "yes" >> p4
		echo "AD.2.1.1:AD.2.1.2:AV.2.1.1.2:AV.2.1.1.3:AV.2.1.1.4:AV.1.7.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	fi
else
		echo "Encryption" >>p1
		echo "Ciphers-value-in-file-/etc/ssh/sshd_config" >>p2
		echo "Ciphers-entry-doesnot-exist-in-/etc/ssh/sshd_config" >>p3
		echo "no" >> p4
		echo "AD.2.1.1:AD.2.1.2:AV.2.1.1.2:AV.2.1.1.3:AV.2.1.1.4:AV.1.7.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
fi
#####################################################################################
#AD.2.1.3.0:AD.2.1.3.1:AD.2.1.3.2:AD.2.1.3.3
grep ^password /etc/pam.d/* | egrep 'required|sufficient' | grep  pam_unix.so |awk -F: '{print $1}' > temp_pam.so
for i in `cat temp_pam.so` ; do
sk=`cat $i |egrep 'md5|sha512|sha256' |grep shadow |awk '{print $4}'`
  for sectionId in AD.2.1.3.0 AD.2.1.3.1 AD.2.1.3.2 ; do
	if [ [ $sk == 'md5' ] || [ $sk == 'sha512' ] || [ $sk == 'sha256'	] ] ; then
		echo "Encryption" >>p1
		echo "Password-EncryptionRequired" >>p2
		echo "$sk-and-shadow-is-set-in-file-$i" >>p3
		echo "yes" >>p4
	    echo $sectionId >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	else
		echo "Encryption" >>p1
		echo "Password-EncryptionRequired" >>p2
		echo "$sk-and-shadow-is-not-set-in-file-$i" >>p3
		echo "no" >>p4
	    echo $sectionId >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	fi
  done	
done
rm -rf temp_pam.so
########################################################################################
#IZ.1.1.4.2:AD.1.1.4.2:pam-settings
if [ -f /etc/pam.d/common-password ] ; then
	cat /etc/pam.d/common-password | grep "^password sufficient pam_unix_passwd.so remember='$PAM_REMEMBER' use_authtok sha512 shadow"
	if [ $? -eq 0 ] ; then
				echo "Password Requirements" >>p1
				echo "Prevent reuse of last eight passwords." >>p2
				echo "AD.1.1.4.2" >>p7
				echo "password_sufficient_pam_unix_sha512_exist" >> p3
				echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
	else
		if [ -f /etc/pam.d/login ] || [ -f /etc/pam.d/passwd ] || [ -f  /etc/pam.d/sshd ] || [ -f /etc/pam.d/su ] ; then	
			sa=`cat /etc/pam.d/login | grep -i "^password sufficient pam_unix.so remember='$PAM_REMEMBER' use_authtok sha512 shadow"`
			sb=`cat /etc/pam.d/passwd | grep -i "^password sufficient pam_unix.so remember='$PAM_REMEMBER' use_authtok sha512 shadow"`
			sc=`cat /etc/pam.d/sshd | grep -i "^password sufficient pam_unix.so remember='$PAM_REMEMBER' use_authtok sha512 shadow"`
			sd=`cat /etc/pam.d/su | grep -i "^password sufficient pam_unix.so remember='$PAM_REMEMBER' use_authtok sha512 shadow"`
			se=`echo $sa | wc -c`
			sf=`echo $sb | wc -c`
			sg=`echo $sc | wc -c`
			sh=`echo $sd | wc -c`
			if [ $sf == 0 ] || [ $se == 0 ] || [ $sg == 0 ] || [ $sh == 0 ] ; then
				echo "Password Requirements" >>p1
				echo "Prevent reuse of last eight passwords." >>p2
				echo "password_sufficient_pam_unix_sha512_exist" >> p3
				echo "yes" >>p4
				echo "AD.1.1.4.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
			else
				echo "Password Requirements" >>p1
				echo "Prevent reuse of last eight passwords." >>p2
				echo "password_sufficient_pam_unix_sha512_not_exist" >> p3
				echo "no" >>p4
				echo "AD.1.1.4.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4
			fi
		fi
	fi
else	
				echo "Password Requirements" >>p1
				echo "Prevent reuse of last eight passwords." >>p2
				echo "This-is-not-for-Redhat-Linux" >> p3
				echo "Not_Applicable" >>p4
				echo "AD.1.1.4.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4			
fi
#######################################################################################
#IZ.1.1.4.3:AD.1.1.4.3:pam-settings
if [ -f /etc/pam.d/common-password ] ; then
	cat /etc/pam.d/common-password | grep "^password sufficient pam_unix_passwd.so remember='$PAM_REMEMBER' use_authtok sha512 shadow"
	if [ $? -eq 0 ] ; then
				echo "Password Requirements" >>p1
				echo "pam.d_file_violation_/etc/pam.d/common-password" >>p2
				echo "AD.1.1.4.3" >>p7
				echo "password_sufficient_pam_unix_sha512_exist" >> p3
				echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
		if [ -f /etc/pam.d/login ] || [ -f /etc/pam.d/passwd ] || [ -f  /etc/pam.d/sshd ] || [ -f /etc/pam.d/su ] ; then	
			sa=`cat /etc/pam.d/login | grep -i "^password sufficient pam_unix.so remember='$PAM_REMEMBER' use_authtok sha512 shadow"`
			sb=`cat /etc/pam.d/passwd | grep -i "^password sufficient pam_unix.so remember='$PAM_REMEMBER' use_authtok sha512 shadow"`
			sc=`cat /etc/pam.d/sshd | grep -i "^password sufficient pam_unix.so remember='$PAM_REMEMBER' use_authtok sha512 shadow"`
			sd=`cat /etc/pam.d/su | grep -i "^password sufficient pam_unix.so remember='$PAM_REMEMBER' use_authtok sha512 shadow"`
			se=`echo $sa | wc -c`
			sf=`echo $sb | wc -c`
			sg=`echo $sc | wc -c`
			sh=`echo $sd | wc -c`
			if [ $sf == 0 ] || [ $se == 0 ] || [ $sg == 0 ] || [ $sh == 0 ] ; then
				echo "Password Requirements" >>p1
				echo "pam.d_file_violation_/etc/pam.d/common-password" >>p2
				echo "password_sufficient_pam_unix_sha512_exist" >> p3
				echo "yes" >>p4
				echo "AD.1.1.4.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
			else
				echo "Password Requirements" >>p1
				echo "pam.d_file_violation_/etc/pam.d/common-password" >>p2
				echo "password_sufficient_pam_unix_sha512_not_exist" >> p3
				echo "no" >>p4
				echo "AD.1.1.4.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
			fi
		fi
	fi
else	
				echo "Password Requirements" >>p1
				echo "pam.d_file_violation_/etc/pam.d/common-password" >>p2
				echo "This-is-not-for-Redhat-Linux" >> p3
				echo "Not_Applicable" >>p4
				echo "AD.1.1.4.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4				
fi
#######################################################################################
#IZ.1.1.4.4:AD.1.1.4.4:pam-settings
if [ -f /etc/pam.d/common-password ] ; then
	cat /etc/pam.d/common-password | grep "^password sufficient pam_unix.so remember='$PAM_REMEMBER' use_authtok sha512 shadow"
	if [ $? -eq 0 ] ; then
				echo "Password Requirements" >>p1
				echo "pam.d_file_violation_/etc/pam.d/common-password" >>p2
				echo "AD.1.1.4.4" >>p7
				echo "password_sufficient_pam_unix_sha512_exist" >> p3
				echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
		if [ -f /etc/pam.d/login ] || [ -f /etc/pam.d/passwd ] || [ -f  /etc/pam.d/sshd ] || [ -f /etc/pam.d/su ] ; then	
			sa=`cat /etc/pam.d/login | grep -i "^password sufficient pam_unix.so remember='$PAM_REMEMBER' use_authtok sha512 shadow"`
			sb=`cat /etc/pam.d/passwd | grep -i "^password sufficient pam_unix.so remember='$PAM_REMEMBER' use_authtok sha512 shadow"`
			sc=`cat /etc/pam.d/sshd | grep -i "^password sufficient pam_unix.so remember='$PAM_REMEMBER' use_authtok sha512 shadow"`
			sd=`cat /etc/pam.d/su | grep -i "^password sufficient pam_unix.so remember='$PAM_REMEMBER' use_authtok sha512 shadow"`
			se=`echo $sa | wc -c`
			sf=`echo $sb | wc -c`
			sg=`echo $sc | wc -c`
			sh=`echo $sd | wc -c`
			if [ $sf == 0 ] || [ $se == 0 ] || [ $sg == 0 ] || [ $sh == 0 ] ; then
				echo "Password Requirements" >>p1
				echo "pam.d_file_violation_/etc/pam.d/common-password" >>p2
				echo "password_sufficient_pam_unix_sha512_exist" >> p3
				echo "yes" >>p4
				echo "AD.1.1.4.4" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
			else
				echo "Password Requirements" >>p1
				echo "pam.d_file_violation_/etc/pam.d/common-password" >>p2
				echo "password_sufficient_pam_unix_sha512_not_exist" >> p3
				echo "no" >>p4
				echo "AD.1.1.4.4" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
			fi
		fi
	fi
else	
				echo "Password Requirements" >>p1
				echo "pam.d_file_violation_/etc/pam.d/common-password" >>p2
				echo "This-is-not-for-Redhat-Linux" >> p3
				echo "Not_Applicable" >>p4
				echo "AD.1.1.4.4" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4				 
fi
######################################################################################
#IZ.1.1.6.1:AD.1.1.6.1
if [ -f /etc/pam.d/common-auth ] ; then
	E=`cat  /etc/pam.d/common-auth | grep -i "pam_tally.so deny=5 onerr=fail per_user no_lock_time"`
	if [ $? -ne 0 ] ; then
		echo "Password Requirements" >>p1
		echo "loginretries" >>p2
		echo "Threshold for consecutive failed login attempts is set in /etc/pam.d/common-auth" >>p3
		echo "yes" >> p4
		echo "AD.1.1.6.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4		
	else
		echo "Password Requirements" >>p1
		echo "loginretries" >>p2
		echo "Threshold for consecutive failed login attempts is not set in /etc/pam.d/common-auth" >>p3
		echo "no" >> p4
		echo "AD.1.1.6.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
else
		echo "Password Requirements" >>p1
		echo "loginretries" >>p2
		echo "This is not for Redhat Linux" >>p3
		echo "Not_Applicable" >> p4
		echo "AD.1.1.6.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
########################################################################################
#IZ.1.1.8.1:AD.1.1.8.1
if [ "$SHARED_ID_VAULTED" == "yes" ] ; then
	echo "Password Requirements" >>p1
	echo "Requirement for controlling shared userids" >>p2
	echo "Shared ID's vaulted in tool" >>p3
	echo "yes" >>p4
	echo "AD.1.1.8.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
else
	echo "Password Requirements" >>p1
	echo "Requirement for controlling shared userids" >>p2
	echo "Shared ID's not vaulted in tool" >>p3
	echo "no" >>p4
	echo "AD.1.1.8.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
#######################################################################################
#IZ.1.1.8.3:AD.1.1.8.3:AD.1.1.8.3.1:IZ.1.1.8.3.1:GID-validation
cat /etc/group | awk -F":" '{print $3}'| sort  | uniq -cd | awk '{print $2}'> temp_gid
sp=`cat temp_gid | wc -c`
if [ "$sp" == 0 ] ; then
		echo "Password Requirements" >>p1
		echo "GID_validation" >>p2
		echo "No_duplicate_GID-value_for_users_in_/etc/group" >>p3
		echo "yes" >>p4
		echo "AD.1.1.8.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4		
else
		for i in `cat temp_gid` ; do
		echo "Password Requirements" >>p1
		echo "gid_validation" >>p2
		echo "Duplicate-gid-value-for-GID-$i in /etc/group" >>p3
		echo "no" >>p4
		echo "AD.1.1.8.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4		
		done
fi
#######################################################################################
#AD.1.1.13.1.1:IZ.1.1.13.1.1:pam-setting
Release=`cat /etc/redhat-release |awk '{print $1}'`
if [ "$Release" != "Red" ] ; then
	if [ -f /etc/pam.d/common-auth ] ; then
		E=`cat  /etc/pam.d/common-auth | grep "^auth required /lib/security/ISA/pam_listfile.so item=user sense=deny file=/etc/security/FILENAME onerr=succeed"`
		if [ $? -ne 0 ] ; then
			echo "Password Requirements" >>p1
			echo "Deny_access_file" >>p2
			echo "The value is not set" >>p3
			echo "no" >> p4
			echo "AD.1.1.13.1.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4		
		else
			echo "Password Requirements" >>p1
			echo "Deny_access_file" >>p2
			echo "The value is set" >>p3
			echo "yes" >> p4
			echo "AD.1.1.13.1.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
		fi
	else
			echo "Password Requirements" >>p1
			echo "Deny_access_file" >>p2
			echo "The file  /etc/pam.d/common-auth not found" >>p3
			echo "no" >> p4
			echo "AD.1.1.13.1.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
else
			echo "Password Requirements" >>p1
			echo "Deny_access_file" >>p2
			echo "This is not for Redhat Linux" >>p3
			echo "Not_Applicable" >> p4
			echo "AD.1.1.13.1.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
######################################################################################
#AD.1.2.1.1:Login success or failure
if [ -f /etc/syslog.conf ] ; then 
	cat  /etc/syslog.conf | egrep -i ".info;mail.none;authpriv.none;cron.none /var/log/messages"
	if [ $? -eq 0 ] ; then
		echo "Logging" >>p1
		echo "Login success or failure" >>p2
		echo "Entry-exist-in-/etc/syslog.conf" >>p3
		echo "yes" >>p4
		echo "AD.1.2.1.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
		echo "Logging" >>p1
		echo "Login success or failure" >>p2
		echo "Entry-not-exist-in-/etc/syslog.conf" >>p3
		echo "no" >>p4
		echo "AD.1.2.1.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
else
		echo "Logging" >>p1
		echo "Login success or failure" >>p2
		echo "Not_Applicable-for-Redhat6_and_7" >>p3
		echo "Not_Applicable" >>p4
		echo "AD.1.2.1.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
########################################################################################
#AD.1.2.1.2
Release=`cat /etc/redhat-release |awk '{print $1}'`
if [ "$Release" != "Red" ] ; then
cat /etc/syslog-ng/syslog-ng.conf | grep "authpriv.\*" | grep "/var/log/secure"
	if [ $? -eq 0 ] ; then 				
                echo "Logging" >>p1
				echo "Login success or failure" >>p2
				echo "/etc/syslog-ng/syslog-ng.conf found" >>p3
				echo "yes" >>p4
				echo "AD.1.2.1.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
				echo "Logging" >>p1
				echo "Login success or failure" >>p2
				echo "/etc/syslog-ng/syslog-ng.conf not found" >>p3
				echo "no" >>p4
				echo "AD.1.2.1.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
else
				echo "Logging" >>p1
				echo "Login success or failure" >>p2
				echo "/etc/syslog-ng/syslog-ng.conf-Not_Applicable-for-redhat-linux" >>p3
				echo "Not_Applicable" >>p4
				echo "AD.1.2.1.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
########################################################################################
#AD.1.2.1.3:AD.1.2.1.4:AD.1.2.1.4.2
Release=`cat /etc/redhat-release |awk '{print $1}'`
for sectionId in  AD.1.2.1.3 AD.1.2.1.4 ; do
if [ "$Release" == "Red" ] ; then
sk1=`cat /etc/rsyslog.conf | grep "^authpriv.\*" | grep "/var/log/secure" |wc -c`
sk2=`cat /etc/rsyslog.conf | grep "^*.info;mail.none;authpriv.none;cron.none" |grep /var/log/messages |wc -c`
	if [ "$sk1" -gt "0" ] || [ "$sk2" -gt "0" ] ; then
		skl=`cat /etc/rsyslog.conf | grep "authpriv.\*" | grep "/var/log/secure"`
		if [ $? -eq 0 ] ; then
				echo "Logging" >>p1
				echo "Login success or failure" >>p2
				echo "/etc/rsyslog.conf entry exist for '$skl'" >>p3
				echo "yes" >>p4
			    echo $sectionId >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	 			
		else
				echo "Logging" >>p1
				echo "Login success or failure" >>p2
				echo "/etc/rsyslog.conf entry missing for '$skl'" >>p3
				echo "no" >>p4
			    echo $sectionId >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
		fi
		skz=`cat /etc/rsyslog.conf | grep "*.info;mail.none;authpriv.none;cron.none" |grep /var/log/messages`
		if [ $? -eq 0 ] ; then
				echo "Logging" >>p1
				echo "Login success or failure" >>p2
				echo "/etc/rsyslog.conf entry exist for '$skz'" >>p3
				echo "yes" >>p4
			    echo $sectionId >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4		
		else
				echo "Logging" >>p1
				echo "Login success or failure" >>p2
				echo "/etc/rsyslog.conf entry not exist for '$skz'" >>p3
				echo "no" >>p4
			    echo $sectionId	 >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4		
		fi
	else
				echo "Logging" >>p1
				echo "Login success or failure" >>p2
				echo "/etc/rsyslog.conf entry not exist for '$skl' and '$$kz'" >>p3
				echo "no" >>p4
			    echo $sectionId >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4				
	fi
else
				echo "Logging" >>p1
				echo "Login success or failure" >>p2
				echo "Not for Redhat Linux" >>p3
				echo "Not_Applicable" >>p4
			    echo $sectionId >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
done
########################################################################################
#AD.1.2.1.5
Release=`cat /etc/os-release |grep ^ID= |cut -c4-9`
if [ "$Release" == "debian" ] ; then
sk1=`cat /etc/rsyslog.conf | grep "auth,authpriv.\*" | grep "/var/log/auth.log" |wc -c`
sk2=`cat /etc/rsyslog.conf | grep "*.*;auth,authpriv.none" |grep "-/var/log/syslog" |wc -c`
sk3=`cat /etc/rsyslog.conf | grep "*.=info;*.=notice;*.=warning; auth,authpriv.none; cron,daemon.none; mail,news.none" |grep "-/var/log/messages" |wc -c`
	if [ "$sk1" -gt "0" ] || [ "$sk2" -gt "0" ] || [ "$sk3" -gt "0" ] ; then
		skl=`cat /etc/rsyslog.conf | grep "auth,authpriv.\*" | grep "/var/log/auth.log"`
		if [ $? -eq 0 ] ; then
				echo "Logging" >>p1
				echo "Login success or failure" >>p2
				echo "/etc/rsyslog.conf entry exist for '$skl'" >>p3
				echo "yes" >>p4
				echo "AD.1.2.1.5" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
		else
				echo "Logging" >>p1
				echo "Login success or failure" >>p2
				echo "/etc/rsyslog.conf entry missing for '$skl'" >>p3
				echo "no" >>p4
				echo "AD.1.2.1.5" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
		fi
		skz=`cat /etc/rsyslog.conf | grep "*.*;auth,authpriv.none" |grep "-/var/log/syslog"`
		if [ $? -eq 0 ] ; then
				echo "Logging" >>p1
				echo "Login success or failure" >>p2
				echo "/etc/rsyslog.conf entry exist for '$skz'" >>p3
				echo "yes" >>p4
				echo "AD.1.2.1.5" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
		else
				echo "Logging" >>p1
				echo "Login success or failure" >>p2
				echo "/etc/rsyslog.conf entry not exist for '$skz'" >>p3
				echo "no" >>p4
				echo "AD.1.2.1.5" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4		
		fi
		skm=`cat /etc/rsyslog.conf | grep "*.=info;*.=notice;*.=warning; auth,authpriv.none; cron,daemon.none; mail,news.none" |grep "-/var/log/messages"`
		if [ $? -eq 0 ] ; then
				echo "Logging" >>p1
				echo "Login success or failure" >>p2
				echo "/etc/rsyslog.conf entry exist for '$skm'" >>p3
				echo "yes" >>p4
				echo "AD.1.2.1.5" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
		else
				echo "Logging" >>p1
				echo "Login success or failure" >>p2
				echo "/etc/rsyslog.conf entry not exist for '$skm'" >>p3
				echo "no" >>p4
				echo "AD.1.2.1.5" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4		
		fi
	else
				echo "Logging" >>p1
				echo "Login success or failure" >>p2
				echo "/etc/rsyslog.conf entry not exist for '$skl' and '$skz' and '$skm'" >>p3
				echo "no" >>p4
				echo "AD.1.2.1.5" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4			
	fi
else
				echo "Logging" >>p1
				echo "Login success or failure" >>p2
				echo "Not-for-Redhat-Linux" >>p3
				echo "Not_Applicable" >>p4
				echo "AD.1.2.1.5" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
#######################################################################################
#AD.1.2.3.2
szk=`cat /etc/redhat-release | awk '{print $1}'`
if [ "$szk" == "Red" ] ; then
	echo "Logging" >>p1
	echo "/var/log/syslog">>p2
	echo "Value-is-not-for-Redhat-Linux" >>p3
	echo "Not_Applicable" >>p4
        echo "AD.1.2.3.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
else
	str6=`ls -ld /var/log/syslog | awk '{print $1}' | cut -c9`
	if [ "$str6" != "w" ] ; then
		echo "Logging" >>p1
		echo "/var/log/syslog" >>p2
		echo "$str6" >> p3
		echo "yes" >>p4
		echo "AD.1.2.3.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
		echo "Logging" >>p1
		echo "/var/log/syslog" >>p2
		echo "$str6" >> p3
		echo "no" >>p4
		echo "AD.1.2.3.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
fi
#######################################################################################
#AD.1.2.4.0
sz=`cat /etc/redhat-release |awk '{print $7}'`
BC=`which bc`
if (( $($BC <<< "$sz<6") > 0 )) ; then
	sk=`which pam_tally`
	if [ $? -eq 0 ] ; then
		echo "Logging" >>p1
		echo "Use-of-pam_tally.so" >>p2
		echo "pam_tally.so-is-used" >> p3
		echo "yes" >>p4
		echo "AD.1.2.4.0" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
		echo "Logging" >>p1
		echo "Use-of-pam_tally.so" >>p2
		echo "pam_tally.so-is-not-used" >> p3
		echo "no" >>p4
		echo "AD.1.2.4.0" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
else
	sk=`which pam_tally2`
	if [ $? -eq 0 ] ; then
		echo "Logging" >>p1
		echo "Use-of-pam_tally2.so" >>p2
		echo "pam_tally2.so-is-used" >> p3
		echo "yes" >>p4
		echo "AD.1.2.4.0" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
		echo "Logging" >>p1
		echo "Use-of-pam_tally2.so" >>p2
		echo "pam_tally2.so-is-not-used" >> p3
		echo "no" >>p4
		echo "AD.1.2.4.0" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
fi
##################################################################################
#AD.1.2.4.1
sk=`which pam_tally2` 
if [ $? -ne 0 ] ; then
	if [ -f /var/log/faillog ] ; then
		echo "Logging" >>p1
		echo "/var/log/faillog" >>p2
		echo "File /var/log/faillog exist">>p3
		echo "yes" >>p4
		echo "AD.1.2.4.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
		echo "Logging" >>p1
		echo "/var/log/faillog" >>p2
		echo "missing-file-/var/log/faillog">>p3
		echo "no" >>p4
		echo "AD.1.2.4.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
else
	echo "Logging" >>p1
	echo "/var/log/faillog" >>p2
	echo "Not applicable as pam_tally2.so in used in PAM files">>p3
	echo "Not_Applicable" >>p4
	echo "AD.1.2.4.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
###################################################################################
#AD.1.2.6:logrotate
$serv rsyslog status
systemctl st
if [ $? -eq 0 ] ; then
	echo "Logging" >>p1
	echo "Log record retention time frame" >>p2
	echo "Rsyslog service is running" >>p3
	echo "AD.1.2.6">>p7
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
else
	echo "Logging" >>p1
	echo "Log record retention time frame" >>p2
	echo "Rsyslog service is not running. Please start the service by command #service rsylog start" >>p3
	echo "AD.1.2.6">>p7
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
sl=`sed -n '/# rotate/,/#.*keep*/p' /etc/logrotate.conf |grep -v '#' |egrep 'monthly|weekly'`
sn=`cat /etc/logrotate.conf |grep -v '#' |grep ^rotate |uniq  |awk '{print $2}'`
if [ $sl == weekly ] && [ $sn -ge $LOG_ROTATE_WEEK ] ; then
#sk=`cat /etc/logrotate.conf |grep -v "#" |grep -v include |grep rotate | sed -e 's/^[ \t]*//'`
#sn=`cat /etc/logrotate.conf |grep -v '#' |grep ^rotate |uniq  |awk '{print $2}'`
	echo "Logging" >>p1
        echo "Log record retention time frame" >>p2
	echo "Logrotate-set-as '$LOG_ROTATE_WEEK' weeks in-/etc/logrotate.conf-globally" >>p3
	echo "AD.1.2.6">>p7
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
else
	echo "Logging" >>p1
        echo "Log record retention time frame" >>p2
	echo "logrotate-is-not-set as '$LOG_ROTATE_WEEK' weeks in-/etc/logrotate.conf-globally" >>p3
	echo "AD.1.2.6">>p7
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
###### Logrotate setup for log files mentioned in /etc/logrotate.conf verification stanza #####
cat /etc/logrotate.conf |grep '/var/log' |sed -e 's/ {//g' |sed -e 's/\/var\/log\///g' >log_file1
for i in `cat log_file1` ; do
sed -n '/\/var\/log\/'$i'.*{/,/}/p' /etc/logrotate.conf |grep -v '#' >log_file2
sj1=`cat log_file2 |grep rotate |awk '{print $2}'`
sj2=`cat log_file2 |grep weekly |wc -c`
sj3=`cat log_file2 |grep monthly |wc -c`
if [[ $sj1 -ge $LOG_ROTATE_WEEK  &&  $sj2 -gt 1 ]] || [[ $sj1 -ge $LOG_ROTATE_MONTH  &&  $sj3 -gt 1 ]] ; then
		echo "Logging" >>p1
                echo "RetainLogFiles" >>p2
		echo "logrotate-is-set as correct for '/var/log/$i' in-/etc/logrotate.conf" >>p3
		echo "AD.1.2.6">>p7
		echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
else        
		echo "Logging" >>p1
                echo "RetainLogFiles" >>p2
		echo "logrotate-is-not-set as incorrect for '/var/log/$i' in-/etc/logrotate.conf" >>p3
		echo "AD.1.2.6">>p7
		echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
done
rm -rf log_file1 log_file2
################################################################################################
#AD.1.4.2,AD.1.4.2.1:filecheck
if [ "$(rpm -q ftp)" != "package ftp is not installed" ] || [ "$(rpm -q vsftpd)" != "package vsftpd is not installed" ] ; then
	aa=`cat /etc/ftpusers | grep -i ^root |wc -c`
	bb=`cat /etc/vsftpd.ftpusers | grep -i ^root |wc -c`
	cc=`cat /etc/vsftpd/ftpusers |grep -i ^root |wc -c`
	if [ $aa -gt 0 ] || [ $bb -gt 0 ] || [ $cc -gt 0 ] ; then
		echo "System Settings" >>p1
		echo "root-user-in-/etc/ftpusers-or-/etc/vsftpd.ftpusers-or-/etc/vsftp/ftpusers" >>p2
		echo "root_id_exist in /etc/ftpusers-or-/etc/vsftpd.ftpusers" >> p3
		echo "yes" >>p4
		echo "AD.1.4.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
		echo "System Settings" >>p1
		echo "root-user-in-/etc/ftpusers-or-/etc/vsftpd.ftpusers-or-/etc/vsftp/ftpusers" >>p2
		echo "root_id_not_exist" >> p3
		echo "no" >>p4
		echo "AD.1.4.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
else
	echo "System Settings" >>p1
	echo "root-user-in-/etc/ftpusers-or-/etc/vsftpd.ftpusers-or-/etc/vsftp/ftpusers" >>p2
	echo "FTP package is not installed on the server" >> p3
	echo "yes" >>p4
	echo "AD.1.4.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
#################################################################################################
#AD.1.4.3
cat /etc/passwd | awk -F":" '{print $1 " " $2}' > pasd_temp
while IFS= read -r line ; do
	line1=`echo $line | awk -F" " '{print $2}'`
	if [ "$line1" == "*" ] || [ "$line1" == "!" ] || [ "$line1" == "x" ] ; then
		echo "System Settings" >>p1
		echo "/etc/passwd-file-have-password-for-user" >>p2
		echo "password-not-assigned-in-/etc/passwd-for-user-$line" >> p3
		echo "yes" >>p4
		echo "AD.1.4.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else	
		echo "System Settings" >>p1
		echo "/etc/passwd-file-have-password-for-user" >>p2
		echo "password-assigned-in-/etc/passwd-for-user-with-$line" >> p3
		echo "no" >>p4
		echo "AD.1.4.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
done <pasd_temp
###############################################################################################
#AD.1.5.3.2
sl=`which service`
sl1=`$sl nfs status`
if [ $? -eq 0 ] && [ -f /etc/exports ] ; then
	pp=`which exportfs`
	sk=`$pp |grep "<world>" |awk '{print $1}' |wc -c`
	if [ $sk -ne 0 ] ; then
	/usr/sbin/exportfs |grep "<world>" |awk '{print $1}' >>ff2
	for i in `cat ff2` ; do
		echo "Network Settingss" >>p1
		echo "Network file system (nfs) settings" >>p2
		echo "NFS is shared to World for FS $i" >> p3
		echo "no" >>p4
		echo "AD.1.5.3.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	 
	done
	else
		echo "Network Settingss" >>p1
		echo "Network file system (nfs) settings" >>p2
		echo "No files shared to world in NFS" >> p3
		echo "yes" >>p4
		echo "AD.1.5.3.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
else
if [ -f /etc/exports ] ; then
	pp=`which exportfs`
	sk=`$pp |grep "<world>" |awk '{print $1}' |wc -c`
	if [ $sk -ne 0 ] ; then
	/usr/sbin/exportfs |grep "<world>" |awk '{print $1}' >>ff2
	for i in `cat ff2` ; do
		echo "Network Settingss" >>p1
		echo "Network file system (nfs) settings" >>p2
		echo "NFS is shared to World for FS $i" >> p3
		echo "no" >>p4
		echo "AD.1.5.3.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	done
	else
		echo "Network Settingss" >>p1
		echo "Network file system (nfs) settings" >>p2
		echo "No files shared to world in NFS" >> p3
		echo "yes" >>p4
		echo "AD.1.5.3.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
else
		echo "Network Settingss" >>p1
		echo "Network file system (nfs) settings" >>p2
		echo "NFS is not running and file /etc/exports not exist" >> p3
		echo "yes" >>p4
		echo "AD.1.5.3.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
fi
##########################################################################################
#AD.1.5.6
sl=`which service`
sl1=`$sl nntpd status`
if [ $? -eq 0 ] ; then
	sp=`timeout 10s openssl s_client -connect www.google.com:443 2>/dev/null | head -3 |grep CONNECTED |wc -l`
	if [ $sp -gt 0 ] ; then
		echo "Network Settings" >>p1
		echo "NNTP authentication and identification" >>p2
		echo "Internet is enabled and nntpd service is running. Manual intervention required to check newsgroups on the server for NNTP" >>p3
		echo "Manual_Check_Required to see if any New transfer settings on the server" >>p4
		echo "AD.1.5.6" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
		echo "Network Settings" >>p1
		echo "NNTP authentication and identification" >>p2
		echo "NNTPD service is running, but internet is disasbled" >>p3
		echo "yes" >>p4
		echo "AD.1.5.6" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
else
	echo "Network Settings" >>p1
	echo "NNTP authentication and identification" >>p2
	echo "NNTPD service is not running on the server" >>p3
	echo "yes" >>p4
	echo "AD.1.5.6" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
###########################################################################################
#AD.1.5.8.1,AD.1.5.8.2,AD.1.5.8.3,AD.1.5.8.4,AD.1.5.8.5,AD.1.5.8.6,AD.1.5.8.7,AD.1.5.8.8,AD.1.5.9.1,AD.1.5.9.2,AD.1.5.9.3,AD.1.5.9.4,AD.1.5.9.5,AD.1.5.9.6,AD.1.5.9.7,AD.1.5.9.8,AD.1.5.9.9,AD.1.5.9.10,AD.1.5.9.11,AD.1.5.9.12,AD.1.5.9.13,AD.1.5.9.14,AD.1.5.9.15,AD.1.5.9.16,AD.1.5.9.17
sp=`which service`
sy=`$sp xinetd status`
if [ $? -eq 0 ] ; then
	sk=`ls /etc/xinetd.d |wc -l`
	if [ $sk -gt 0 ] ; then
	ls -ltr /etc/xinetd.d/ |grep -v "nrpe" |awk '{print $9}' |grep -v '^$' >xinetd_file
	for i in `cat xinetd_file` ; do
		sj=`cat /etc/xinetd.d/$i |grep -v '#' |grep disable |awk -F= '{print $2}' |sed -e 's/ //g'`
		if [ "$sj" == "yes" ] ; then
			echo "Network Settings" >>p1
			echo "Denial of Service through xinetd or inetd" >>p2
			echo "Service $i is disabled in /etc/xinetd.d" >>p3
			echo "yes" >>p4
			echo "AD.1.5.8.1:AD.1.5.8.2:AD.1.5.8.3:AD.1.5.8.4:AD.1.5.8.5:AD.1.5.8.6:AD.1.5.8.7:AD.1.5.8.8:AD.1.5.9.1:AD.1.5.9.2:AD.1.5.9.3:AD.1.5.9.4:AD.1.5.9.5:AD.1.5.9.6:AD.1.5.9.7:AD.1.5.9.8:AD.1.5.9.9:AD.1.5.9.10:AD.1.5.9.11:AD.1.5.9.12:AD.1.5.9.13:AD.1.5.9.14:AD.1.5.9.15:AD.1.5.9.16:AD.1.5.9.17" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
		else
			echo "Network Settings" >>p1
			echo "Denial of Service through xinetd or inetd" >>p2
			echo "Service $i is enabled in /etc/xinetd.d" >>p3
			echo "no" >>p4
			echo "AD.1.5.8.1:AD.1.5.8.2:AD.1.5.8.3:AD.1.5.8.4:AD.1.5.8.5:AD.1.5.8.6:AD.1.5.8.7:AD.1.5.8.8:AD.1.5.9.1:AD.1.5.9.2:AD.1.5.9.3:AD.1.5.9.4:AD.1.5.9.5:AD.1.5.9.6:AD.1.5.9.7:AD.1.5.9.8:AD.1.5.9.9:AD.1.5.9.10:AD.1.5.9.11:AD.1.5.9.12:AD.1.5.9.13:AD.1.5.9.14:AD.1.5.9.15:AD.1.5.9.16:AD.1.5.9.17" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
		fi
	done
	else
			echo "Network Settings" >>p1
			echo "Denial of Service through xinetd or inetd" >>p2
			echo "No service available in /etc/xinetd.d" >>p3
			echo "yes" >>p4
			echo "AD.1.5.8.1:AD.1.5.8.2:AD.1.5.8.3:AD.1.5.8.4:AD.1.5.8.5:AD.1.5.8.6:AD.1.5.8.7:AD.1.5.8.8:AD.1.5.9.1:AD.1.5.9.2:AD.1.5.9.3:AD.1.5.9.4:AD.1.5.9.5:AD.1.5.9.6:AD.1.5.9.7:AD.1.5.9.8:AD.1.5.9.9:AD.1.5.9.10:AD.1.5.9.11:AD.1.5.9.12:AD.1.5.9.13:AD.1.5.9.14:AD.1.5.9.15:AD.1.5.9.16:AD.1.5.9.17" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
else
			echo "Network Settings" >>p1
			echo "Denial of Service through xinetd or inetd" >>p2
			echo "xinetd service is not running" >>p3
			echo "yes" >>p4
			echo "AD.1.5.8.1:AD.1.5.8.2:AD.1.5.8.3:AD.1.5.8.4:AD.1.5.8.5:AD.1.5.8.6:AD.1.5.8.7:AD.1.5.8.8:AD.1.5.9.1:AD.1.5.9.2:AD.1.5.9.3:AD.1.5.9.4:AD.1.5.9.5:AD.1.5.9.6:AD.1.5.9.7:AD.1.5.9.8:AD.1.5.9.9:AD.1.5.9.10:AD.1.5.9.11:AD.1.5.9.12:AD.1.5.9.13:AD.1.5.9.14:AD.1.5.9.15:AD.1.5.9.16:AD.1.5.9.17" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
rm -rf xinetd_file
################################################################################################
#AD.1.5.9.18;AD.1.5.9.19;AD.1.5.9.18.1;AD.1.5.9.18.2;AD.1.5.9.18.3
sl=`which service`
sl1=`$sl snmpd status`
if [ $? -eq 0 ] ; then
sk=`cat /etc/snmp/snmpd.conf |grep ^rocommunity |grep -i public |wc -l`
sk1=`cat /etc/snmp/snmpd.conf |grep ^rwcommunity |grep -i public |wc -l`
sp=`cat /etc/snmp/snmpd.conf |grep ^rocommunity |grep -i private |wc -l`
sp1=`cat /etc/snmp/snmpd.conf |grep ^rwcommunity |grep -i private |wc -l`
	if [ $sk -gt 0 ] || [ $sk1 -gt 0 ] || [ $sp -gt 0 ] || [ $sp1 -gt 0 ] ; then
		echo "Network Settings" >>p1
		echo "SNMP Service" >>p2
		echo "snmpd-daemon-is-running and public/private community has read/write in /etc/snmp/snmpd.conf" >>p3
		echo "no" >>p4
		echo "AD.1.5.9.18:AD.1.5.9.19" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
		echo "Network Settings" >>p1
		echo "SNMP Service" >>p2
		echo "snmpd-daemon-is-running but public/private community not there in /etc/snmp/snmpd.conf" >>p3
		echo "yes" >>p4
		echo "AD.1.5.9.18:AD.1.5.9.19" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
else
		echo "Network Settings" >>p1
		echo "SNMP Service" >>p2
		echo "snmpd-daemon-is-not-running" >>p3
		echo "yes" >>p4
		echo "AD.1.5.9.18:AD.1.5.9.19" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
########################################################################################
#AD.1.5.9.20;AD.1.5.9.20.1
stp=`cat /etc/sysctl.conf |grep ^net.ipv4.tcp_syncookies |awk -F"=" '{print $2}' |sed -e 's/ //g'`
if [ "$stp" == "1" ] ; then
		echo "Network Settingss" >>p1
 		echo "/etc/sysctl.conf" >>p2
		echo "Correct-setting-net.ipv4.tcp_syncookies = 1 in /etc/sysctl.conf" >>p3
		echo "yes" >>p4
		echo 'AD.1.5.9.20' >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
else
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "Incorrect-value-set-for-net.ipv4.tcp_syncookies-in-/etc/sysctl.conf" >> p3
	echo "no" >>p4	
	echo 'AD.1.5.9.20' >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
#####################################################################################
#AD.1.5.9.21;AD.1.5.9.20.2
stm=`cat /etc/sysctl.conf |grep ^net.ipv4.icmp_echo_ignore_broadcasts |awk -F"=" '{print $2}' |sed -e 's/ //g'`
if [ "$stm" == "1" ] ; then
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "Correct-setting-net.ipv4.icmp_echo_ignore_broadcasts=1-in-/etc/sysctl.conf" >>p3
	echo 'AD.1.5.9.21' >>p7
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
else
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "net.ipv4.icmp_echo_ignore_broadcasts=1_is_not_set-in-/etc/sysctl.conf" >>p3
	echo "no" >>p4
	echo 'AD.1.5.9.21' >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4		
fi
###################################################################################
#AD.1.5.9.22;AD.1.5.9.20.3
stn=`cat /etc/sysctl.conf |grep ^net.ipv4.conf.all.accept_redirects |awk -F"=" '{print $2}' |sed -e 's/ //g'`
if [ "$stn" == "0" ] ; then
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "Correct-setting-net.ipv4.conf.all.accept_redirects=0-in-/etc/sysctl.conf" >>p3
	echo "yes" >>p4
	echo 'AD.1.5.9.22' >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
else
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "net.ipv4.conf.all.accept_redirects=0_is_not_set-in-/etc/sysctl.conf" >>p3
	echo "no" >>p4
	echo 'AD.1.5.9.22' >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4		
fi
###################################################################################
#AD.1.5.9.24
sl=`which service`
sl1=`$sl vsftpd status`
if [ $? -eq 0 ] ; then
	echo "Network Settings" >>p1
	echo "ftp-service" >>p2
	echo "ftp-is-enabled" >>p3
	echo "no" >>p4
	echo "AD.1.5.9.24" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
else
	echo "Network Settings" >>p1
	echo "ftp-service" >>p2
	echo "ftp-is-disabled" >>p3
	echo "yes" >>p4
	echo "AD.1.5.9.24" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
##################################################################################
#AD.1.5.10.2:AD.1.5.11
sz=`rpm -q ypserv ypbind portmap yp-tools`
if [ $? -eq 0 ] ; then
	sl=`which service`
	sl1=`$sl ypserv status`
	if [ $? -eq 0 ] ; then
		echo "Network Settings" >>p1
		echo "NIS and NIS+ maps" >>p2
		echo "NIS-is-enabled_verify-the-map-files" >>p3
		echo "no" >>p4
		echo "AD.1.5.11" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
		echo "Network Settings" >>p1
		echo "NIS and NIS+ maps" >>p2
		echo "NIS-is-disabled" >>p3
		echo "yes" >>p4
		echo "AD.1.5.11" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
else
		echo "Network Settings" >>p1
		echo "NIS and NIS+ maps" >>p2
		echo "NIS packages not installed" >>p3
		echo "yes" >>p4
		echo "AD.1.5.11" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
#################################################################################
#AD.1.5.12.2
if [ -f /etc/xinetd.d/rlogin ] ; then
sz=`cat /etc/xinetd.d/rlogin |grep disable |awk -F= '{print $2}'`
sl=`cat /etc/securetty | grep rlogin`
	if [ "$sz" == "no" ] || [ "$sl" == "0" ] ; then
		echo "Network Settings" >>p1
		echo "rlogin" >>p2
		echo "rlogin-is-enabled" >>p3
		echo "no" >>p4
		echo "AD.1.5.12.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
		echo "Network Settings" >>p1
		echo "rlogin" >>p2
		echo "rlogin-is-disabled" >>p3
		echo "yes" >>p4
		echo "AD.1.5.12.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
else
		echo "Network Settings" >>p1
		echo "rlogin" >>p2
		echo "rlogin-is-not-enabled" >>p3
		echo "yes" >>p4
		echo "AD.1.5.12.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
##################################################################################
#AD.1.5.12.3
if [ -f /etc/xinetd.d/rsh ] ; then
sz=`cat /etc/xinetd.d/rsh |grep disable |awk -F= '{print $2}'`
sl=`cat /etc/securetty | grep rsh`
	if [ "$sz" == "no" ] || [ $sl -eq 0 ] ; then
		echo "Network Settings" >>p1
		echo "rlogin" >>p2
		echo "rsh-is-enabled" >>p3
		echo "no" >>p4
		echo "AD.1.5.12.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
		echo "Network Settings" >>p1
		echo "rlogin" >>p2
		echo "rsh-is-disabled" >>p3
		echo "yes" >>p4
		echo "AD.1.5.12.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
else
		echo "Network Settings" >>p1
		echo "rlogin" >>p2
		echo "rsh-is-not-enabled" >>p3
		echo "yes" >>p4
		echo "AD.1.5.12.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
##################################################################################
#AD.1.8.3.2
str=`ls -ld /usr |awk '{print $1}' |cut -c9`
if [ "$str" == "w" ] ; then
		echo "Protecting Resources - OSRs" >>p1
		echo "/usr-dir-permission" >>p2
		echo "/usr-dir-is-writtable-by-others" >>p3
		echo "no" >>p4
		echo "AD.1.8.3.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
else
		echo "Protecting Resources - OSRs" >>p1
		echo "/usr-dir-permission" >>p2
		echo "/usr-dir-permission-is-correctly-set" >>p3
		echo "yes" >>p4
		echo "AD.1.8.3.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
##################################################################################
#AD.1.8.4.2
str=$(stat -c "%a %n" /etc/shadow |awk '{print $1}')
if [ "$str" == "600" ] || [ "$str" == "0" ] ; then
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/shadow-permission" >>p2
		echo "/etc/shadow-permission-is-correctly-set" >>p3
		echo "yes" >>p4
		echo "AD.1.8.4.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/shadow-permission" >>p2
		echo "/etc/shadow-permission-is-incorrect" >>p3
		echo "no" >>p4
		echo "AD.1.8.4.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
########################################################################################
#AD.1.8.12.5
sk=`which pam_tally2`
if [ $? -ne 0 ] ; then
	sz=`cat /etc/redhat-release |awk '{print $7}'`
	BC=`which bc`
	if (( $($BC <<< "$sz<7") > 0 )) ; then
		sk=`ls -l /var/log/auth.log |awk '{print $4}'`
		sj=`getent group $sk |awk -F: '{print $3}'`
		if [ $sj -le 99 ] || [[ $sj -ge 101 && $sj -le 499 ]] ; then
			ss1=`find /var/log/auth.log -type f -perm /g+r |wc -l`
			ss2=`find /var/log/auth.log -type f -perm /g+w |wc -l`
			if [ $ss1 -gt 0 ] || [ $ss2 -gt 0 ] ; then
				echo "Protecting Resources - OSRs" >>p1
				echo "/var/log/auth.log-Group Read-Write access" >>p2
				echo "/var/log/auth.log has correct permission and owned by priviledged group ID" >> p3
				echo "Yes" >>p4
				echo "AD.1.8.12.5" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
			else
				echo "Protecting Resources - OSRs" >>p1
				echo "/var/log/auth.log-Group Read-Write access" >>p2
				echo "/var/log/auth.log has incorrect permission and not owned by priviledged group ID" >> p3
				echo "no" >>p4
				echo "AD.1.8.12.5" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
			fi
		else
			echo "Protecting Resources - OSRs" >>p1
			echo "/var/log/auth.log-Group Read-Write access" >>p2
			echo "/var/log/auth.log not owned by priviledged group ID" >> p3
			echo "no" >>p4
			echo "AD.1.8.12.5" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
		fi
	else
	if (( $($BC <<< "$sz>=7") > 0 )) ; then
		sk=`ls -l /var/log/auth.log |awk '{print $4}'`
		sj=`getent group $sk |awk -F: '{print $3}'`
		if [ $sj -le 99 ] || [[ $sj -ge 101 && $sj -le 999 ]] ; then
			ss1=`find /var/log/auth.log -type f -perm /g+r |wc -l`
			ss2=`find /var/log/auth.log -type f -perm /g+w |wc -l`
			if [ $ss1 -gt 0 ] || [ $ss2 -gt 0 ] ; then
				echo "Protecting Resources - OSRs" >>p1
				echo "/var/log/auth.log-Group Read-Write access" >>p2
				echo "/var/log/auth.log has correct permission and owned by priviledged group ID" >> p3
				echo "Yes" >>p4
				echo "AD.1.8.12.5" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
			else
				echo "Protecting Resources - OSRs" >>p1
				echo "/var/log/auth.log-Group Read-Write access" >>p2
				echo "/var/log/auth.log has incorrect permission and not owned by priviledged group ID" >> p3
				echo "no" >>p4
				echo "AD.1.8.12.5" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
			fi
		else
			echo "Protecting Resources - OSRs" >>p1
			echo "/var/log/auth.log-Group Read-Write access" >>p2
			echo "/var/log/auth.log not owned by priviledged group ID" >> p3
			echo "no" >>p4
			echo "AD.1.8.12.5" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
		fi
	else
			echo "Protecting Resources - OSRs" >>p1
			echo "/var/log/auth.log-Group Read-Write access" >>p2
			echo "Not applicable as it is not for RHEL6 or RHEL7" >> p3
			echo "Not_Applicable" >>p4
			echo "AD.1.8.12.5" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi	
	fi
else			
			echo "Protecting Resources - OSRs" >>p1
			echo "/var/log/auth.log-Group Read-Write access" >>p2
			echo "Not applicable as pam_tally2 is in use" >> p3
			echo "Not_Applicable" >>p4
			echo "AD.1.8.12.5" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
########################################################################################
#AD.1.8.13.2
sk=`cat /etc/inittab |grep -v '#' |grep -v '^$' |awk -F: '{print $4}' |wc -l`
if [ $sk -gt 0 ] ; then
cat /etc/inittab |grep -v '#' |grep -v '^$' |awk -F: '{print $4}' >t1
while IFS= read -r line ; do
        sk1=`echo $line |awk '{print $1}' |cut -c 1`
        if [ "$sk1" == "/" ] ; then
                echo "Protecting Resources - OSRs" >>p1
                echo "/etc/inittab" >>p2
		echo "Full-path-is-specified-for-command- $line in-/etc/inittab" >>p3
		echo "AD.1.8.13.2" >>p7
		echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
	if [ "$sk1" == "" ] ; then
                echo "Protecting Resources - OSRs" >>p1
                echo "/etc/inittab" >>p2
		echo "Value_is_set_as_null_in-4th_field_of_/etc/inittab" >>p3
		echo "yes" >>p4
		echo "AD.1.8.13.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
		echo "Protecting Resources - OSRs" >>p1
                echo "/etc/inittab" >>p2
		echo "Full-path-is-not-specified-for-command- $line in-/etc/inittab" >>p3
		echo "no" >>p4
		echo "AD.1.8.13.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
        fi
	fi
done <t1
else
		echo "Protecting Resources - OSRs" >>p1
                echo "/etc/inittab" >>p2
		echo "No system facility entries exist in-/etc/inittab" >>p3
		echo "yes" >>p4
		echo "AD.1.8.13.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
rm -rf t1
#######################################################################################
#AD.1.8.13.3;AD.1.8.13.4
sk=`cat /etc/inittab |grep -v '#' |grep -v '^$' |awk -F: '{print $4}' |wc -l`
if [ $sk -gt 0 ] ; then
cat /etc/inittab |grep -v '#' |grep -v '^$' |awk -F: '{print $4}' |awk '{print $1}' >t1
while IFS= read -r line ; do
	str=`find $line -type f -perm /o+w \! -perm -1000 |wc -l`
	if [ $str -eq 0 ] ; then
                echo "Protecting Resources - OSRs" >>p1
                echo "/etc/inittab" >>p2
		echo "Permission for others in $line in /etc/inittab is valid" >>p3
		echo "AD.1.8.13.3:AD.1.8.13.4" >>p7
		echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
                echo "Protecting Resources - OSRs" >>p1
                echo "/etc/inittab" >>p2
		echo "Permission for others in $line in /etc/inittab is invalid" >>p3
		echo "no" >>p4
		echo "AD.1.8.13.3:AD.1.8.13.4" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
done <t1
else
		echo "Protecting Resources - OSRs" >>p1
                echo "/etc/inittab" >>p2
		echo "No system facility entries exist in-/etc/inittab" >>p3
		echo "yes" >>p4
		echo "AD.1.8.13.3:AD.1.8.13.4" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
rm -rf t1
#########################################################################################
#AD.1.8.17.1
if [ -f /etc/xinetd.conf ] ; then
	sk=`cat /etc/xinetd.conf |grep -v '#' |grep includedir |awk '{print $2}' |wc -l`
	if [ $sk -gt 0 ] ; then
	cat /etc/xinetd.conf |grep -v '#' |grep includedir |awk '{print $2}' >t1
	while IFS= read -r line ; do
        	sk1=`echo $line |cut -c 1`
        	if [ "$sk1" == "/" ] ; then
		        echo "Protecting Resources - OSRs" >>p1
		        echo "/etc/xinetd.conf" >>p2
			echo "Full-path-is-specified-for $line in-/etc/xinetd.conf" >>p3
			echo "AD.1.8.17.1" >>p7
			echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
		else
		        echo "Protecting Resources - OSRs" >>p1
		        echo "/etc/xinetd.conf" >>p2
			echo "Full-path-is-specified-for $line in-/etc/xinetd.conf" >>p3
			echo "AD.1.8.17.1" >>p7
			echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
        	fi
	done <t1
	else
		echo "Protecting Resources - OSRs" >>p1
                echo "/etc/xinetd.conf" >>p2
		echo "No system facility entries exist in-/etc/xinetd.conf" >>p3
		echo "yes" >>p4
		echo "AD.1.8.13.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
else
		echo "Protecting Resources - OSRs" >>p1
                echo "/etc/xinetd.conf" >>p2
		echo "Not-Applicable-as-file-/etc/xinetd.conf-not-exist" >>p3
		echo "AD.1.8.17.1" >>p7
		echo "Not_Applicable" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
###########################################################################################
#AD.1.8.17.2;AD.1.8.17.3
if [ -f /etc/xinetd.conf ] ; then
	sk=`cat /etc/xinetd.conf |grep -v '#' |grep includedir |awk '{print $2}' |wc -l`
	if [ $sk -gt 0 ] ; then
	cat /etc/xinetd.conf |grep -v '#' |grep includedir |awk '{print $2}' >t1
	while IFS= read -r line ; do
        	str=`ls -ld $line |awk '{print $1}' |cut -c9`
		if [ "$str" != "w" ] ; then
		        echo "Protecting Resources - OSRs" >>p1
		        echo "/etc/xinetd.conf" >>p2
			echo "Permission for others in $line in /etc/xinetd.conf is valid" >>p3
			echo "AD.1.8.17.2:AD.1.8.17.3" >>p7
			echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
		else
		        echo "Protecting Resources - OSRs" >>p1
		        echo "/etc/xinetd.conf" >>p2
			echo "Permission for others in $line in /etc/xinetd.conf is invalid" >>p3
			echo "AD.1.8.17.2:AD.1.8.17.3" >>p7
			echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
        	fi
	done <t1
	else
		echo "Protecting Resources - OSRs" >>p1
                echo "/etc/xinetd.conf" >>p2
		echo "No system facility entries exist in-/etc/xinetd.conf" >>p3
		echo "yes" >>p4
		echo "AD.1.8.17.2:AD.1.8.17.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
else
		echo "Protecting Resources - OSRs" >>p1
                echo "/etc/xinetd.conf" >>p2
		echo "Not-Applicable-as-file-/etc/xinetd.conf-not-exist" >>p3
		echo "Not_Applicable" >>p4
		echo "AD.1.8.17.2:AD.1.8.17.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4		
fi
rm -rf t1
################################################################################################
#AD.1.8.21.1
if [ -f /var/spool/cron/tabs/root ] ; then
		echo "Protecting Resources - OSRs" >>p1
		echo "/var/spool/cron/tabs/root" >>p2
		echo "/var/spool/cron/tabs/root-file-exist" >> p3
		echo "yes" >>p4
		echo "AD.1.8.21.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
else
		echo "Protecting Resources - OSRs" >>p1
		echo "/var/spool/cron/tabs/root" >>p2
		echo "/var/spool/cron/tabs/root-file-not-exist" >> p3
		echo "Not_Applicable" >>p4
		echo "AD.1.8.21.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
###############################################################################################
#AD.2.0.1
if [ -f /etc/motd ] || [ -f /etc/issue ] ; then
	str=`cat /etc/motd |wc -c`
	if [ "$str" -gt "0" ] ; then
		echo "Business Use Notice" >>p1
		echo "Business Use Notice exists" >>p2
		echo "Business use notice mentioned in /etc/motd" >> p3
		echo "yes" >>p4
		echo "AD.2.0.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else 
		echo "Business Use Notice" >>p1
		echo "Business Use Notice exists" >>p2
		echo "Business use notice not mentioned in /etc/motd" >> p3
		echo "no" >>p4
		echo "AD.2.0.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
else
		echo "Business Use Notice" >>p1
		echo "Business_use_notice_entry_not_exist_in_file_/etc/motd" >>p2
		echo "/etc/motd_or_/etc/issue_file_not_exist" >> p3
		echo "no" >>p4
		echo "AD.2.0.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
###############################################################################################
#AD.2.1.4
cat /etc/passwd | egrep -v "/sbin/nologin|sync|shutdown|halt|/bin/false" | awk -F":" '{print $1}' > temp_id
for i in `cat temp_id` ; do
sp=`ls -ld /home/$i/.ssh/*.pub |wc -l`
if [ $sp -gt 1 ] ; then
	if [ -f /home/$i/.ssh/id_rsa.pub ] ; then
		A=`id $i | awk '{print $1}' | awk -F"(" '{print $2}' | awk -F")" '{print $1}'`
		sk=`ls -lrt /home/$i/.ssh/id_rsa.pub | awk '{print $3}'`
		skm=$(stat -c "%a %n" /home/$i/.ssh/id_rsa.pub |awk '{print $1}')
		if [ "$A" == "$sk" ] ; then
			echo "Encryption" >>p1
			echo "Protection of private keys" >>p2
			echo "Correct ownership-for-user-$i-is-$sk-for-/home/$i/.ssh/id_rsa.pub" >>p3
			echo "yes" >>p4
			echo "AD.2.1.4" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
		else
			echo "Encryption" >>p1
			echo "Protection of private keys" >>p2
			echo "Incorrect ownership-for-user-$i-is-$sk-for-/home/$i/.ssh/id_rsa.pub" >>p3
			echo "no" >>p4
			echo "AD.2.1.4" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
		fi
		if [ "$skm" == "600" ] ; then
			echo "Encryption" >>p1
			echo "Protection of private keys" >>p2
			echo "Correct permission for file /home/$i/.ssh/id_rsa.pub-and-permission-is-600" >>p3
			echo "yes" >>p4
			echo "AD.2.1.4" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
		else
			echo "Encryption" >>p1
			echo "Protection of private keys" >>p2
			echo "Incorrect permission for file /home/$i/.ssh/id_rsa.pub-and-permission-is-not-600" >>p3
			echo "no" >>p4
			echo "AD.2.1.4" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
		fi
	fi
	if [ -f /home/$i/.ssh/id_dsa.pub ] ; then
		A=`id $i | awk '{print $1}' | awk -F"(" '{print $2}' | awk -F")" '{print $1}'`
		sk=`ls -lrt /home/$i/.ssh/id_dsa.pub | awk '{print $3}'`
		skm=$(stat -c "%a %n" /home/$i/.ssh/id_dsa.pub |awk '{print $1}')
		if [ "$A" == "$sk" ] ; then
			echo "Encryption" >>p1
			echo "Protection of private keys" >>p2
			echo "Correct ownership-for-user-$i-is-$sk-for-/home/$i/.ssh/id_dsa.pub" >>p3
			echo "yes" >>p4
			echo "AD.2.1.4" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
		else
			echo "Encryption" >>p1
			echo "Protection of private keys" >>p2
			echo "Incorrect ownership-for-user-$i-is-$sk-for-/home/$i/.ssh/id_dsa.pub" >>p3
			echo "no" >>p4
			echo "AD.2.1.4" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
		fi
		if [ "$skm" == "600" ] ; then
			echo "Encryption" >>p1
			echo "Protection of private keys" >>p2
			echo "Correct permission for file /home/$i/.ssh/id_dsa.pub-and-permission-is-600" >>p3
			echo "yes" >>p4
			echo "AD.2.1.4" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
		else
			echo "Encryption" >>p1
			echo "Protection of private keys" >>p2
			echo "Correct permission for file /home/$i/.ssh/id_dsa.pub-and-permission-is-not-600" >>p3
			echo "no" >>p4
			echo "AD.2.1.4" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
		fi
	fi
else
	if [ -f /home/$i/.ssh/id_rsa.pub ] ; then
		A=`id $i | awk '{print $1}' | awk -F"(" '{print $2}' | awk -F")" '{print $1}'`
		sk=`ls -lrt /home/$i/.ssh/id_rsa.pub | awk '{print $3}'`
		skm=$(stat -c "%a %n" /home/$i/.ssh/id_rsa.pub |awk '{print $1}')
		if [ "$A" == "$sk" ] ; then
			echo "Encryption" >>p1
			echo "Protection of private keys" >>p2
			echo "Correct ownership-for-user-$i-is-$sk-for-/home/$i/.ssh/id_rsa.pub" >>p3
			echo "yes" >>p4
			echo "AD.2.1.4" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
		else
			echo "Encryption" >>p1
			echo "Protection of private keys" >>p2
			echo "Incorrect ownership-for-user-$i-is-$sk-for-/home/$i/.ssh/id_rsa.pub" >>p3
			echo "no" >>p4
			echo "AD.2.1.4" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
		fi
		if [ "$skm" == "600" ] ; then
			echo "Encryption" >>p1
			echo "Protection of private keys" >>p2
			echo "Correct permission for file /home/$i/.ssh/id_rsa.pub-and-permission-is-600" >>p3
			echo "yes" >>p4
			echo "AD.2.1.4" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
		else
			echo "Encryption" >>p1
			echo "Protection of private keys" >>p2
			echo "Incorrect permission for file /home/$i/.ssh/id_rsa.pub-and-permission-is-not-600" >>p3
			echo "no" >>p4
			echo "AD.2.1.4" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
		fi
	else
	if [ -f /home/$i/.ssh/id_dsa.pub ] ; then
		A=`id $i | awk '{print $1}' | awk -F"(" '{print $2}' | awk -F")" '{print $1}'`
		sk=`ls -lrt /home/$i/.ssh/id_dsa.pub | awk '{print $3}'`
		skm=$(stat -c "%a %n" /home/$i/.ssh/id_dsa.pub |awk '{print $1}')
		if [ "$A" == "$sk" ] ; then
			echo "Encryption" >>p1
			echo "Protection of private keys" >>p2
			echo "Correct ownership-for-user-$i-is-$sk-for-/home/$i/.ssh/id_dsa.pub" >>p3
			echo "yes" >>p4
			echo "AD.2.1.4" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
		else
			echo "Encryption" >>p1
			echo "Protection of private keys" >>p2
			echo "Incorrect ownership-for-user-$i-is-$sk-for-/home/$i/.ssh/id_dsa.pub" >>p3
			echo "no" >>p4
			echo "AD.2.1.4" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
		fi
		if [ "$skm" == "600" ] ; then
			echo "Encryption" >>p1
			echo "Protection of private keys" >>p2
			echo "Correct permission for file /home/$i/.ssh/id_dsa.pub-and-permission-is-600" >>p3
			echo "yes" >>p4
			echo "AD.2.1.4" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
		else
			echo "Encryption" >>p1
			echo "Protection of private keys" >>p2
			echo "Inorrect permission for file /home/$i/.ssh/id_dsa.pub. It should be 600" >>p3
			echo "no" >>p4
			echo "AD.2.1.4" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
		fi
	else
			echo "Encryption" >>p1
			echo "Protection of private keys" >>p2
			echo "No public key exist for user $i in /home/$i/.ssh/" >>p3
			echo "yes" >>p4
			echo "AD.2.1.4" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
	fi
fi
done
rm -rf temp_id
################################################################################################
#IZ.1.1.12.1:AD.1.1.12.1:2nd field of /etc/shadow
for i in `cat /etc/passwd | egrep -v "/sbin/nologin|sync|shutdown|halt|/bin/false" | awk -F":" '{print $1}'` ; do
	sk=`passwd -S $i |awk '{print $2}'`
	if [ "$sk" == "NP" ] ; then
			echo "Password Requirements" >>p1
                	echo "Copy of passwd file containing the encrypted passwords" >>p2
			echo "The ID $i has no password set" >>p3
			echo "AD.1.1.12.1" >>p7
			echo "no" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
			echo "$timestamp" >>en4	
	else
	if [ "$sk" == "LK" ] ; then
		sk3=`chage -l $i | grep "Password expires" |sed -e 's/://' | awk '{ print $3}'`
		if [ "$sk3" == "never" ] ; then
			echo "Password Requirements" >>p1
                	echo "Copy of passwd file containing the encrypted passwords" >>p2
			echo "The id $i is a locked account but password is set as never expire" >>p3
			echo "AD.1.1.12.1" >>p7
			echo "no" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
			echo "$timestamp" >>en4	
		else
			echo "Password Requirements" >>p1
            echo "Copy of passwd file containing the encrypted passwords" >>p2
			echo "The id $i is a locked account and password is set as expire" >>p3
			echo "AD.1.1.12.1" >>p7
			echo "yes" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
			echo "$timestamp" >>en4	
		fi
	else
	if [ "$sk" == "PS" ] ; then
		sk1=`passwd -S $i |awk '{print $11}' |cut -c1-5`
		if [ "$sk1" == "crypt" ] ; then
			echo "Password Requirements" >>p1
            echo "Copy of passwd file containing the encrypted passwords" >>p2
			echo "The id $i has encrypted password settings" >>p3
			echo "AD.1.1.12.1" >>p7
			echo "yes" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
			echo "$timestamp" >>en4	
		else
			echo "Password Requirements" >>p1
            echo "Copy of passwd file containing the encrypted passwords" >>p2
			echo "The id $i has non-encrypted password settings" >>p3
			echo "AD.1.1.12.1" >>p7
			echo "no" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
			echo "$timestamp" >>en4	
		fi
	fi
	fi
	fi
done
##############################################################################################
#AD.1.2.7.1:IZ.1.2.7.1:Logging
sl=`whereis service | awk '{print $2}'`
A=`$sl ntpd status |wc -c`
B=`$sl chronyd status |wc -c`
if [ $A -gt 0 ] ; then
		echo "Logging" >>p1
                echo "Synchronized system clocks - ensure it is active" >>p2
		echo "ntpd-is-running" >>p3
		echo "AD.1.2.7.1">>p7
		echo "yes" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
			echo "$timestamp" >>en4
else
	if [ $B -gt 0 ] ; then
		echo "Logging" >>p1
                echo "Synchronized system clocks - ensure it is active" >>p2
		echo "chronyd-is-running" >>p3
		echo "AD.1.2.7.1">>p7
		echo "yes" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
			echo "$timestamp" >>en4
	else
		echo "Logging" >>p1
                echo "Synchronized system clocks - ensure it is active" >>p2
		echo "ntpd-chronyd-is-not-running" >>p3
		echo "AD.1.2.7.1" >>p7
		echo "no" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
			echo "$timestamp" >>en4
	fi
fi
###################################################################################################
#AD.1.2.7.2:IZ.1.2.7.2:Logging
sl=`whereis service | awk '{print $2}'`
A=`$sl ntpd status |wc -c`
B=`$sl chronyd status |wc -c`
if [ $B -gt 0 ] ; then
	val1=`/usr/bin/chronyc tracking |grep "Leap status" |awk -F: '{print $2}' |sed -e 's/ //g'`
	if [ "$val1" == "Normal" ] ; then
		echo "Logging" >>p1
		echo "Synchronized system clocks - chronyd has a server" >>p2
		echo "chronyd-is-active and time-is-synchronised" >>p3
		echo "AD.1.2.7.2" >>p7
		echo "yes" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
			echo "$timestamp" >>en4
	else
		echo "Logging" >>p1
		echo "Synchronized system clocks - chronyd has a server" >>p2
		echo "chronyd-is-active but time-is-not-synchronised" >>p3
		echo "AD.1.2.7.2">>p7
		echo "no" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
			echo "$timestamp" >>en4
	fi
elif [ $A -gt 0 ]; then
	val2=`/usr/bin/ntpstat tracking |grep "Leap status" |awk -F: '{print $2}' |sed -e 's/ //g'`
	if [ "$val2" == "Normal" ] ; then
		echo "Logging" >>p1
		echo "Synchronized system clocks - chronyd has a server" >>p2
		echo "ntpd-is-configured and time-is-synchronised" >>p3
		echo "AD.1.2.7.2">>p7
		echo "yes" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
			echo "$timestamp" >>en4
	else
		echo "Logging" >>p1
		echo "Synchronized system clocks - chronyd has a server" >>p2
		echo "ntp-is-not-configured" >>p3
		echo "AD.1.2.7.2">>p7
		echo "no" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
			echo "$timestamp" >>en4
	fi
else
		echo "Logging" >>p1
		echo "Synchronized system clocks - chronyd has a server" >>p2
		echo "ntp-and-chronyd-is-not-configured" >>p3
		echo "AD.1.2.7.2">>p7
		echo "no" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
			echo "$timestamp" >>en4
fi
################################################################################################
#AD.1.2.7.3:IZ.1.2.7.3:Logging
ps -ef |grep chronyd |grep -v "grep"
if [ $? -eq 0 ] ; then
	sl=`ps -ef |grep chronyd |grep -v "grep" |awk '{print $1}'`
	if [ "$sl" == "chrony" ] ; then
		echo "Logging" >>p1
                echo "Synchronized system clocks - chronyd does not have excess privilege" >>p2
		echo "The task is running as chrony ID" >>p3
		echo "AD.1.2.7.3">>p7
		echo "yes" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
			echo "$timestamp" >>en4
	else
		echo "Logging" >>p1
                echo "Synchronized system clocks - chronyd does not have excess privilege" >>p2
		echo "The task is not running as chrony ID" >>p3
		echo "AD.1.2.7.3">>p7
		echo "no" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
			echo "$timestamp" >>en4
	fi
else
		echo "Logging" >>p1
                echo "Synchronized system clocks - chronyd does not have excess privilege" >>p2
		echo "Chrony service is not active" >>p3
		echo "AD.1.2.7.3">>p7
		echo "Yes" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
			echo "$timestamp" >>en4
fi
#######################################################################################################
#AD.1.2.7.4:IZ.1.2.7.4Logging
sl=`whereis service | awk '{print $2}'`
A=`$sl ntpd status |wc -c`
B=`$sl chronyd status |wc -c`
if [ $A -gt 0 ] ; then
	val1=`cat /etc/ntp.conf |grep 'restrict default kod nomodify notrap nopeer noquery' |wc -c`
	val2=`cat /etc/ntp.conf |grep 'restrict -6 default kod nomodify notrap nopeer noquery' |wc -c`
	if [ $val1 -gt 0 ] || [ $val2 -gt 0 ] ; then
		echo "Logging" >>p1
        	echo "Synchronized system clocks - ntpd has secure defaults" >>p2
		echo "ntpd-is-active and key-defaults-for-both-ip4-and-ip6-is-set" >>p3
		echo "AD.1.2.7.4">>p7
		echo "yes" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
			echo "$timestamp" >>en4
	else
		echo "Logging" >>p1
        	echo "Synchronized system clocks - ntpd has secure defaults" >>p2
		echo "ntpd-is-active but key-defaults-for-both-ip4-and-ip6-is-not-set" >>p3
		echo "AD.1.2.7.4">>p7
		echo "no" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
			echo "$timestamp" >>en4
	fi
else
	if [ $B -gt 0 ] ; then
		echo "Logging" >>p1
        	echo "Synchronized system clocks - ntpd has secure defaults" >>p2
		echo "chrony-is-configured" >>p3
		echo "AD.1.2.7.4">>p7
		echo "yes" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
			echo "$timestamp" >>en4
	else
		echo "Logging" >>p1
        	echo "Synchronized system clocks - ntpd has secure defaults" >>p2
		echo "chrony-is-not-configured" >>p3
		echo "AD.1.2.7.4">>p7
		echo "no" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
			echo "$timestamp" >>en4
	fi
fi
########################################################################################################
#AD.1.2.7.5:IZ.1.2.7.5:Logging
sl=`whereis service | awk '{print $2}'`
A=`$sl ntpd status |wc -c`
B=`$sl chronyd status |wc -c`
if [ $A -gt 0 ] ; then
	val1=`/usr/bin/ntpstat`
	if [ $? -eq 0 ] ; then
		echo "Logging" >>p1
        	echo "Synchronized system clocks - ntpd has a server" >>p2
		echo "ntpd-is-active and time-is-synchronised" >>p3
		echo "AD.1.2.7.5">>p7
		echo "yes" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
			echo "$timestamp" >>en4
	else
		echo "Logging" >>p1
        	echo "Synchronized system clocks - ntpd has a server" >>p2
		echo "ntpd-is-active but time-is-not-synchronised" >>p3
		echo "AD.1.2.7.5">>p7
		echo "no" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
			echo "$timestamp" >>en4
	fi
else
	val2=`/usr/bin/chronyc tracking |grep "Leap status" |awk -F: '{print $2}' |sed -e 's/ //g'`
	if [ $B -gt 0 ] && [ "$val2" == "Normal" ] ; then
		echo "Logging" >>p1
        	echo "Synchronized system clocks - ntpd has a server" >>p2
		echo "chrony-is-configured and time-is-synchronised" >>p3
		echo "AD.1.2.7.5">>p7
		echo "yes" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
			echo "$timestamp" >>en4
	else
		echo "Logging" >>p1
        	echo "Synchronized system clocks - ntpd has a server" >>p2
		echo "chrony-is-not-configured" >>p3
		echo "AD.1.2.7.5">>p7
		echo "no" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
			echo "$timestamp" >>en4
	fi
fi
#######################################################################################################################
#AD.1.4.3.1
Release=`cat /etc/redhat-release |awk '{print $1}'`
if [ "$Release" == "Red" ] ; then

	count=`rpm -qa libselinux | awk -F'-' '{print $1}'|wc -l`

	if [ $count -gt 0 ] ; then
		echo "system-settings" >>p1
		echo "SELINUX-package status" >>p2
		echo "SELinux is installed" >>p3
		echo "yes" >>p4
		echo "AD.1.4.3.1" >>p7
			echo "$c" >> p5
			echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
			echo "$timestamp" >>en4
	else
		echo "system-settings" >>p1
		echo "SELINUX-package status" >>p2
		echo "SELinux is not installed" >>p3
		echo "no" >>p4
		echo "AD.1.4.3.1" >>p7
			echo "$c" >> p5
			echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
			echo "$timestamp" >>en4
	fi
else
				echo "System-Settings" >>p1
				echo "Ensure the SELinux state is enforcing or permissive" >>p2
				echo "It is not for Redhat Linux" >>p3
				echo "no" >>p4
				echo "AD.1.4.3.1" >>p7
			echo "$c" >> p5
			echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
			echo "$timestamp" >>en4
fi

############################################################################################################
#AD.1.4.3.2
Release=`cat /etc/redhat-release |awk '{print $1}'`
if [ "$Release" == "Red" ] ; then
	A=`getenforce`
	B=`cat /etc/selinux/config |grep ^SELINUX= |awk -F= '{print $2}'`
	if [ "$A" == "Enforcing" ] || [ "$A" == "Permissive" ] && [ "$B" == "enforcing" ] || [ "$B" == "permissive" ] ; then
				echo "System-Settings" >>p1
				echo "Ensure the SELinux state is enforcing or permissive" >>p2
				echo "$B-set-in-file-/etc/selinux/config" >>p3	
				echo "yes" >>p4
				echo "AD.1.4.3.2" >>p7
			echo "$c" >> p5
			echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
			echo "$timestamp" >>en4
	else
				echo "System-Settings" >>p1
				echo "Ensure the SELinux state is enforcing or permissive" >>p2
				echo "$B-set-in-file-/etc/selinux/config" >>p3
				echo "no" >>p4
				echo "AD.1.4.3.2" >>p7
			echo "$c" >> p5
			echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
			echo "$timestamp" >>en4	
	fi
else
				echo "System-Settings" >>p1
				echo "Ensure the SELinux state is enforcing or permissive" >>p2
				echo "It is not for Redhat Linux" >>p3
				echo "no" >>p4
				echo "AD.1.4.3.2" >>p7
			echo "$c" >> p5
			echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
			echo "$timestamp" >>en4
fi
####################################################################################################
#IZ.1.1.2.2:AD.1.1.2.2:2nd field of /etc/passwd
allNull=()
noNull=()
cat /etc/passwd | awk -F":" '{print $1}' >temp_passwd
for i in `cat temp_passwd` ; do
	sk1=`cat /etc/passwd |grep -w ^$i |awk -F: '{print $2}'`
	if [ "$sk1" == "" ] ; then
		allNull+=("$i")
	else
		noNull+=("$i")
	fi
done
allNull=$(IFS=, ; echo "${allNull[*]}")
noNull=$(IFS=, ; echo "${noNull[*]}")
if [ "$allNull" != "" ] ; then
	echo "Password Requirements" >>p1
    echo "second field of /etc/passwd" >>p2
	echo "The second field /etc/passwd is set as null for id '$allNull'" >>p3
	echo "no" >>p4
	echo "AD.1.1.2.2" >>p7
			echo "$c" >> p5
			echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
			echo "$timestamp" >>en4
fi
if [ "$noNull" != "" ] ; then
	echo "Password_requirement" >>p1
    echo "second field of /etc/passwd" >>p2
	echo "The second field /etc/passwd is not set as null for id '$noNull'" >>p3
	echo "AD.1.1.2.2" >>p7
	echo "yes" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
			echo "$timestamp" >>en4
fi
rm -rf temp_passwd
###########################################################################################
#AD.1.4.4.1:AD.1.4.4.2:AD.1.4.3.1.1
Release=`cat /etc/redhat-release |awk '{print $1}'`
if [ "$Release" == "Red" ] ; then
	echo "System-Settings" >>p1
	echo "Ensure AppArmor is installed if preferred over SELinux" >>p2
	echo "This is not for Redhat Linux" >>p3	
	echo "Not_Applicable" >>p4
	echo "AD.1.4.4.1:AD.1.4.4.2" >>p7
			echo "$c" >> p5
			echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
			echo "$timestamp" >>en4
else
	echo "System-Settings" >>p1
	echo "Ensure AppArmor is installed if preferred over SELinux" >>p2
	echo "Manual check is required to verify in AppArmor package is installed" >>p3
	echo "no" >>p4
	echo "AD.1.4.4.1:AD.1.4.4.2" >>p7	
			echo "$c" >> p5
			echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
			echo "$timestamp" >>en4
fi

##################################################################################################################################

########################################################################################

################# SSH #################################################################

#######################################################################################
#AV.1.1.1
sk=`cat /etc/ssh/sshd_config | grep -i "^PermitEmptyPasswords" |uniq |wc -l`
if [ $sk -gt 0 ] ; then
  sz=`cat /etc/ssh/sshd_config | grep -i "^PermitEmptyPasswords" | awk '{print $2}' |uniq`
  if [ "$sz" == "$PERMITEMPTYPASSWORDS" ] ; then
		echo "Password Requirements" >>p1
        echo "PermitEmptyPasswords" >>p2
		echo "PermitEmptyPasswords is set as \"$sz\" in /etc/ssh/sshd_config" >> p3
		echo "yes" >>p4
		echo "AV.1.1.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
  else
		echo "Password Requirements" >>p1
        echo "PermitEmptyPasswords" >>p2
		echo "Value-is-not-set" >> p3
        echo "no" >>p4
		echo "AV.1.1.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
  fi
else
  sz=`cat /etc/ssh/sshd_config | grep -i "^#PermitEmptyPasswords" | awk '{print $2}' |uniq`
  if [ "$sz" == "$PERMITEMPTYPASSWORDS" ] ; then
		echo "Password Requirements" >>p1
        echo "PermitEmptyPasswords" >>p2
		echo "PermitEmptyPasswords is set as \"$sz\" in /etc/ssh/sshd_config" >> p3
		echo "yes" >>p4
		echo "AV.1.1.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
  else
		echo "Password Requirements" >>p1
        echo "PermitEmptyPasswords" >>p2
		echo "Value-is-not-set" >> p3
        echo "no" >>p4
		echo "AV.1.1.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
  fi
fi
###########################################################################
#AV.1.1.2;AV.1.1.3;AV.1.2.3.1;AV.1.2.3.2 ;AV.1.2.3.3;AV.1.2.3.4 ;AV.1.2.3.5;AV.1.2.3.6;AV.1.2.4.1;AV.1.2.4.2;AV.1.2.4.3;AV.1.2.4.4;AV.1.4.6;AV.1.4.7;AV.1.4.9 ;AV.1.4.10;AV.1.4.11;AV.1.4.12;AV.1.4.13;AV.1.4.15 ;AV.1.4.16;AV.1.4.17;AV.1.4.18;AV.1.5.3;AV.1.5.4;AV.1.5.6;AV.1.5.7;AV.1.8.4.1;AV.1.8.4.2;AV.1.8.4.3;AV.1.8.4.4;AV.1.8.4.5;AV.1.8.4.6;AV.1.8.4.7;AV.1.8.5.1;AV.1.8.5.2;AV.1.8.5.3;AV.1.8.5.4;AV.1.8.5.5;AV.1.8.5.6;AV.1.8.5.7;AV.1.8.5.8;AV.1.8.5.10;AV.1.8.5.11;AV.1.8.5.12;AV.1.8.5.13;AV.1.8.5.14;AV.2.0.1.2;AV.2.0.1.3;AV.2.0.1.4;AV.2.1.1.5;AV.2.1.1.6;AV.2.1.1.7;AV.2.2.1.1;AV.2.2.1.2;AV.2.2.1.3;AV.2.2.1.4
	echo "Windows SSH Requirements" >>p1
	echo "SSH Parameter-Windows" >>p2
	echo "These parameters are for Windows" >>p3
	echo "Not_Applicable" >>p4
	echo "AV.1.1.2:AV.1.1.3:AV.1.2.3.1:AV.1.2.3.2:AV.1.2.3.3:AV.1.2.3.4:AV.1.2.3.5:AV.1.2.3.6:AV.1.2.4.1:AV.1.2.4.2:AV.1.2.4.3:AV.1.2.4.4:AV.1.4.6:AV.1.4.7:AV.1.4.9:AV.1.4.10:AV.1.4.11:AV.1.4.12:AV.1.4.13:AV.1.4.15:AV.1.4.16:AV.1.4.17:AV.1.4.18:AV.1.5.3:AV.1.5.4:AV.1.5.6:AV.1.5.7:AV.1.8.4.1:AV.1.8.4.2:AV.1.8.4.3:AV.1.8.4.4:AV.1.8.4.5:AV.1.8.4.6:AV.1.8.4.7:AV.1.8.5.1:AV.1.8.5.2:AV.1.8.5.3:AV.1.8.5.4:AV.1.8.5.5:AV.1.8.5.6:AV.1.8.5.7:AV.1.8.5.8:AV.1.8.5.10:AV.1.8.5.11:AV.1.8.5.12:AV.1.8.5.13:AV.1.8.5.14:AV.2.0.1.2:AV.2.0.1.3:AV.2.0.1.4:AV.2.1.1.5:AV.2.1.1.6:AV.2.1.1.7" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
############################################################################
#AV.1.1.6,AV.1.1.7
cat /etc/passwd | awk -F":" '{print $1}' > temp_id
for i in `cat temp_id`
do
	if [ -f /home/$i/.ssh/authorized_keys ]
	then
		A=`id $i | awk '{print $1}' | awk -F"(" '{print $2}' | awk -F")" '{print $1}'`
		B=`id $i | awk '{print $2}' | awk -F"(" '{print $2}' | awk -F")" '{print $1}'`
		sk=`ls -lrt /home/$i/.ssh/id_rsa.pub | awk '{print $3}'`
		sl=`ls -lrt /home/$i/.ssh/id_dsa.pub | awk '{print $4}'`
		if [ "$A" == "$sk" ]
		then
				echo "Password Requirements" >>p1
				echo "Private Key Passphrases - system-to-system authentication" >>p2
				echo "Private-key-is-owned-by-correct-group" >>p3
				echo "yes" >>p4
				echo "AV.1.1.6:AV.1.1.7" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
		else
			if [ "$B" == "$sl" ] 
			then
				echo "Password Requirements" >>p1
				echo "Private Key Passphrases - system-to-system authentication" >>p2
				echo "ownership-for-/home/$i/.ssh/authorized_keys-is-$sk:$sl" >>p3
				echo "yes" >>p4
				echo "AV.1.1.6:AV.1.1.7" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
			fi
		fi
	else
				echo "Password Requirements" >>p1
				echo "Private Key Passphrases - system-to-system authentication" >>p2
				echo "/home/$i/.ssh/authorized_keys-doesnt-exist" >>p3
				echo "yes" >>p4
				echo "AV.1.1.6:AV.1.1.7" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
done
rm -rf 	temp_id	
############################################################################
#AV.1.2.1.2,AV.1.2.1.3
sk=`cat /etc/ssh/sshd_config | grep -i "^LogLevel" |uniq |wc -l`
if [ $sk -gt 0 ] ; then
  sk=`cat /etc/ssh/sshd_config | grep -i "^LogLevel" | awk '{print $2}' |uniq`
  if [ "$sk" == "INFO" ] || [ "$sk" == "DEBUG" ] ; then
		echo "Logging" >>p1
        	echo "LogLevel" >>p2
		echo "LogLevel-set-as \"$sk\" in /etc/ssh/sshd_config" >> p3
		echo "yes" >>p4
		echo "AV.1.2.1.2:AV.1.2.1.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
  else
		echo "Logging" >>p1
        	echo "LogLevel" >>p2
		echo "LogLevel-should-be-set-as-INFO" >> p3
                echo "no" >>p4
		echo "AV.1.2.1.2:AV.1.2.1.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
  fi
else
  sk=`cat /etc/ssh/sshd_config | grep -i "^#LogLevel" | awk '{print $2}' |uniq`
  if [ "$sk" == "INFO" ] || [ "$sk" == "DEBUG" ] ; then
		echo "Logging" >>p1
        	echo "LogLevel" >>p2
		echo "LogLevel-set-as \"$sk\" in /etc/ssh/sshd_config" >> p3
		echo "yes" >>p4
		echo "AV.1.2.1.2:AV.1.2.1.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
  else
		echo "Logging" >>p1
        	echo "LogLevel" >>p2
		echo "LogLevel-should-be-set-as-INFO" >> p3
                echo "no" >>p4
		echo "AV.1.2.1.2:AV.1.2.1.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
  fi
fi
######################################################################

#AV.1.2.2
sz=`rpm -qa |grep -i ssh |grep -i openssh-[0-9].[0-9] | cut -c1,2,3,4,5,6,7`
if [ "$sz" == "openssh" ] ; then
		echo "Logging" >>p1
		echo "QuietMode" >>p2
		echo "Not applicable for OpenSSH" >>p3
		echo "Not_Applicable" >>p4
		echo "AV.1.2.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
else
	szl=`cat /etc/ssh/sshd_config | grep -i "^QuietMode" | awk '{print $2}' |uniq`
	if [ "$szl" == "no" ] ; then
		echo "Logging" >>p1
		echo "QuietMode" >>p2
		echo "$szl" >>p3
		echo "yes" >>p4
		echo "AV.1.2.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
		echo "Logging" >>p1
		echo "QuietMode" >>p2
		echo "Value-is-not-set" >>p3
		echo "no" >>p4
		echo "AV.1.2.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
fi
#########################################################################
#AV.1.4.1
sz=`rpm -qa |grep -i ssh |grep -i openssh-[0-9].[0-9] | cut -c1,2,3,4,5,6,7,8,9,10,11`
szk=`echo $sz | awk -F"-" '{print $2}'`
BC=`which bc`
if (( $($BC <<< "$szk<=3.7") > 0 )) ; then
	sk=`cat /etc/ssh/sshd_config | grep -i "^KeepAlive" | awk '{print $2}' |uniq |wc -l`
	if [ $sk -gt 0 ] ; then
	szl=`cat /etc/ssh/sshd_config | grep -i "^KeepAlive" | awk '{print $2}' |uniq`
	if [ "$szl" == "yes" ] ; then
		echo "SystemSettings" >>p1
		echo "KeepAlive" >>p3
		echo "KeepAlive_$szl" >>p3
		echo "yes" >>p4
		echo "AV.1.4.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
		echo "SystemSettings" >>p1
		echo "KeepAlive" >>p2
		echo "KeepAlive_$szl" >>p3
		echo "no" >>p4
		echo "AV.1.4.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
	else
		echo "SystemSettings" >>p1
		echo "KeepAlive" >>p2
		echo "KeepAlive value is set" >>p3
		echo "yes" >>p4
		echo "AV.1.4.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
else
		echo "SystemSettings" >>p1
		echo "KeepAlive" >>p2
		echo "Applicable-only-for-openssh-versions-3.7-or-less" >>p3
		echo "Not_Applicable" >>p4
		echo "AV.1.4.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
#######################################################################
#AV.1.4.2
sz=`rpm -qa |grep -i ssh |grep -i openssh-[0-9].[0-9] | cut -c1,2,3,4,5,6,7,8,9,10,11`
szk=`echo $sz | awk -F"-" '{print $2}'`
BC=`which bc`
if (( $($BC <<< "$szk>=3.8") > 0 )) ; then
   sk=`cat /etc/ssh/sshd_config | grep -i "^TCPKeepAlive" |uniq |wc -l`
   if [ $sk -gt 0 ] ; then
	szl=`cat /etc/ssh/sshd_config | grep -i "^TCPKeepAlive" | awk '{print $2}' |uniq`
	if [ "$szl" == "$TCPKEEPALIVE" ] ; then
		echo "System Settings" >>p1
		echo "TCPKeepAlive" >>p2
		echo "Value is set as \"$szl\" in /etc/ssh/sshd_config" >>p3
		echo "yes" >>p4
		echo "AV.1.4.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
		echo "System Settings" >>p1
		echo "TCPKeepAlive" >>p2
		echo "TCPKeepAlive Value-is-not-set in /etc/ssh/sshd_config" >>p3
		echo "no" >>p4
		echo "AV.1.4.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
   else
	szl=`cat /etc/ssh/sshd_config | grep -i "^#TCPKeepAlive" | awk '{print $2}' |uniq`
	if [ "$szl" == "$TCPKEEPALIVE" ] ; then
		echo "System Settings" >>p1
		echo "TCPKeepAlive" >>p2
		echo "Value is set as \"$szl\" in /etc/ssh/sshd_config" >>p3
		echo "yes" >>p4
		echo "AV.1.4.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
		echo "System Settings" >>p1
		echo "TCPKeepAlive" >>p2
		echo "TCPKeepAlive Value-is-not-set in /etc/ssh/sshd_config" >>p3
		echo "no" >>p4
		echo "AV.1.4.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
    fi
else
		echo "SystemSettings" >>p1
		echo "TCPKeepAlive" >>p2
		echo "Applicable-only-for-openssh-versions-3.8-and-greater" >>p3
		echo "Not_Applicable" >>p4
		echo "AV.1.4.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
######################################################################
#AV.1.4.3
sk=`cat /etc/ssh/sshd_config | grep -i "^LoginGraceTime" |uniq |wc -l`
if [ $sk -gt 0 ] ; then
	szl=`cat /etc/ssh/sshd_config | grep -i "^LoginGraceTime" | awk '{print $2}' |uniq`
	if [ "$szl" -le "$LOGINGRACETIME" ] || [ "$szl" == "2m" ] ; then
		echo "System Settings" >>p1
		echo "LoginGraceTime" >>p2
		echo "Value is set as \"$szl\" in /etc/ssh/sshd_config" >>p3
		echo "yes" >>p4
		echo "AV.1.4.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
		echo "System Settings" >>p1
		echo "LoginGraceTime" >>p2
		echo "Value-is-not-set in /etc/ssh/sshd_config" >>p3
		echo "no" >>p4
		echo "AV.1.4.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
else
	szl=`cat /etc/ssh/sshd_config | grep -i "^#LoginGraceTime" | awk '{print $2}' |uniq`
	if [ "$szl" -le "$LOGINGRACETIME" ] || [ "$szl" == "2m" ] ; then
		echo "System Settings" >>p1
		echo "LoginGraceTime" >>p2
		echo "Value is set as \"$szl\" in /etc/ssh/sshd_config" >>p3
		echo "yes" >>p4
		echo "AV.1.4.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
		echo "System Settings" >>p1
		echo "LoginGraceTime" >>p2
		echo "Value-is-not-set in /etc/ssh/sshd_config" >>p3
		echo "no" >>p4
		echo "AV.1.4.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
fi
###################################################################
#AV.1.4.4
sz=`rpm -qa |grep -i ssh |grep -i openssh-[0-9].[0-9] | cut -c1,2,3,4,5,6,7`
if [ "$sz" != "openssh" ] ; then
	sk=`cat /etc/ssh/sshd_config | grep -i "^MaxConnections" |uniq |wc -l`
	if [ $sk -gt 0 ] ; then
	szl=`cat /etc/ssh/sshd_config | grep -i "^MaxConnections" | awk '{print $2}' |uniq | awk 'FNR  == 1'`
	if [ "$szl" <= "100" ] ; then
		echo "System Settings" >>p1
		echo "MaxConnections" >>p2
		echo "$szl" >>p3
		echo "yes" >>p4
		echo "AV.1.4.4" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
		echo "System Settings" >>p1
		echo "MaxConnections" >>p2
		echo "Value-is-not-set" >>p3
		echo "no" >>p4
		echo "AV.1.4.4" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
	else
		echo "System Settings" >>p1
		echo "MaxConnections" >>p2
		echo "Value-is-set" >>p3
		echo "yes" >>p4
		echo "AV.1.4.4" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
else
		echo "System Settings" >>p1
		echo "MaxConnections" >>p2
		echo "Not Applicable-for-OpenSSH" >>p3
		echo "Not_Applicable" >>p4
		echo "AV.1.4.4" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
#########################################################################
#AV.1.4.5
sk=`cat /etc/ssh/sshd_config | grep -i "^MaxStartups" |uniq |wc -l`
if [ $sk -gt 0 ] ; then
	szl=`cat /etc/ssh/sshd_config | grep -i "^MaxStartups" | awk '{print $2}' |uniq`
	if [ $szl  -le $MAXSTARTUPS ] || [ "$szl" == "10:30:100" ] ; then
		echo "System Settings" >>p1
		echo "MaxStartups" >>p2
		echo "Value is set as \"$szl\" in /etc/ssh/sshd_config" >>p3
		echo "yes" >>p4
		echo "AV.1.4.5" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
		echo "System Settings" >>p1
		echo "MaxStartups" >>p2
		echo "Value-is-not-set in /etc/ssh/sshd_config" >>p3
		echo "no" >>p4
		echo "AV.1.4.5" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
else
	szl=`cat /etc/ssh/sshd_config | grep -i "^#MaxStartups" | awk '{print $2}' |uniq`
	if [ $szl  -le $MAXSTARTUPS ] || [ "$szl" == "10:30:100" ] ; then
		echo "System Settings" >>p1
		echo "MaxStartups" >>p2
		echo "Value is set as \"$szl\" in /etc/ssh/sshd_config" >>p3
		echo "yes" >>p4
		echo "AV.1.4.5" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
		echo "System Settings" >>p1
		echo "MaxStartups" >>p2
		echo "Value-is-not-set in /etc/ssh/sshd_config" >>p3
		echo "no" >>p4
		echo "AV.1.4.5" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
fi
#########################################################################
#AV.1.4.8
sz=`rpm -qa |grep -i ssh |grep -i openssh-[0-9].[0-9] | cut -c1,2,3,4,5,6,7,8,9,10,11`
szk=`echo $sz | awk -F"-" '{print $2}'`
BC=`which bc`
if (( $($BC <<< "$szk>3.9") > 0 )) ; then
  sk=`cat /etc/ssh/sshd_config | grep -i "^MaxAuthTries" |uniq |wc -l`
  if [ $sk -gt 0 ] ; then
	szl=`cat /etc/ssh/sshd_config | grep -i "^MaxAuthTries" | awk '{print $2}' |uniq`
	if [ $szl -le $MAXAUTHTRIES ] ; then
		echo "System Settings" >>p1
		echo "MaxAuthTries" >>p2
		echo "Value is set as \"$szl\" in /etc/ssh/sshd_config" >>p3
		echo "yes" >>p4
		echo "AV.1.4.8" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
		echo "System Settings" >>p1
		echo "MaxAuthTries" >>p2
		echo "Value-is-not-set in /etc/ssh/sshd_config" >>p3
		echo "no" >>p4
		echo "AV.1.4.8" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
  else
	szl=`cat /etc/ssh/sshd_config | grep -i "^#MaxAuthTries" | awk '{print $2}' |uniq`
	if [ $szl -le $MAXAUTHTRIES ] ; then
		echo "System Settings" >>p1
		echo "MaxAuthTries" >>p2
		echo "Value is set as \"$szl\" in /etc/ssh/sshd_config" >>p3
		echo "yes" >>p4
		echo "AV.1.4.8" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
		echo "System Settings" >>p1
		echo "MaxAuthTries" >>p2
		echo "Value-is-not-set in /etc/ssh/sshd_config" >>p3
		echo "no" >>p4
		echo "AV.1.4.8" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
  fi
else
		echo "System Settings" >>p1
		echo "MaxAuthTries" >>p2
		echo "Applicable-for-only-openssh3.9-and-greater" >>p3
		echo "Not_Applicable" >>p4
		echo "AV.1.4.8" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
###########################################################################
#AV.1.4.14
sz=`rpm -qa |grep -i ssh |grep -i openssh-[0-9].[0-9] | cut -c1,2,3,4,5,6,7`
if [ "$sz" != "openssh" ] ; then
	szl=`cat /etc/ssh/sshd_config | grep -i "^AuthKbdInt.Retries" | awk '{print $2}' |uniq`
	if [ "$szl" <= "5" ] ; then
		echo "System Settings" >>p1
		echo "AuthKbdInt.Retries" >>p2
		echo "Value is set as \"$szl\" in /etc/ssh/sshd_config" >>p3
		echo "yes" >>p4
		echo "AV.1.4.14" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
		echo "System Settings" >>p1
		echo "AuthKbdInt.Retries" >>p2
		echo "Value-is-not-set" >>p3
		echo "no" >>p4
		echo "AV.1.4.14" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
else
		echo "System Settings" >>p1
		echo "AuthKbdInt.Retries" >>p2
		echo "Not Applicable for OpenSSH" >>p3
		echo "Not_Applicable" >>p4
		echo "AV.1.4.14" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
###########################################################################
#AV.1.5.1
sshval=`rpm -qa |grep -i ssh |grep -i openssh-[0-9].[0-9] |cut -c1,2,3,4,5,6,7`
if [ "$sshval" != "openssh" ] ; then
sk=`cat /etc/ssh/sshd_config | grep -i "^KeyRegenerationInterval" |uniq |wc -l`
if [ $sk -gt 0 ] ; then
	szl=`cat /etc/ssh/sshd_config | grep -i "^KeyRegenerationInterval" | awk '{print $2}' |uniq`
	if [ "$szl" -le "$KEYREGENERATIONINTERVAL" ] || [ "$szl" == "1h" ] ; then
		echo "System Settings" >>p1
		echo "KeyRegenerationInterval" >>p2
		echo "Value is set as \"$szl\" in /etc/ssh/sshd_config" >>p3
		echo "yes" >>p4
		echo "AV.1.5.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
		echo "System Settings" >>p1
		echo "KeyRegenerationInterval" >>p2
		echo "Value-is-not-set in /etc/ssh/sshd_config" >>p3
		echo "no" >>p4
		echo "AV.1.5.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
else
	szl=`cat /etc/ssh/sshd_config | grep -i "^#KeyRegenerationInterval" | awk '{print $2}' |uniq`
	if [ "$szl" -le "$KEYREGENERATIONINTERVAL" ] || [ "$szl" == "1h" ] ; then
		echo "System Settings" >>p1
		echo "KeyRegenerationInterval" >>p2
		echo "Value is set as \"$szl\" in /etc/ssh/sshd_config" >>p3
		echo "yes" >>p4
		echo "AV.1.5.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
		echo "System Settings" >>p1
		echo "KeyRegenerationInterval" >>p2
		echo "Value-is-not-set in /etc/ssh/sshd_config" >>p3
		echo "no" >>p4
		echo "AV.1.5.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
fi
else
		echo "System Settings" >>p1
		echo "KeyRegenerationInterval" >>p2
		echo "This is not applicable for SSH protocol version 2 for openssh" >>p3
		echo "Not_Applicable" >>p4
		echo "AV.1.5.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
#############################################################################################
#AV.1.5.2
sk=`cat /etc/ssh/sshd_config | grep -i "^protocol" |uniq |wc -l`
if [ $sk -gt 0 ] ; then
	sz=`grep -i ^protocol /etc/ssh/sshd_config | awk 'FNR == 1 {print $2}'` 
	if [ "$sz" == "2" ] || [ "$sz" == "1,2" ] || [ "$sz" == "2,1" ]  ; then
		echo "Network Settingss" >>p1
		echo "SSH-protocol" >>p2
		echo "Value is set as $sz in /etc/ssh/sshd_config" >>p3
		echo "yes" >>p4
		echo "AV.1.5.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4				
	else
		echo "Network Settingss" >>p1
		echo "SSH-protocol" >>p2
		echo "value-should-be-2(or)1,2(or)2,1 in /etc/ssh/sshd_config" >>p3
		echo "no" >>p4
		echo "AV.1.5.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4		
	fi
else
	sz=`grep -i ^#protocol /etc/ssh/sshd_config | awk 'FNR == 1 {print $2}'` 
	if [ "$sz" == "2" ] || [ "$sz" == "1,2" ] || [ "$sz" == "2,1" ]  ; then
		echo "Network Settingss" >>p1
		echo "SSH-protocol" >>p2
		echo "Value is set as $sz in /etc/ssh/sshd_config" >>p3
		echo "yes" >>p4
		echo "AV.1.5.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
		echo "Network Settingss" >>p1
		echo "SSH-protocol" >>p2
		echo "Protocol is not set in /etc/ssh/sshd_config" >>p3
		echo "no" >>p4
		echo "AV.1.5.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
fi
#############################################################################################
#AV.1.5.5
sk=`cat /etc/ssh/sshd_config | grep -i "^GatewayPorts" |uniq |wc -l`
if [ $sk -gt 0 ] ; then
	sz=`cat /etc/ssh/sshd_config | grep -i "^GatewayPorts" | awk '{print $2}' |uniq`
	if [ "$sz" == "$GATEWAYPORTS" ] ; then
			echo "Network Settingss" >>p1
			echo "GatewayPorts" >>p2
			echo "GatewayPorts is set as \"$sz\" in /etc/ssh/sshd_config" >>p3
			echo "yes" >>p4
			echo "AV.1.5.5" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
			echo "Network Settingss" >>p1
			echo "GatewayPorts" >>p2
			echo "Value-is-not-set in /etc/ssh/sshd_config" >>p3
			echo "no" >>p4
			echo "AV.1.5.5" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
else
	sz=`cat /etc/ssh/sshd_config | grep -i "^#GatewayPorts" | awk '{print $2}' |uniq`
	if [ "$sz" == "$GATEWAYPORTS" ] ; then
			echo "Network Settingss" >>p1
			echo "GatewayPorts" >>p2
			echo "GatewayPorts is set as \"$sz\" in /etc/ssh/sshd_config" >>p3
			echo "yes" >>p4
			echo "AV.1.5.5" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
			echo "Network Settingss" >>p1
			echo "GatewayPorts" >>p2
			echo "Value-is-not-set in /etc/ssh/sshd_config" >>p3
			echo "no" >>p4
			echo "AV.1.5.5" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
fi
##########################################################################################
#AV.1.7.1.1
sz=`cat /etc/ssh/sshd_config | grep -i "^PermitRootLogin" | awk '{print $2}' |uniq`
if [ "$sz" == "$PERMITROOTLOGIN" ] ; then
		echo "IdentifyandAuthenticateUsers" >>p1
        	echo "PermitRootLogin" >>p2
		echo "PermitRootLogin is set as \"$sz\" in /etc/ssh/sshd_config" >> p3
		echo "yes" >>p4
		echo "AV.1.7.1.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
else
		echo "Password Requirements" >>p1
        	echo "PermitRootLogin" >>p2
		echo "PermitRootLogin is incorrectly set as \"$sz\" in /etc/ssh/sshd_config" >> p3
                echo "no" >>p4
		echo "AV.1.7.1.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
###########################################################################################
#AV.1.7.1.2
cat /etc/passwd | awk -F":" '{print $1}' > temp_id
for i in `cat temp_id` ; do
	if [ -f /home/$i/.ssh/authorized_keys ] ; then
		cat /home/$i/.ssh/authorized_keys | grep "root@"
		if [ $? -eq 0 ] ; then
			echo "Identify and Authenticate Users" >>p1
			echo "PermitRootLogin without-password" >>p2
			echo "root entry found-in-authorized_keys-for-user-$i" >>p3
			echo "no" >>p4
			echo "AV.1.7.1.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
		else
			echo "Identify and Authenticate Users" >>p1
			echo "PermitRootLogin without-password" >>p2
			echo "root-entry-not-found-in-authorized_keys-for-user-$i" >>p3
			echo "yes" >>p4
			echo "AV.1.7.1.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
		fi
	else
			echo "Identify and Authenticate Users" >>p1
			echo "PermitRootLogin without-password" >>p2
			echo "no-authorized-keys-found-no-root-verification-required - $i" >>p3
			echo "yes" >>p4
			echo "AV.1.7.1.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi	
done
############################################################################################
#AV.1.7.3.2
if [ -f /etc/hosts.equiv ] ; then
	sk=`cat /etc/hosts.equiv |wc -l`
	if [ $sk -gt 0 ] ; then
		echo "IdentifyandAuthenticateUsers" >>p1
        	echo "Host-Based Authentication" >>p2
		echo "File /etc/hosts.equiv-exist and entries found. Please check the entry  in file and remediate it as per techspec" >> p3
		echo "no" >>p4
		echo "AV.1.7.3.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
		echo "IdentifyandAuthenticateUsers" >>p1
        	echo "Host-Based Authentication" >>p2
		echo "File /etc/hosts.equiv-exist and but no entry found" >> p3
		echo "yes" >>p4
		echo "AV.1.7.3.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
else
		echo "IdentifyandAuthenticateUsers" >>p1
        	echo "Host-Based Authentication" >>p2
		echo "File /etc/hosts.equiv not exist" >> p3
		echo "yes" >>p4
		echo "AV.1.7.3.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
#############################################################################################
#AV.1.7.3.3
if [ -f /etc/hosts.equiv ] ; then
	if [ -f /etc/shosts.equiv ] ; then
		echo "IdentifyandAuthenticateUsers" >>p1
        	echo "Host-Based Authentication" >>p2
		echo "File /etc/shosts.equiv-exist" >> p3
		echo "yes" >>p4
		echo "AV.1.7.3.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
		echo "IdentifyandAuthenticateUsers" >>p1
        	echo "Host-Based Authentication" >>p2
		echo "File /etc/shosts.equiv must exist as file /etc/hosts.equiv is in use" >> p3
		echo "no" >>p4
		echo "AV.1.7.3.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
else
		echo "IdentifyandAuthenticateUsers" >>p1
        	echo "Host-Based Authentication" >>p2
		echo "Host based authentication is disabled" >> p3
		echo "yes" >>p4
		echo "AV.1.7.3.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
#############################################################################################
#AV.1.8.2.1,AV.1.8.2.2,AV.1.8.2.3,AV.1.8.6.1,AV.1.8.2.4,AV.1.8.2.5,AV.1.8.2.6,AV.1.8.2.7,AV.1.8.2.8,AV.1.8.2.9,AV.1.8.2.10,AV.1.8.2.11,AV.1.8.2.12,AV.1.8.2.13,AV.1.8.2.14,AV.1.8.2.15,AV.1.8.2.16,AV.1.8.2.17,AV.1.8.2.18,AV.1.8.2.19,AV.1.8.2.20,AV.1.8.2.21,AV.1.8.2.22,AV.1.8.2.23,AV.1.8.2.24,AV.1.8.2.25,AV.1.8.2.26,AV.1.8.2.27,AV.1.8.2.28,AV.1.8.2.29,AV.1.8.2.30,AV.1.8.2.31,AV.1.8.2.32,AV.1.8.2.33,AV.1.8.2.34,AV.1.8.2.35,AV.1.8.2.36,AV.1.8.2.37,AV.1.8.2.38,AV.1.8.2.39,AV.1.8.2.40,AV.1.8.2.41,AV.1.8.2.42,AV.1.8.2.43,AV.1.8.2.44,AV.1.8.2.45,AV.1.8.2.46,AV.1.8.2.47,AV.1.8.2.49,AV.1.8.2.50,AV.1.8.3.1,AV.1.8.3.2,AV.1.8.3.3,AV.1.8.3.4,AV.1.8.3.5,AV.1.8.3.6,AV.1.8.3.7,AV.1.8.3.8,AV.1.8.3.9,AV.1.8.3.10
echo "/usr/bin/openssl,/usr/bin/scp,/usr/bin/scp2,/usr/bin/sftp,/usr/bin/sftp2,/usr/bin/sftp-server,/usr/bin/sftp-server2,/usr/bin/slogin,/usr/bin/ssh,/usr/bin/ssh2,/usr/bin/ssh-add,/usr/bin/ssh-add2,/usr/bin/ssh-agent,/usr/bin/ssh-agent2,/usr/bin/ssh-askpass,/usr/bin/ssh-askpass2,/usr/bin/ssh-certenroll2,/usr/bin/ssh-chrootmgr,/usr/bin/ssh-dummy-shell,/usr/bin/ssh-keygen,/usr/bin/ssh-keygen2,/usr/bin/ssh-keyscan,/usr/bin/ssh-pam-client,/usr/bin/ssh-probe,/usr/bin/ssh-probe2,/usr/bin/ssh-pubkeymgr,/usr/bin/ssh-signer,/usr/bin/ssh-signer2,/lib/libcrypto.a,/lib/libssh.a,/lib/libssl.a,/lib/libz.a,/lib-exec/openssh/sftp-server,/lib-exec/openssh/ssh-keysign,/lib-exec/openssh/ssh-askpass,/lib-exec/sftp-server,/lib-exec/ssh-keysign,/lib-exec/ssh-rand-helper,/libexec/openssh/sftp-server,/libexec/openssh/ssh-keysign,/libexec/openssh/ssh-askpass,/libexec/sftp-server,/libexec/ssh-keysign,/libexec/ssh-rand-helper,/usr/bin/sshd,/usr/bin/sshd2,/usr/bin/sshd-check-conf,/lib/svc/method/sshd,/usr/lib/ssh/sshd,/etc/openssh/sshd_config,/etc/ssh/sshd_config,/etc/ssh/sshd2_config,/etc/ssh2/sshd_config,/etc/ssh2/sshd2_config,/etc/sshd_config,/etc/sshd2_config,/usr/local/etc/sshd_config,/usr/local/etc/sshd2_config,/usr/lib/ssh/ssh-keysign" > temp
tr "," "\n" < temp > temp1
for i in `cat temp1` ; do
	if [ -f $i ] ; then
	sz=`cat /etc/redhat-release |awk '{print $7}'`
	BC=`which bc`
	if (( $($BC <<< "$sz<7") > 0 )) ; then
	sj=`ls -ld $i |awk '{print $3}'`
	sk=`ls -ld $i |awk '{print $4}'`
	sl=`id -u $sj`
	sm=`getent group $sk |awk -F: '{print $3}'`
		if [ $sl -le 99 ] || [[ $sl -ge 101 && $sl -le 499 ]] ; then
			echo "Protecting Resources - OSRs" >>p1
			echo "OSR Executable and Libraries" >>p2
			echo "The file $i is owned by $sj - Permission is Valid" >>p3
			echo "yes" >>p4
			echo "AV.1.8.2.1:AV.1.8.2.2:AV.1.8.6.1:AV.1.8.2.3:AV.1.8.2.4:AV.1.8.2.5:AV.1.8.2.6:AV.1.8.2.7:AV.1.8.2.8:AV.1.8.2.9:AV.1.8.2.10:AV.1.8.2.11:AV.1.8.2.12:AV.1.8.2.13:AV.1.8.2.14:AV.1.8.2.15:AV.1.8.2.16:AV.1.8.2.17:AV.1.8.2.18:AV.1.8.2.19:AV.1.8.2.20:AV.1.8.2.21:AV.1.8.2.22:AV.1.8.2.23:AV.1.8.2.24:AV.1.8.2.25:AV.1.8.2.26:AV.1.8.2.27:AV.1.8.2.28:AV.1.8.2.29:AV.1.8.2.30:AV.1.8.2.31:AV.1.8.2.32:AV.1.8.2.33:AV.1.8.2.34:AV.1.8.2.35:AV.1.8.2.36:AV.1.8.2.37:AV.1.8.2.38:AV.1.8.2.39:AV.1.8.2.40:AV.1.8.2.41:AV.1.8.2.42:AV.1.8.2.43:AV.1.8.2.44:AV.1.8.2.45:AV.1.8.2.46:AV.1.8.2.47:AV.1.8.2.49:AV.1.8.2.50:AV.1.8.3.1:AV.1.8.3.2:AV.1.8.3.3:AV.1.8.3.4:AV.1.8.3.5:AV.1.8.3.6:AV.1.8.3.7:AV.1.8.3.8:AV.1.8.3.9:AV.1.8.3.10" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
		else
			echo "Protecting Resources - OSRs" >>p1
			echo "OSR Executable and Libraries" >>p2
			echo "The file $i is owned by $sj - Permission is invalid" >>p3
			echo "no" >>p4
			echo "AD.1.8.1.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
		fi
		if [ $sm -le 99 ] || [[ $sm -ge 101 && $sm -le 999 ]] ; then
			echo "Protecting Resources - OSRs" >>p1
			echo "OSR Executable and Libraries" >>p2
			echo "Group owner of file $i is $sk - Permission is Valid" >>p3
			echo "yes" >>p4
			echo "AV.1.8.2.1:AV.1.8.2.2:AV.1.8.2.3:AV.1.8.6.1:AV.1.8.2.4:AV.1.8.2.5:AV.1.8.2.6:AV.1.8.2.7:AV.1.8.2.8:AV.1.8.2.9:AV.1.8.2.10:AV.1.8.2.11:AV.1.8.2.12:AV.1.8.2.13:AV.1.8.2.14:AV.1.8.2.15:AV.1.8.2.16:AV.1.8.2.17:AV.1.8.2.18:AV.1.8.2.19:AV.1.8.2.20:AV.1.8.2.21:AV.1.8.2.22:AV.1.8.2.23:AV.1.8.2.24:AV.1.8.2.25:AV.1.8.2.26:AV.1.8.2.27:AV.1.8.2.28:AV.1.8.2.29:AV.1.8.2.30:AV.1.8.2.31:AV.1.8.2.32:AV.1.8.2.33:AV.1.8.2.34:AV.1.8.2.35:AV.1.8.2.36:AV.1.8.2.37:AV.1.8.2.38:AV.1.8.2.39:AV.1.8.2.40:AV.1.8.2.41:AV.1.8.2.42:AV.1.8.2.43:AV.1.8.2.44:AV.1.8.2.45:AV.1.8.2.46:AV.1.8.2.47:AV.1.8.2.49:AV.1.8.2.50:AV.1.8.3.1:AV.1.8.3.2:AV.1.8.3.3:AV.1.8.3.4:AV.1.8.3.5:AV.1.8.3.6:AV.1.8.3.7:AV.1.8.3.8:AV.1.8.3.9:AV.1.8.3.10" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
		else
			echo "Protecting Resources - OSRs" >>p1
			echo "OSR Executable and Libraries" >>p2
			echo "Group owner of file $i is $sk - Permission is invalid" >>p3
			echo "no" >>p4
			echo "AD.1.8.1.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
		fi
	else
	sz=`cat /etc/redhat-release |awk '{print $7}'`
	BC=`which bc`
	if (( $($BC <<< "$sz>=7") > 0 )) ; then
	sj=`ls -ld $i |awk '{print $3}'`
	sk=`ls -ld $i |awk '{print $4}'`
	sl=`id -u $sj`
	sm=`getent group $sk |awk -F: '{print $3}'`
		if [ $sl -le 99 ] || [[ $sl -ge 101 && $sl -le 499 ]] ; then
			echo "Protecting Resources - OSRs" >>p1
			echo "OSR Executable and Libraries" >>p2
			echo "The file $i is owned by $sj - Permission is Valid" >>p3
			echo "yes" >>p4
			echo "AV.1.8.2.1:AV.1.8.2.2:AV.1.8.2.3:AV.1.8.2.4:AV.1.8.6.1:AV.1.8.2.5:AV.1.8.2.6:AV.1.8.2.7:AV.1.8.2.8:AV.1.8.2.9:AV.1.8.2.10:AV.1.8.2.11:AV.1.8.2.12:AV.1.8.2.13:AV.1.8.2.14:AV.1.8.2.15:AV.1.8.2.16:AV.1.8.2.17:AV.1.8.2.18:AV.1.8.2.19:AV.1.8.2.20:AV.1.8.2.21:AV.1.8.2.22:AV.1.8.2.23:AV.1.8.2.24:AV.1.8.2.25:AV.1.8.2.26:AV.1.8.2.27:AV.1.8.2.28:AV.1.8.2.29:AV.1.8.2.30:AV.1.8.2.31:AV.1.8.2.32:AV.1.8.2.33:AV.1.8.2.34:AV.1.8.2.35:AV.1.8.2.36:AV.1.8.2.37:AV.1.8.2.38:AV.1.8.2.39:AV.1.8.2.40:AV.1.8.2.41:AV.1.8.2.42:AV.1.8.2.43:AV.1.8.2.44:AV.1.8.2.45:AV.1.8.2.46:AV.1.8.2.47:AV.1.8.2.49:AV.1.8.2.50:AV.1.8.3.1:AV.1.8.3.2:AV.1.8.3.3:AV.1.8.3.4:AV.1.8.3.5:AV.1.8.3.6:AV.1.8.3.7:AV.1.8.3.8:AV.1.8.3.9:AV.1.8.3.10" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
		else
			echo "Protecting Resources - OSRs" >>p1
			echo "OSR Executable and Libraries" >>p2
			echo "The file $i is owned by $sj - Permission is invalid" >>p3
			echo "no" >>p4
			echo "AV.1.8.2.1:AV.1.8.2.2:AV.1.8.2.3:AV.1.8.2.4:AV.1.8.6.1:AV.1.8.2.5:AV.1.8.2.6:AV.1.8.2.7:AV.1.8.2.8:AV.1.8.2.9:AV.1.8.2.10:AV.1.8.2.11:AV.1.8.2.12:AV.1.8.2.13:AV.1.8.2.14:AV.1.8.2.15:AV.1.8.2.16:AV.1.8.2.17:AV.1.8.2.18:AV.1.8.2.19:AV.1.8.2.20:AV.1.8.2.21:AV.1.8.2.22:AV.1.8.2.23:AV.1.8.2.24:AV.1.8.2.25:AV.1.8.2.26:AV.1.8.2.27:AV.1.8.2.28:AV.1.8.2.29:AV.1.8.2.30:AV.1.8.2.31:AV.1.8.2.32:AV.1.8.2.33:AV.1.8.2.34:AV.1.8.2.35:AV.1.8.2.36:AV.1.8.2.37:AV.1.8.2.38:AV.1.8.2.39:AV.1.8.2.40:AV.1.8.2.41:AV.1.8.2.42:AV.1.8.2.43:AV.1.8.2.44:AV.1.8.2.45:AV.1.8.2.46:AV.1.8.2.47:AV.1.8.2.49:AV.1.8.2.50:AV.1.8.3.1:AV.1.8.3.2:AV.1.8.3.3:AV.1.8.3.4:AV.1.8.3.5:AV.1.8.3.6:AV.1.8.3.7:AV.1.8.3.8:AV.1.8.3.9:AV.1.8.3.10" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
		fi
		if [ $sm -le 99 ] || [[ $sm -ge 101 && $sm -le 499 ]] ; then
			echo "Protecting Resources - OSRs" >>p1
			echo "OSR Executable and Libraries" >>p2
			echo "Group owner of file $i is $sk - Permission is Valid" >>p3
			echo "yes" >>p4
			echo "AV.1.8.2.1:AV.1.8.2.2:AV.1.8.2.3:AV.1.8.2.4:AV.1.8.2.5:AV.1.8.6.1:AV.1.8.2.6:AV.1.8.2.7:AV.1.8.2.8:AV.1.8.2.9:AV.1.8.2.10:AV.1.8.2.11:AV.1.8.2.12:AV.1.8.2.13:AV.1.8.2.14:AV.1.8.2.15:AV.1.8.2.16:AV.1.8.2.17:AV.1.8.2.18:AV.1.8.2.19:AV.1.8.2.20:AV.1.8.2.21:AV.1.8.2.22:AV.1.8.2.23:AV.1.8.2.24:AV.1.8.2.25:AV.1.8.2.26:AV.1.8.2.27:AV.1.8.2.28:AV.1.8.2.29:AV.1.8.2.30:AV.1.8.2.31:AV.1.8.2.32:AV.1.8.2.33:AV.1.8.2.34:AV.1.8.2.35:AV.1.8.2.36:AV.1.8.2.37:AV.1.8.2.38:AV.1.8.2.39:AV.1.8.2.40:AV.1.8.2.41:AV.1.8.2.42:AV.1.8.2.43:AV.1.8.2.44:AV.1.8.2.45:AV.1.8.2.46:AV.1.8.2.47:AV.1.8.2.49:AV.1.8.2.50:AV.1.8.3.1:AV.1.8.3.2:AV.1.8.3.3:AV.1.8.3.4:AV.1.8.3.5:AV.1.8.3.6:AV.1.8.3.7:AV.1.8.3.8:AV.1.8.3.9:AV.1.8.3.10" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
		else
			echo "Protecting Resources - OSRs" >>p1
			echo "OSR Executable and Libraries" >>p2
			echo "Group owner of file $i is $sk - Permission is invalid" >>p3
			echo "no" >>p4
			echo "AV.1.8.2.1:AV.1.8.2.2:AV.1.8.2.3:AV.1.8.2.4:AV.1.8.2.5:AV.1.8.6.1:AV.1.8.2.6:AV.1.8.2.7:AV.1.8.2.8:AV.1.8.2.9:AV.1.8.2.10:AV.1.8.2.11:AV.1.8.2.12:AV.1.8.2.13:AV.1.8.2.14:AV.1.8.2.15:AV.1.8.2.16:AV.1.8.2.17:AV.1.8.2.18:AV.1.8.2.19:AV.1.8.2.20:AV.1.8.2.21:AV.1.8.2.22:AV.1.8.2.23:AV.1.8.2.24:AV.1.8.2.25:AV.1.8.2.26:AV.1.8.2.27:AV.1.8.2.28:AV.1.8.2.29:AV.1.8.2.30:AV.1.8.2.31:AV.1.8.2.32:AV.1.8.2.33:AV.1.8.2.34:AV.1.8.2.35:AV.1.8.2.36:AV.1.8.2.37:AV.1.8.2.38:AV.1.8.2.39:AV.1.8.2.40:AV.1.8.2.41:AV.1.8.2.42:AV.1.8.2.43:AV.1.8.2.44:AV.1.8.2.45:AV.1.8.2.46:AV.1.8.2.47:AV.1.8.2.49:AV.1.8.2.50:AV.1.8.3.1:AV.1.8.3.2:AV.1.8.3.3:AV.1.8.3.4:AV.1.8.3.5:AV.1.8.3.6:AV.1.8.3.7:AV.1.8.3.8:AV.1.8.3.9:AV.1.8.3.10" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
		fi
	else
			echo "Protecting Resources - OSRs" >>p1
			echo "OSR Executable and Libraries" >>p2
			echo "Not applicable as it is not for RHEL6 or RHEL7" >>p3
			echo "Not_Applicable" >>p4
			echo "AV.1.8.2.1:AV.1.8.2.2:AV.1.8.2.3:AV.1.8.2.4:AV.1.8.2.5:AV.1.8.6.1:AV.1.8.2.6:AV.1.8.2.7:AV.1.8.2.8:AV.1.8.2.9:AV.1.8.2.10:AV.1.8.2.11:AV.1.8.2.12:AV.1.8.2.13:AV.1.8.2.14:AV.1.8.2.15:AV.1.8.2.16:AV.1.8.2.17:AV.1.8.2.18:AV.1.8.2.19:AV.1.8.2.20:AV.1.8.2.21:AV.1.8.2.22:AV.1.8.2.23:AV.1.8.2.24:AV.1.8.2.25:AV.1.8.2.26:AV.1.8.2.27:AV.1.8.2.28:AV.1.8.2.29:AV.1.8.2.30:AV.1.8.2.31:AV.1.8.2.32:AV.1.8.2.33:AV.1.8.2.34:AV.1.8.2.35:AV.1.8.2.36:AV.1.8.2.37:AV.1.8.2.38:AV.1.8.2.39:AV.1.8.2.40:AV.1.8.2.41:AV.1.8.2.42:AV.1.8.2.43:AV.1.8.2.44:AV.1.8.2.45:AV.1.8.2.46:AV.1.8.2.47:AV.1.8.2.49:AV.1.8.2.50:AV.1.8.3.1:AV.1.8.3.2:AV.1.8.3.3:AV.1.8.3.4:AV.1.8.3.5:AV.1.8.3.6:AV.1.8.3.7:AV.1.8.3.8:AV.1.8.3.9:AV.1.8.3.10" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
	fi
else
			echo "Protecting Resources - OSRs" >>p1
			echo "OSR Executable and Libraries" >>p2
			echo "Not applicable as file $i not exist" >>p3
			echo "Not_Applicable" >>p4
			echo "AV.1.8.2.1:AV.1.8.2.2:AV.1.8.2.3:AV.1.8.2.4:AV.1.8.2.5:AV.1.8.6.1:AV.1.8.2.6:AV.1.8.2.7:AV.1.8.2.8:AV.1.8.2.9:AV.1.8.2.10:AV.1.8.2.11:AV.1.8.2.12:AV.1.8.2.13:AV.1.8.2.14:AV.1.8.2.15:AV.1.8.2.16:AV.1.8.2.17:AV.1.8.2.18:AV.1.8.2.19:AV.1.8.2.20:AV.1.8.2.21:AV.1.8.2.22:AV.1.8.2.23:AV.1.8.2.24:AV.1.8.2.25:AV.1.8.2.26:AV.1.8.2.27:AV.1.8.2.28:AV.1.8.2.29:AV.1.8.2.30:AV.1.8.2.31:AV.1.8.2.32:AV.1.8.2.33:AV.1.8.2.34:AV.1.8.2.35:AV.1.8.2.36:AV.1.8.2.37:AV.1.8.2.38:AV.1.8.2.39:AV.1.8.2.40:AV.1.8.2.41:AV.1.8.2.42:AV.1.8.2.43:AV.1.8.2.44:AV.1.8.2.45:AV.1.8.2.46:AV.1.8.2.47:AV.1.8.2.49:AV.1.8.2.50:AV.1.8.3.1:AV.1.8.3.2:AV.1.8.3.3:AV.1.8.3.4:AV.1.8.3.5:AV.1.8.3.6:AV.1.8.3.7:AV.1.8.3.8:AV.1.8.3.9:AV.1.8.3.10" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
done
rm -rf temp temp1
#################################################################################
#AV.1.9.1
sz=`rpm -qa |grep -i ssh |grep -i openssh-[0-9].[0-9] | cut -c1,2,3,4,5,6,7,8,9,10,11`
szk=`echo $sz | awk -F"-" '{print $2}'`
BC=`which bc`
if (( $($BC <<< "$szk>=3.5") > 0 )) ; then
   sk=`cat /etc/ssh/sshd_config | grep -i "^PermitUserEnvironment" |uniq |wc -l`
   if [ $sk -gt 0 ] ; then
	szl=`cat /etc/ssh/sshd_config | grep -i "^PermitUserEnvironment" | awk '{print $2}' |uniq`
	if [ "$szl" == "$PERMITUSERENVIRONMENT" ] ; then
		echo "Protecting Resources - User Resources" >>p1
		echo "PermitUserEnvironment" >>p2
		echo "PermitUserEnvironment is set as \"$szl\" in /etc/ssh/sshd_config" >>p3
		echo "yes" >>p4
		echo "AV.1.9.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
		echo "Protecting Resources - User Resources" >>p1
		echo "PermitUserEnvironment" >>p2
		echo "PermitUserEnvironment is not set in /etc/ssh/sshd_config" >>p3
		echo "no" >>p4
		echo "AV.1.9.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
    else
	szl=`cat /etc/ssh/sshd_config | grep -i "^#PermitUserEnvironment" | awk '{print $2}' |uniq`
	if [ "$szl" == "$PERMITUSERENVIRONMENT" ] ; then
		echo "Protecting Resources - User Resources" >>p1
		echo "PermitUserEnvironment" >>p2
		echo "PermitUserEnvironment is set as \"$szl\" in /etc/ssh/sshd_config" >>p3
		echo "yes" >>p4
		echo "AV.1.9.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
		echo "Protecting Resources - User Resources" >>p1
		echo "PermitUserEnvironment" >>p2
		echo "PermitUserEnvironment is not set in /etc/ssh/sshd_config" >>p3
		echo "no" >>p4
		echo "AV.1.9.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
    fi
else
		echo "Protecting Resources - User Resources" >>p1
		echo "PermitUserEnvironment" >>p2
		echo "Applicable-only-for-openssh-version-3.5-and-higher" >>p3
		echo "Not_Applicable" >>p4
		echo "AV.1.9.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
########################################################################################
#AV.1.9.2
sk=`cat /etc/ssh/sshd_config | grep -i "^StrictModes" |uniq |wc -l`
if [ $sk -gt 0 ] ; then
	szk=`cat /etc/ssh/sshd_config | grep "^StrictModes" | awk '{print $2}' |uniq`
	if [ "$szk" == "$STRICTMODES" ] ; then
		echo "IdentifyandAuthenticateUsers" >>p1
		echo "StrictModes" >>p2
		echo "StrictModes is set as \"$szk\" in /etc/ssh/sshd_config" >> p3
		echo "yes" >>p4
		echo "AV.1.9.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
		echo "IdentifyandAuthenticateUsers" >>p1
		echo "StrictModes" >>p2
		echo "Value-is-not-set in /etc/ssh/sshd_config" >> p3
		echo "no" >>p4
		echo "AV.1.9.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
else
	szk=`cat /etc/ssh/sshd_config | grep "^#StrictModes" | awk '{print $2}' |uniq`
	if [ "$szk" == "$STRICTMODES" ] ; then
		echo "IdentifyandAuthenticateUsers" >>p1
		echo "StrictModes" >>p2
		echo "StrictModes is set as \"$szk\" in /etc/ssh/sshd_config" >> p3
		echo "yes" >>p4
		echo "AV.1.9.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
		echo "IdentifyandAuthenticateUsers" >>p1
		echo "StrictModes" >>p2
		echo "Value-is-not-set in /etc/ssh/sshd_config" >> p3
		echo "no" >>p4
		echo "AV.1.9.2" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
fi
############################################################################################
#AV.1.9.3
sz=`rpm -qa |grep -i ssh |grep -i openssh-[0-9].[0-9] | cut -c1,2,3,4,5,6,7,8,9,10,11`
szk=`echo $sz | awk -F"-" '{print $2}'`
if (( $(bc <<< "$szk>=3.9") > 0 )) ; then
	szl=`cat /etc/ssh/sshd_config | grep -i "^AcceptEnv" | egrep 'TERM|PATH|HOME| MAIL| SHELL| LOGNAME| USER| USERNAME| _RLD*| DYLD_*| LD_*| LDR_*| LIBPATH| SHLIB_PATH'`
	if [ $? -eq 0 ] ; then
		echo "Protecting Resources - User Resources" >>p1
		echo "User Environment variables are not correctly set" >>p3
		echo "AcceptEnv" >>p2
		echo "no" >>p4
		echo "AV.1.9.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
		echo "Protecting Resources - User Resources" >>p1
		echo "User Environment variables are correctly set" >>p3
		echo "AcceptEnv" >>p2
		echo "yes" >>p4
		echo "AV.1.9.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
else
		echo "Protecting Resources - User Resources" >>p1
		echo "AcceptEnv" >>p2
		echo "Applicable-only-for-openssh-version-3.9-and-higher" >>p3
		echo "Not_Applicable" >>p4
		echo "AV.1.9.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
#########################################################################################
#AV.2.0.1.1:IZ.2.0.1.1
sk=`cat /etc/ssh/sshd_config | grep -i "^PrintMotd" |uniq |wc -l`
if [ $sk -gt 0 ] ; then
	szk=`cat /etc/ssh/sshd_config | grep "^PrintMotd" | awk '{print $2}' |uniq`
	if [ "$szk" == "$PRINTMOTD" ] ; then
		echo "Business Use Notice " >>p1
		echo "PrintMotd" >>p2
		echo "PrintMotd is set as \"$szk\" in /etc/ssh/sshd_config" >> p3
		echo "yes" >>p4
		echo "AV.2.0.1.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
		echo "Business Use Notice " >>p1
		echo "PrintMotd" >>p2
		echo "Value-is-not-set in /etc/ssh/sshd_config" >> p3
		echo "no" >>p4
		echo "AV.2.0.1.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
else
	szk=`cat /etc/ssh/sshd_config | grep "^#PrintMotd" | awk '{print $2}' |uniq`
	if [ "$szk" == "$PRINTMOTD" ] ; then
		echo "Business Use Notice " >>p1
		echo "PrintMotd" >>p2
		echo "PrintMotd is set as \"$szk\" in /etc/ssh/sshd_config" >> p3
		echo "yes" >>p4
		echo "AV.2.0.1.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
		echo "Business Use Notice " >>p1
		echo "PrintMotd" >>p2
		echo "Value-is-not-set in /etc/ssh/sshd_config" >> p3
		echo "no" >>p4
		echo "AV.2.0.1.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
fi
################################################################################
#AV.2.1.1.1
sk=`cat /etc/ssh/sshd_config | grep -i "^Protocol" |uniq |wc -l`
if [ $sk -gt 0 ] ; then
  sz=`grep -i ^Protocol /etc/ssh/sshd_config | awk 'FNR == 1 {print $2}'` 
  if [ "$sz" == "1" ] || [ "$sz" == "1,2" ] || [ "$sz" == "2,1" ]  ; then
	szl=`cat /etc/ssh/sshd_config | grep -i "^ServerKeyBits" | awk '{print $2}'`
	if [ $szl -ge 1024 ] ; then	
		echo "Encryption" >>p1
		echo "Data Transmission" >>p2
		echo "ServerKeyBits-value-is set as \"$szl\" in /etc/ssh/sshd_config" >>p3
		echo "yes" >>p4
		echo "AV.2.1.1.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
		echo "Encryption" >>p1
		echo "Data Transmission" >>p2
		echo "ServerKeyBits value must be greater than or equal to 1024" >>p3
		echo "no" >>p4
		echo "AV.2.1.1.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
  else
		echo "Encryption" >>p1
		echo "Data Transmission" >>p2
		echo "Not applicable as the SSH protocol version 1 is not enabled" >>p3
		echo "Not_Applicable" >>p4
		echo "AV.2.1.1.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
  fi		
else
  sz=`grep -i ^#protocol /etc/ssh/sshd_config | awk 'FNR == 1 {print $2}'` 
  if [ "$sz" == "1" ] || [ "$sz" == "1,2" ] || [ "$sz" == "2,1" ]  ; then
	szl=`cat /etc/ssh/sshd_config | grep -i "^ServerKeyBits" | awk '{print $2}'`
	if [ $szl -ge 1024 ] ; then	
		echo "Encryption" >>p1
		echo "Data Transmission" >>p2
		echo "ServerKeyBits-value-is set as \"$szl\" in /etc/ssh/sshd_config" >>p3
		echo "yes" >>p4
		echo "AV.2.1.1.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
		echo "Encryption" >>p1
		echo "Data Transmission" >>p2
		echo "ServerKeyBits value must be greater than or equal to 1024" >>p3
		echo "no" >>p4
		echo "AV.2.1.1.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
  else
		echo "Encryption" >>p1
		echo "Data Transmission" >>p2
		echo "Not applicable as the SSH protocol version 1 is not enabled" >>p3
		echo "Not_Applicable" >>p4
		echo "AV.2.1.1.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
  fi		
fi
####################################################################################


########################################## Sudo #####################################
#ZY.1.2.4;AV.1.2.4
sl=`sed -n '/# rotate.log*/,/#.*keep*/p' /etc/logrotate.conf |grep -v '#' |egrep 'monthly|weekly'`
sn=`cat /etc/logrotate.conf |grep -v '#' |grep ^rotate |uniq  |awk '{print $2}'`
if [[ "$sl" == "weekly" && "$sn" -ge "$LOG_ROTATE_WEEK" ]] || [[ "$sl" == "monthly" && "$sn" -ge "$LOG_ROTATE_MONTH" ]] ; then
cat /etc/logrotate.conf |grep "^include.*/etc/logrotate.d"
if [ $? -eq 0 ] ; then
  sp=`cat /etc/logrotate.d/syslog |grep '^/var/log/secure' |wc -l`
  if [ $sp -gt 0 ] ; then
	sed -n '/\/var\/log\/secure.*{/,/}/p' /etc/logrotate.d/syslog |grep -v '#' > log_file1
	sk=`cat log_file1 |wc -l`
	if [ $sk -gt 0 ] ; then
		sj1=`cat log_file1 |grep rotate |awk '{print $2}'`
		sj2=`cat log_file1 |grep weekly |wc -c`
		sj3=`cat log_file1 |grep monthly |wc -c`
		if [[ $sj1 -ge $LOG_ROTATE_WEEK  &&  $sj2 -gt 1 ]] || [[ $sj1 -ge $LOG_ROTATE_MONTH  &&  $sj3 -gt 1 ]] ; then
			echo "Logging" >>p1
		        echo "Retain Log Files" >>p2
			echo "Logrotate-is-set-as correct for /var/log/secure in-/etc/logrotate.d/syslog" >>p3
			echo "ZY.1.2.4:AV.1.2.4">>p7
			echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
		else
			echo "Logging" >>p1
		        echo "Retain Log Files" >>p2
			echo "Logrotate-is-set-as incorrect for /var/log/secure in-/etc/logrotate.d/syslog" >>p3
			echo "ZY.1.2.4:AV.1.2.4">>p7
			echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
		fi
	else
		echo "Logging" >>p1
                echo "Retain Log Files" >>p2
		echo "Logrotate for /var/log/secure is-set-as correct in /etc/logrotate.d/syslog" >>p3
		echo "ZY.1.2.4:AV.1.2.4">>p7
		echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
  else
		echo "Logging" >>p1
                echo "Retain Log Files" >>p2
		echo "Logrotate for /var/log/secure is not set correct in /etc/logrotate.d/syslog" >>p3
		echo "ZY.1.2.4:AV.1.2.4">>p7
		echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
  fi
else
		echo "Logging" >>p1
                echo "Retain Log Files" >>p2
		echo "'include /etc/logrotate.d' entry not found in /etc/logrotate.conf. Please check logrotate policy manually" >>p3
		echo "ZY.1.2.4:AV.1.2.4">>p7
		echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
else
cat /etc/logrotate.conf |grep "^include.*/etc/logrotate.d"
if [ $? -eq 0 ] ; then
  sp=`cat /etc/logrotate.d/syslog |grep '^/var/log/secure' |wc -l`
  if [ $sp -gt 0 ] ; then
	sed -n '/\/var\/log\/secure.*{/,/}/p' /etc/logrotate.d/syslog |grep -v '#' > log_file1
	sk=`cat log_file1 |wc -l`
	if [ $sk -gt 0 ] ; then
		sj1=`cat log_file1 |grep rotate |awk '{print $2}'`
		sj2=`cat log_file1 |grep weekly |wc -c`
		sj3=`cat log_file1 |grep monthly |wc -c`
		if [[ $sj1 -ge $LOG_ROTATE_WEEK  &&  $sj2 -gt 1 ]] || [[ $sj1 -ge $LOG_ROTATE_MONTH  &&  $sj3 -gt 1 ]] ; then
			echo "Logging" >>p1
		        echo "Retain Log Files" >>p2
			echo "Logrotate-is-set-as correct for /var/log/secure in-/etc/logrotate.d/syslog" >>p3
			echo "ZY.1.2.4:AV.1.2.4">>p7
			echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
		else
			echo "Logging" >>p1
		        echo "Retain Log Files" >>p2
			echo "Logrotate-is-set-as incorrect for /var/log/secure in-/etc/logrotate.d/syslog" >>p3
			echo "ZY.1.2.4:AV.1.2.4">>p7
			echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
		fi
	else
		echo "Logging" >>p1
                echo "Retain Log Files" >>p2
		echo "Logrotate for /var/log/secure is-set-as correct in /etc/logrotate.d/syslog" >>p3
		echo "ZY.1.2.4:AV.1.2.4">>p7
		echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
  else
		echo "Logging" >>p1
                echo "Retain Log Files" >>p2
		echo "Logrotate for /var/log/secure is not set correct in /etc/logrotate.d/syslog" >>p3
		echo "ZY.1.2.4:AV.1.2.4">>p7
		echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
  fi
else
		echo "Logging" >>p1
                echo "Retain Log Files" >>p2
		echo "'include /etc/logrotate.d' entry not found in /etc/logrotate.conf. Please check logrotate policy manually" >>p3
		echo "ZY.1.2.4:AV.1.2.4">>p7
		echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
fi
rm -rf log_file1
#######################################################################################
#ZY.1.2.1
sk=`cat /etc/sudoers.d/* |grep "\!logfile" |wc -l`
sl=`cat /etc/sudoers |grep "\!logfile" |wc -l`
if [ $sk -gt 0 ] || [ $sl -gt 0 ] ; then
			echo "Logging" >>p1
			echo "Sudo Logging must not be disabled" >>p2
			echo "Sudo logging is disabled" >>p3
			echo "no" >>p4
			echo "ZY.1.2.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
else
			echo "Logging" >>p1
			echo "Sudo Logging must not be disabled" >>p2
			echo "Sudo logging is not disabled" >>p3
			echo "yes" >>p4
			echo "ZY.1.2.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
#######################################################################################
#ZY.1.2.3,ZY.1.4.4,ZY.1.2.2
sl=`ls -l /var/log/hist/root/ |wc -c`
for sectionId in ZY.1.2.3 ZY.1.4.4 ZY.1.2.2 ; do
if [ "$sl" -gt "0" ] && [ -f /etc/profile.d/secondary_logging_IBM.sh ] ; then
			echo "Logging" >>p1
			echo "Secondary logging" >>p2
			echo "Secondary login is in place" >>p3
			echo "yes" >>p4
		    echo $sectionId >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
else
	sl1=`ls -ltr /root/.history-sudo-* |wc -l`
	if [ $sl1 -gt 0 ] ; then
			echo "Logging" >>p1
			echo "Secondary logging" >>p2
			echo "Secondary login is in place" >>p3
			echo "yes" >>p4
		    echo $sectionId >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else		
			echo "Logging" >>p1
			echo "Secondary logging" >>p2
			echo "Secondary login is not in place" >>p3
			echo "no" >>p4
	        echo $sectionId >>p7 
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
fi
done
########################################################################################
#ZY.1.4.2.0;#ZY.1.4.2.1
cat /etc/sudoers |grep SHELLESCAPE
if [ $? -eq 0 ] ; then
cat /etc/sudoers | grep -i "noexec"
if [ $? -eq 0 ] ; then
		echo "System Settings" >>p1
		echo "Commands which allow shell escape" >>p2
		echo "noexec is enabled" >>p3
		echo "yes" >>p4
		echo "ZY.1.4.2.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
else
		echo "System Settings" >>p1
		echo "Commands which allow shell escape" >>p2
		echo "noexec-is-not-enabled" >>p3
		echo "no" >>p4
		echo "ZY.1.4.2.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
else
		echo "System Settings" >>p1
		echo "Commands which allow shell escape" >>p2
		echo "shell escape-is-not-enabled" >>p3
		echo "no" >>p4
		echo "ZY.1.4.2.1" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
####################################################################################
#ZY.1.4.2.3
Release=`cat /etc/redhat-release |awk '{print $1}'`
if [ "$Release" != "Red" ] ; then
cat /etc/sudoers | grep "Defaults env_file=/etc/sudo.env"
	if [ $? -eq 0 ] ; then
		if [ -f /etc/sudo.env ] ; then
			cat /etc/sudo.env | egrep "^SMIT_SHELL=n|^SMIT_SEMI_COLON=n|^SMIT_QUOTE=n"
			if [ $? -eq 0 ] ; then
				echo "System Settings" >>p1
				echo "Commands which allow shell escape" >>p2
				echo "SMIT-values-found" >>p3
				echo "missing-values-SMIT_SHELL=n|^SMIT_SEMI_COLON=n|^SMIT_QUOTE=n" >>p2
				echo "yes" >>p4
				echo "ZY.1.4.2.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
			else
				echo "missing-values-SMIT_SHELL=n|^SMIT_SEMI_COLON=n|^SMIT_QUOTE=n" >>p3
				echo "System Settings" >>p1
				echo "Commands which allow shell escape" >>p2
				echo "yes" >>p4
				echo "ZY.1.4.2.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
			fi
		else
			echo "System Settings" >>p1
			echo "Commands which allow shell escape" >>p2
			echo "/etc/sudo.env-file-not-found" >>p3
			echo "no" >>p4
			echo "ZY.1.4.2.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
		fi
	fi
else
			echo "System Settings" >>p1
			echo "Commands which allow shell escape" >>p2
			echo "This-is-not-for-Linux" >>p3
			echo "Not_Applicable" >>p4
			echo "ZY.1.4.2.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
###################################################################################
#ZY.1.4.3.1,ZY.1.8.2.1,ZY.1.8.2.2,ZY.1.8.1.2,ZY.1.8.1.4
cat /etc/sudoers |egrep "^#include|^#includedir" |awk '{print $2}' >temp1
cat /etc/sudoers.d/* |egrep "^#include|^#includedir" |awk '{print $2}' >>temp1
for i in `cat temp1` ; do
sk=`echo $i |cut -c1`
for sectionId in ZY.1.4.3.1 ZY.1.8.2.1 ZY.1.8.2.2 ZY.1.8.1.2 ZY.1.8.1.4 ; do
if [ "$sk" == "/" ] ; then
	echo "System Settings" >>p1
	echo "Specific commands/programs executed via sudo:" >>p2
	echo "Full path specified for command \"$i\" in sudoers config file having include or includedir statements" >>p3
	echo "yes" >>p4
    echo $sectionId >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	 
else
	echo "System Settings" >>p1
	echo "Specific commands/programs executed via sudo:" >>p2
	echo "Full path not specified for command \"$i\" in sudoers config file having include or includedir statements" >>p3
	echo "no" >>p4
    echo $sectionId >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
done
done
rm -rf temp1
##################################################################################
#ZY.1.4.3.3
sk=`cat /etc/sudoers |grep -v '#' |grep -v '^$' |tail -1`

if [[ "$sk" == *"ALL ALL=!SUDOSUDO"* ]] ; then
			echo "System Settings" >>p1
			echo "Preventing Nested Sudo invocation" >>p2
			echo "ALL-ALL=!SUDOSUDO-found" >>p3
			echo "yes" >>p4
			echo "ZY.1.4.3.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
else
			echo "System Settings" >>p1
			echo "Preventing Nested Sudo invocation" >>p2
			echo "ALL-ALL=!SUDOSUDO-not-found" >>p3
			echo "no" >>p4
			echo "ZY.1.4.3.3" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
############################################################################

#ZY.1.8.1.0
ls -l /etc/sudoers
if [ $? -eq 0 ] ; then
	sz=`ls -lrt /etc/sudoers | awk '{print $1}' | cut -c9`
	sz1=`ls -lrt /etc/sudoers | awk '{print $3}'`
	if [ "$sz1" == "root" ] && [ "$sz" != "w" ] ; then
		echo "Protecting Resources - OSRs" >>p1
                echo "/etc/sudoers permission" >>p2
		echo "Permission of /etc/sudoers is valid" >>p3
                echo "yes" >>p4
                echo "ZY.1.8.1.0" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	else
		echo "Protecting Resources - OSRs" >>p1
                echo "/etc/sudoers permission" >>p2
		echo "Permission of /etc/sudoers is invalid" >>p3
                echo "no" >>p4
                echo "ZY.1.8.1.0" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
	fi
else
		echo "Protecting Resources - OSRs" >>p1
                echo "/etc/sudoers permission" >>p2
		echo "File /etc/sudoers not exist" >>p3
                echo "no" >>p4
                echo "ZY.1.8.1.0" >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
fi
###########################################################################
#ZY.1.8.1.1,ZY.1.8.1.3,ZY.1.8.1.5,ZY.1.8.1.6,ZY.1.8.2.3
sl=`ls -ltr /etc/sudoers.d |wc -l`
file1=`ls -ld /etc/sudoers.d |wc -l`
if [ $file1 -gt 0 ] && [ $sl -gt 1 ] ; then
cat /etc/sudoers |egrep "^#include|^#includedir" |awk '{print $2}' >temp1
cat /etc/sudoers.d/* |egrep "^#include|^#includedir" |awk '{print $2}' >>temp1
	sn=`cat temp1 |wc -l`
	if [ $sn -gt 0 ] ; then
	for i in `cat temp1` ; do
		sz=`ls -ld $i | awk '{print $1}' | cut -c9`
		sk=`ls -ld $i | awk '{print $3}'`
		sp=`ls -ld $i | awk '{print $4}'`
      for sectionId in ZY.1.8.1.1 ZY.1.8.1.3 ZY.1.8.1.5 ZY.1.8.1.6 ZY.1.8.2.3 ; do
		if [ "$sk" == "root" ] && [ "$sz" != "w" ] && [ "$sp" == "root" ] ; then
			echo "Protecting Resources - OSRs" >>p1
		        echo "File permission in /etc/sudoers.d and /etc/sudoers" >>p2
			echo "File permission is valid for $i" >>p3
		        echo "yes" >>p4
			    echo $sectionId >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
		else
			echo "Protecting Resources - OSRs" >>p1
		        echo "File permission in /etc/sudoers.d and /etc/sudoers" >>p2
			echo "File permission is invalid for $i" >>p3
		        echo "no" >>p4
			    echo $sectionId >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4	
		fi
       done
	done
	else
	    for sectionId in ZY.1.8.1.1 ZY.1.8.1.3 ZY.1.8.1.5 ZY.1.8.1.6 ZY.1.8.2.3 ; do
		        echo "Protecting Resources - OSRs" >>p1
                echo "File permission in /etc/sudoers.d and /etc/sudoers" >>p2
		        echo "SUDO template not implemented" >>p3
                echo "no" >>p4
	            echo $sectionId >>p7
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4			
		done		
	fi
else
        for sectionId in ZY.1.8.1.1 ZY.1.8.1.3 ZY.1.8.1.5 ZY.1.8.1.6 ZY.1.8.2.3 ; do
		        echo "Protecting Resources - OSRs" >>p1
                echo "File permission in /etc/sudoers.d and /etc/sudoers" >>p2
		        echo "SUDO template not implemented" >>p3
                echo "no" >>p4
                echo $sectionId >>p7 
	echo "$c" >> p5
	echo "$z" >>p6
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
	echo "$timestamp" >>en4			
		done		
fi
rm -rf temp1
########################################################################





##############################################################################################################
echo -e "ACCOUNT:$accountName-$accountID \nLinuxTechSpec Version: $LinuxtechSpecVersion \nSSHTechSpec Version: $SSHtechSpecVersion\nSudoTechSpec Version: $SudotechSpecVersion\nCustomisation Date:$customisedDate \nScan Version: $scanVersion \n*************************************************************************************" > `hostname`_Linux_SSH_SUDO$c_mhc.csv

paste -d "|" p6 en1 en2 en3 p7 p1 p2 p3 p4 p5 en4 >> `hostname`_Linux_SSH_SUDO$c_mhc.csv
chmod 644 `hostname`_Linux_SSH_SUDO$c_mhc.csv
rm -rf temp_shadow temp_shadow1 temp1_shadow temp_shadow2 temp_shadow3 temp-ud psw_temp temp_uid temp_uid1 temp_gid temp_gid1 pasd_temp en1 en2 en3 en4 p5 p4 p3 p2 p1 p6 p7 f1 t1 temp_pam.so world-writable-test log_file1 temp_id file1
else
echo "Error: The parameter file hc_scan_parameter not found. Please copy the file hc_scan_parameter into same location where HC scan script is available, then run the script again."
fi
