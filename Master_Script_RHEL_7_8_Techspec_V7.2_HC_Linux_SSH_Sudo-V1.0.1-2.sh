#!/bin/bash -X
#########################################################################################################
# Author   : Abhilash Dd Chaitanya and Ashutosh Mishra                              			#
# Email    : achaitan@in.ibm.com, ashmishn@in.ibm.com                               			#
# Modified by: Shweta Aagja11/India/IBM,Bikram Behera/India/IBM & Sivakrishna G Babuavvaru/India/IBM    #
# Reviewed & Modified by: Ashutosh Mishra19/India/IBM & Rakesh C Sharma04/India/IBM 			#
# Reviewed by: Rama Ramala/India/IBM,Sailen Roy3/India/IBM,Sanil Rk Puthiyapurayil/India/IBM@IBM	#
# Platform : Linux RHEL7 and RHEL8			     	        	    			#
# Script   : Shell script					                    			#
# Title    : Health check script for Linux, SSH and SUDO                            			#	     
#########################################################################################################
if [ -f hc_scan_parameter ]
then

rm -rf temp_shadow temp_shadow1 temp1_shadow temp_shadow2 temp-ud psw_temp temp_uid temp_uid1 temp_gid temp_gid1 pasd_temp p5 p4 p3 p2 p1 p6 p12 f1 t1 temp_pam.so file1 log_file1 log_file2 world-writable-test temp_id ff2 e1 e2 e3 e4 e5 e6 temp_home user

clear
pause(){
  read -p "Press [Enter] key to continue..." fackEnterKey
}
#z=`hostname`
#c=`date | awk '{print $1"-"$2"-"$3"-"$6"-"$4}'`

z=`hostname`
fqdn=`hostname --fqdn`
ipAddress=`hostname -i` 
osName=`cat /etc/redhat-release`
c=`date | awk '{print $1"-"$2"-"$3"-"$6"-"$4}'`
timestamp=`date '+%Y-%m-%d-%H%M%S%N'`

# please provide the below details while customising the Scan script.
#-------------------------------------------------------------------
accountName="Account name put here"
accountID="Account ID put Here"
customisedDate="10/12/2020"
scanVersion="V1.1"
techSpecVersion="Linux V7.2 SSH v5.2  Sudo v6.1 "
#-------------------------------------------------------------------

echo "FQDN" >>en1
echo "IP-ADDRESS" >>en2
echo "OS-NAME" >>en3
echo "TIMESTAMP" >> en4
echo "SECTION-HEADING" >>p1
echo "SYSTEM-VALUE/PARAMETER" >>p2
echo "CURRENT-VALUE" >>p3
echo "SECTION-ID" >>p12
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
TMOUT=`cat hc_scan_parameter |grep ^TMOUT |awk '{print $2}'`
AUTOLOGOUT=`cat hc_scan_parameter |grep ^AUTOLOGOUT |awk '{print $2}'`
SYSLOG_IP=`cat hc_scan_parameter |grep ^SYSLOG_IP |awk '{print $2}'`
############################################################################################################


#IZ.1.1.2.0
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
		echo "no-violation-for--password_complexity-in-/etc/pam.d/password-auth" >> p3
		echo "IZ.1.1.2.0">>p12
		echo "yes" >>p4
	else
		echo "IZ.1.1.2.0" >>p12
		echo "Password Requirements" >>p1
		echo "PASS_MIN_LEN-password_complexity" >>p2
		echo "password_complexity-violation-in-/etc/pam.d/password-auth" >> p3
		echo "no" >>p4
	fi
else
	echo "IZ.1.1.2.0" >>p12
	echo "Password Requirements" >>p1
	echo "PASS_MIN_LEN-password_complexity" >>p2
	echo "File-Not-Exist /etc/pam.d/password-auth" >> p3
	echo "no" >>p4
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
		echo "no-violation-for--password_complexity-in-/etc/pam.d/system-auth" >> p3
		echo "IZ.1.1.2.0">>p12
		echo "yes" >>p4
	else
		echo "IZ.1.1.2.0" >>p12
		echo "Password Requirements" >>p1
		echo "PASS_MIN_LEN-password_complexity" >>p2
		echo "password_complexity-violation-in-/etc/pam.d/system-auth" >> p3
		echo "no" >>p4
	fi
else
	echo "IZ.1.1.2.0" >>p12
	echo "Password Requirements" >>p1
	echo "PASS_MIN_LEN-password_complexity" >>p2
	echo "File-Not-Exist /etc/pam.d/system-auth" >> p3
	echo "no" >>p4
fi



#IZ.1.1.1.1:PASS_MAX_DAYS
sz=`cat /etc/login.defs |grep -v "#"| grep ^PASS_MAX_DAYS | awk '{print $2}' |uniq`
if [ "$sz" != "$PASS_MAX_DAYS" ]
then
	echo "Password Requirementss" >>p1
	echo "PASS_MAX_DAYS value in /etc/login.defs" >>p2
	echo "$sz"  >>p3
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
	echo "IZ.1.1.1.1" >>p12

else
	echo "Password Requirementss" >>p1
	echo "PASS_MAX_DAYS value in /etc/login.defs" >>p2
	echo "$sz" >>p3
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
	echo "IZ.1.1.1.1" >>p12
	
fi


#IZ.1.1.1.2:Fifth field of /etc/shadow
cat /etc/passwd | egrep -v "/sbin/nologin|sync|shutdown|halt|/bin/false" | awk -F":" '{print $1}' >temp_passwd
for i in `cat temp_passwd` ; do
sk=`chage -l $i |grep "^Maximum" |sed -e 's/://g' |awk '{print $8}'`
        if [ "$sk" -le "$PASS_MAX_DAYS" ] && [ "$sk" -gt 0 ] ; then
                echo "Password Requirements" >>p1
                echo "PASS_MAX_DAYS" >>p2
		echo "Fifth field of /etc/shadow is set as $sk for id $i" >>p3
		echo "IZ.1.1.1.2" >>p12
		echo "yes" >>p4
	else
                echo "Password Requirements" >>p1
                echo "PASS_MAX_DAYS" >>p2
		echo "Fifth field of /etc/shadow is set as $sk for id $i" >>p3
		echo "no" >>p4
		echo "IZ.1.1.1.2" >>p12
        fi
done
rm -rf temp_passwd

#IZ.1.1.2.1:2nd field of /etc/shadow



cat /etc/shadow | awk -F":" '{print $1}' >temp_shadow2
for i in `cat temp_shadow2`
do
        sk1=`passwd -S $i |awk '{print $2}'`
        if [ "$sk1" == "NP" ]
        then
		echo "Password Requirements" >>p1
                echo "password specification within /etc/shadow" >>p2
		echo "A null password is assigned for user '$i'" >>p3
		echo "no" >>p4
		echo "IZ.1.1.2.1" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
                
	else
		echo "Password Requirements" >>p1
                echo "password specification within /etc/shadow" >>p2
		echo "User '$i' has no null value in second field of /etc/shadow" >>p3
		echo "IZ.1.1.2.1" >>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
               
        fi
done
rm -rf temp_shadow2

#IZ.1.1.2.2:2nd field of /etc/passwd
cat /etc/passwd | awk -F":" '{print $1}' >temp_passwd
for i in `cat temp_passwd`
do
        sk1=`cat /etc/passwd |grep -w ^$i |awk -F: '{print $2}'`
        if [ "$sk1" == "" ]
        then
		echo "Password Requirements" >>p1
                echo "second field of /etc/passwd" >>p2
		echo "The second field /etc/passwd is set as null for user $i" >>p3
		echo "no" >>p4
		echo "IZ.1.1.2.2" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
	else
		echo "Password_requirement" >>p1
                echo "second field of /etc/passwd" >>p2
		echo "The second field /etc/passwd is not set as null for user $i" >>p3
		echo "IZ.1.1.2.2" >>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
        fi
done
rm -rf temp_passwd


#IZ.1.1.3.1:PASS_MIN_DAYS
sm=`cat /etc/login.defs | grep -v "#"| grep ^PASS_MIN_DAYS  | awk '{print $2}' |uniq`
if [ "$sm" != "$PASS_MIN_DAYS" ]
then
	echo "Password Requirementss" >>p1
	echo "PASS_MIN_DAYS value in /etc/login.defs" >>p2
	echo "$sm" >>p3
	echo "no" >>p4
	echo IZ.1.1.3.1 >>p12
	echo "$c" >> p5
	echo "$z" >>p6
else
	echo "Password Requirementss" >>p1
	echo "PASS_MIN_DAYS value in /etc/login.defs" >>p2
	echo "$sm" >>p3
	echo "yes" >>p4
	echo IZ.1.1.3.1 >>p12
	echo "$c" >> p5
	echo "$z" >>p6
fi


#IZ.1.1.3.2:4th field of /etc/shadow - updated (06-05-2021)
cat /etc/passwd | egrep -v "/sbin/nologin|sync|shutdown|halt|/bin/false" | awk -F":" '{print $1}' >temp_passwd
for i in `cat temp_passwd`
do
sk=`chage -l $i |grep "^Minimum" |sed -e 's/://g' |awk '{print $8}'`
        if [ "$sk" -ge "$PASS_MIN_DAYS" ]
        then
                echo "Password Requirements" >>p1
                echo "Per-userid_Minimum_Password_Age" >>p2
		echo "Field 4 of /etc/shadow is set as "$sk" for id $i" >>p3
		echo "IZ.1.1.3.2" >>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	else
                echo "Password Requirements" >>p1
                echo "Per-userid_Minimum_Password_Age" >>p2
		echo "Field 4 of /etc/shadow is not set as "$sk" for id $i" >>p3
		echo "no" >>p4
		echo "IZ.1.1.3.2" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
        fi
done
rm -rf temp_passwd


#IZ.1.1.4.1:pam-settings
if [ -f /etc/pam.d/system-auth ]
then
	E=`cat /etc/pam.d/system-auth |grep -v '#' |grep ^password |egrep 'required|sufficient' |grep pam_unix.so |grep remember=$PAM_REMEMBER |egrep 'use_authtok|sha512|md5|shadow'`
	if [ $? -eq 0 ]
	then
		echo "Password Requirementss" >>p1
		echo "prevent_reuse_of_lat_eight_passwords" >>p2
		echo "pam_unix.so_remember value set correct in /etc/pam.d/system-auth" >>p3
		echo "yes" >> p4
		echo "IZ.1.1.4.1" >>p12
		echo "$c" >> p5
		echo "$z" >>p6	
	else
		echo "Password Requirementss" >>p1
		echo "prevent_reuse_of_lat_eight_passwords" >>p2
		echo "pam_unix.so_remember value not set correct in /etc/pam.d/system-auth" >>p3
		echo "no" >> p4
		echo "IZ.1.1.4.1" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
	fi
else
		echo "Password Requirementss" >>p1
		echo "prevent_reuse_of_lat_eight_passwords" >>p2
		echo "File-not-found-/etc/pam.d/system-auth. Please check the entry in /etc/pam.d/login, /etc/pam.d/passwd, /etc/pam.d/sshd and /etc/pam.d/su" >>p3
		echo "no" >> p4
		echo "IZ.1.1.4.1" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
fi

if [ -f /etc/pam.d/password-auth ]
then
	E=`cat /etc/pam.d/password-auth |grep -v '#' |grep ^password |egrep 'required|sufficient' |grep pam_unix.so |grep remember=$PAM_REMEMBER |egrep 'use_authtok|sha512|md5|shadow'`
	if [ $? -eq 0 ]
	then
		echo "Password Requirementss" >>p1
		echo "prevent_reuse_of_lat_eight_passwords" >>p2
		echo "pam_unix.so_remember value set correct in /etc/pam.d/password-auth" >>p3
		echo "yes" >> p4
		echo "IZ.1.1.4.1" >>p12
		echo "$c" >> p5
		echo "$z" >>p6	
	else
		echo "Password Requirementss" >>p1
		echo "prevent_reuse_of_lat_eight_passwords" >>p2
		echo "pam_unix.so_remember value not set correct in /etc/pam.d/password-auth" >>p3
		echo "no" >> p4
		echo "IZ.1.1.4.1" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
	fi
else
		echo "Password Requirementss" >>p1
		echo "prevent_reuse_of_lat_eight_passwords" >>p2
		echo "File-not-found-/etc/pam.d/password-auth. Please check the entry in /etc/pam.d/login, /etc/pam.d/passwd, /etc/pam.d/sshd and /etc/pam.d/su" >>p3
		echo "no" >> p4
		echo "IZ.1.1.4.1" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
fi

#IZ.1.1.6.0:loginretries value in password-auth and system-auth
if [ -f /etc/pam.d/system-auth ]
then
sk=`cat /etc/pam.d/system-auth |grep -v '#' | grep ^auth |grep required | egrep -w "pam_tally.so.*deny=5 |pam_tally2.so.*deny=5" |wc -l`
sl=`cat /etc/pam.d/system-auth |grep -v '#' | grep ^account |grep required | egrep -w "pam_tally.so |pam_tally2.so" |wc -l`
sk1=`cat /etc/pam.d/system-auth |grep -v '#' | grep ^auth |grep required | egrep -w "pam_faillock.so.*preauth.*deny=5" |wc -l`
sk2=`cat /etc/pam.d/system-auth |grep -v '#' | grep ^[default=die] | egrep -w "pam_faillock.so.*authfail.*deny=5" |wc -l`
sl1=`cat /etc/pam.d/system-auth |grep -v '#' | grep ^account |grep required | egrep -w "pam_faillock.so" |wc -l`
	if [ $sk -gt 0 ] && [ $sl -gt 0 ]
	then
		echo "Password Requirements"  >>p1
		echo "loginretries"  >>p2
		echo "Consecutive failed login attempts is set in /etc/pam.d/system-auth"  >>p3
		echo IZ.1.1.6.0  >>p12
		echo "yes"  >>p4
		echo "$c" >> p5
		echo "$z"  >> p6
	elif [ $sk1 -gt 0 ] && [ $sl1 -gt 0 ] &&  [ $sk2 -gt 0 ]
	then
		echo "Password Requirements"  >>p1
		echo "loginretries"  >>p2
		echo "Consecutive failed login attempts is set in /etc/pam.d/system-auth"  >>p3
		echo IZ.1.1.6.0  >>p12
		echo "yes"  >>p4
		echo "$c" >> p5
		echo "$z"  >> p6
	else
		echo "Password Requirements"  >>p1
		echo "loginretries"  >>p2
		echo "Consecutive failed login attempts is not set in /etc/pam.d/system-auth"  >>p3
		echo IZ.1.1.6.0  >>p12
		echo "no"  >>p4
		echo "$c" >> p5
		echo "$z"  >> p6
	fi
else
		echo "Password Requirements"  >>p1
		echo "loginretries"  >>p2
		echo "File not found /etc/pam.d/system-auth"
		echo IZ.1.1.6.0  >>p12
		echo "no"  >>p4
		echo "$c" >> p5
		echo "$z"  >> p6
fi
if [ -f /etc/pam.d/password-auth ]
then
sk=`cat /etc/pam.d/password-auth |grep -v '#' | grep ^auth |grep required | egrep -w "pam_tally.so.*deny=5 |pam_tally2.so.*deny=5" |wc -l`
sl=`cat /etc/pam.d/password-auth |grep -v '#' | grep ^account |grep required | egrep -w "pam_tally.so |pam_tally2.so" |wc -l`
sk1=`cat /etc/pam.d/password-auth |grep -v '#' | grep ^auth |grep required | egrep -w "pam_faillock.so.*preauth.*deny=5" |wc -l`
sk2=`cat /etc/pam.d/password-auth |grep -v '#' | grep ^[default=die] | egrep -w "pam_faillock.so.*authfail.*deny=5" |wc -l`
sl1=`cat /etc/pam.d/password-auth |grep -v '#' | grep ^account |grep required | egrep -w "pam_faillock.so" |wc -l`
	if [ $sk -gt 0 ] && [ $sl -gt 0 ]
	then
		echo "Password Requirements"  >>p1
		echo "loginretries"  >>p2
		echo "Consecutive failed login attempts is set in /etc/pam.d/password-auth"  >>p3
		echo IZ.1.1.6.0  >>p12
		echo "yes"  >>p4
		echo "$c" >> p5
		echo "$z"  >> p6
	elif [ $sk1 -gt 0 ] && [ $sl1 -gt 0 ] &&  [ $sk2 -gt 0 ]
	then
		echo "Password Requirements"  >>p1
		echo "loginretries"  >>p2
		echo "Consecutive failed login attempts is set in /etc/pam.d/password-auth"  >>p3
		echo IZ.1.1.6.0  >>p12
		echo "yes"  >>p4
		echo "$c" >> p5
		echo "$z"  >> p6
	else
		echo "Password Requirements"  >>p1
		echo "loginretries"  >>p2
		echo "Consecutive failed login attempts is not set in /etc/pam.d/password-auth"  >>p3
		echo IZ.1.1.6.0  >>p12
		echo "no"  >>p4
		echo "$c" >> p5
		echo "$z"  >> p6
	fi
else
		echo "Password Requirements"  >>p1
		echo "loginretries"  >>p2
		echo "File not found /etc/pam.d/password-auth"  >>p3
		echo IZ.1.1.6.0 >>p12
		echo "no"  >>p4
		echo "$c" >> p5
		echo "$z"  >> p6
fi





#IZ.1.1.7.1
szkl=`passwd -S root |awk '{print $2}'`
sk=`chage -l root |grep "^Maximum" |sed -e 's/://g' |awk '{print $8}'`
if [ "$szkl" == "PS" ] && [[ "$sk" -le "$PASS_MAX_DAYS" && "$sk" -gt "0" ]]
then
		echo "IZ.1.1.7.1" >>p12
		echo "Password Requirements" >>p1
		echo "Password and expiry settings for ROOT" >>p2
		echo "root_passwd_is_set and expiry period set as $sk" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
else
	
		echo "IZ.1.1.7.1" >>p12
		echo "Password Requirements" >>p1
		echo "Password and expiry settings for ROOT" >>p2
		echo "root_passwd setting is incorrect. Please check root password expiry and password status" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
fi


#IZ.1.1.7.2
sz=`cat /etc/ssh/sshd_config | grep -i "^PermitRootLogin" | awk '{print $2}' |uniq`
if [ "$sz" == "$PERMITROOTLOGIN" ]
then
		echo "Password Requirements" >>p1
        	echo "ROOT Login access must be restricted to the physical console" >>p2
		echo "PermitRootLogin is set as $sz in /etc/ssh/sshd_config. Interactive root login is disabled" >> p3
		echo "yes" >>p4
         	echo "$c" >> p5
                echo "$z" >>p6
		echo "IZ.1.1.7.2" >>p12
else
		echo "Password Requirementss" >>p1
        	echo "ROOT Login access must be restricted to the physical console" >>p2
		echo "PermitRootLogin is set as $sz in /etc/ssh/sshd_config. Interactive root login is enabled" >> p3
                echo "no" >>p4
                echo "$c" >> p5
                echo "$z" >>p6
		echo "IZ.1.1.7.2" >>p12
fi


#IZ.1.1.8.2:UID-validation
cat /etc/passwd | awk -F":" '{print $3}'| sort  | uniq -cd | awk '{print $2}'> temp_uid
sp=`cat temp_uid | wc -c`
if [ "$sp" == 0 ]
then
		echo "Password Requirementss" >>p1
		echo "UID_validation" >>p2
		echo  "No_duplicate_uid_value_for_users_in_/etc/passwd" >>p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "IZ.1.1.8.2" >>p12
		echo "$z" >>p6	
else
		for i in `cat temp_uid`
		do
		echo "Password Requirementss" >>p1
		echo "uid_validation" >>p2
		echo "Duplicate-uid-value-for-UID-$i" >>p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "IZ.1.1.8.2" >>p12
		echo "$z" >>p6	
		done
fi


#IZ.1.1.9.0:IZ.1.1.9.1:non-expiry-passwords
cat /etc/passwd | egrep -v "/sbin/nologin|sync|shutdown|halt|/bin/false" |awk -F: '{print $1}' > sys-user-info
for i in `cat sys-user-info`
do
sk=`passwd -S $i |awk '{print $2}'`
if [ "$sk" == "PS" ] || [ "$sk" == "NP" ]
then
	chage -l $i | grep -w 99999 
	if [ $? -eq 0 ]
	then
		echo "Password Requirementss" >>p1
		echo "Non-expiring passwords" >>p2
		echo "Expiry_passwd_value_not_exist_for_$i" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "IZ.1.1.9.0" >>p12
	else
		echo "Password Requirementss" >>p1
		echo "Non-expiring passwords" >>p2
		echo "Expiry_passwd_value_exist_for_$i" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "IZ.1.1.9.0" >>p12
	fi
else
		echo "Password Requirementss" >>p1
		echo "Non-expiring passwords" >>p2
		echo "Not applicable as user ID $i is locked" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "IZ.1.1.9.0" >>p12	
fi
done
rm -rf sys-user-info

#IZ.1.1.10.1
for i in `cat /etc/passwd | egrep -v "/sbin/nologin|sync|shutdown|halt|/bin/false" | awk -F":" '{print $1}'`
do
sk=`chage -l $i | grep "Password expires" |sed -e 's/://' | awk '{ print $3}'`
if [ "$sk" == "never" ]
then
	sl=`getent passwd $i |awk -F: '{print $7}'`
	if [ "$sl" == "/sbin/nologin" ] || [ "$sl" == "/bin/false" ]
	then
		echo "Password Requirementss" >>p1
		echo "direct_or_remote_login" >>p2
		echo "User $i has a valid shell $sl" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.1.10.1" >>p12
	else
		echo "Password Requirementss" >>p1
		echo "direct_or_remote_login" >>p2
		echo "User $i has invalid shell $sl as it is set as never expired" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.1.10.1" >>p12
	fi
else
		sl=`getent passwd $i |awk -F: '{print $7}'`
		echo "Password Requirementss" >>p1
		echo "direct_or_remote_login" >>p2
		echo "User $i has valid shell $sl" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.1.10.1" >>p12	
fi
done




#IZ.1.2.4.3 - updated
grep -v '^\s*#' /etc/pam.d/password-auth /etc/pam.d/system-auth | grep pam_faillock.so
if [ $? -eq 0 ] ; then
	if [ -d /var/run/faillock ] ; then
		echo "Logging" >>p1
		echo "Directory must exist for all systems using pam_faillock." >>p2
		echo "Directory exists for all systems using pam_faillock." >>p3
		echo "IZ.1.2.4.3">>p12
		echo "yes" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
			echo "$timestamp" >>en4	
	else
		echo "Logging" >>p1
		echo "Directory must exist for all systems using pam_faillock." >>p2
		echo "Directory does not exist for all systems using pam_faillock." >>p3
		echo "IZ.1.2.4.3">>p12
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
	echo "Directory must exist for all systems using pam_faillock." >>p2
	echo "pam_faillock module not exist in pasword-auth and system-auth" >>p3
	echo "IZ.1.2.4.3">>p12
	echo "yes" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
			echo "$timestamp" >>en4	
fi

#IZ.1.4.6.1
sp=`cat /etc/profile | grep -v '^\s*#' | egrep '^\s*TMOUT|/etc/profile.d/|done|\s*\.' |wc -l`
sl=`cat /etc/profile | grep -v '^\s*#' | egrep 'TMOUT|/etc/profile.d/|done|\s*\.' |grep '.*/etc/profile.d/IBMsinit.sh' |wc -l`
sm=`cat /etc/profile | grep -v '^\s*#' | egrep '^\s*TMOUT|/etc/profile.d/|done|\s*\.' |grep TMOUT |wc -l`
if [ $sp -gt 0 ] && [ $sl -gt 0 ] && [ $sm -ge 0 ]
then
	sk=`cat /etc/profile | grep -v '^\s*#' | egrep "for.*i|done" |grep TMOUT |head -1 |wc -l`
	sn=`cat /etc/profile | grep -v '^\s*#' | egrep "for.*i|done|TMOUT" |tail -1 |grep TMOUT |wc -l`
	if [ $sk -ge 0 ] && [ $sn -eq 0 ]
	then
		echo "System Settings" >>p1
		echo "Set systems to terminate a session after a period of inactivity - /etc/profile" >>p2
		echo "Session terminate setting is correct in /etc/profile" >>p3
		echo "IZ.1.4.6.1">>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	else

		echo "System Settings" >>p1
		echo "Set systems to terminate a session after a period of inactivity - /etc/profile" >>p2
		echo "Session terminate setting is not correct in /etc/profile. Please refer Techspec" >>p3
		echo "IZ.1.4.6.1">>p12
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	fi
else
		echo "System Settings" >>p1
		echo "Set systems to terminate a session after a period of inactivity - /etc/profile" >>p2
		echo "Session terminate setting is not correct in /etc/profile" >>p3
		echo "IZ.1.4.6.1">>p12
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
fi

#IZ.1.4.6.2
flag=0
sk=`which csh`
if [ $? -eq 0 ] ; then
	sk=`cat /etc/csh.login | grep -v '^\s*#' | egrep 'autologout|/etc/profile.d/|\s*source' | grep 'foreach i ( /etc/profile.d/\*.csh /etc/profile.d/csh.local )'`
	if [ $? -eq 0 ] ; then
		sk=`cat /etc/csh.login | grep -v '^\s*#' | egrep 'autologout|/etc/profile.d/|\s*source' | grep -v 'source "$i" >& /dev/null' | grep 'source "$i"'`
		if [ $? -eq 0 ] ; then
			sk=`cat /etc/csh.login | grep -v '^\s*#' | egrep 'autologout|/etc/profile.d/|\s*source' | grep 'source "$i" >& /dev/null'`
			if [ $? -eq 0 ] ; then
				flag=1
			fi
		fi
	fi
	
else
	flag=1
fi
sk=`cat /etc/csh.login | grep -v '^\s*#' | egrep 'autologout|/etc/profile.d/|\s*source' | grep 'set autologout=31'`
if [ $? -eq 0 ] ; then
	sk=`cat /etc/csh.login | grep -v '^\s*#' | egrep 'autologout|/etc/profile.d/|\s*source' | grep 'source /etc/profile.d/IBMsinit.csh'`
	if [ $? -eq 0 ] ; then
		flag=1
	fi
fi
if [ $flag == 1 ] ; then

	echo "System Settings" >>p1
	echo "Set systems to terminate a session after a period of inactivity - /etc/csh.login" >>p2
	echo "Systems terminates a session after a period of inactivity - /etc/csh.login" >>p3
	echo "IZ.1.4.6.2">>p12
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
else

	echo "System Settings" >>p1
	echo "Set systems to terminate a session after a period of inactivity - /etc/csh.login" >>p2
	echo "Systems does not terminate a session after a period of inactivity - /etc/csh.login" >>p3
	echo "IZ.1.4.6.2">>p12
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
fi


#IZ.1.4.6.3
if [ -f /etc/profile.d/IBMsinit.sh ] ; then
	grep '^[^#]*TMOUT' /etc/profile.d/IBMsinit.sh
	if [ $? -eq 0 ]
	then
	sk=`grep '^[^#]*TMOUT' /etc/profile.d/IBMsinit.sh |grep "TMOUT.*=" | awk -F '=' '{print $2}'`
		if [ "$sk" == "$TMOUT" ] ; then
			echo "System Settings" >>p1
			echo "Set systems to terminate a session after a period of inactivity - /etc/profile.d/IBMsinit.sh" >>p2
			echo "TMOUT value is specified as $sk in /etc/profile.d/IBMsinit.sh - Valid" >>p3
			echo "IZ.1.4.6.3">>p12
			echo "yes" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
		else

			echo "System Settings" >>p1
			echo "Set systems to terminate a session after a period of inactivity - /etc/profile.d/IBMsinit.sh" >>p2
			echo "TMOUT value is specified as $sk in /etc/profile.d/IBMsinit.sh - Invalid" >>p3
			echo "IZ.1.4.6.3">>p12
			echo "no" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
		fi
	else
			echo "System Settings" >>p1
			echo "Set systems to terminate a session after a period of inactivity - /etc/profile.d/IBMsinit.sh" >>p2
			echo "TMOUT is not mentioned in file /etc/profile.d/IBMsinit.sh" >>p3
			echo "IZ.1.4.6.3">>p12
			echo "no" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
	fi
else
			echo "System Settings" >>p1
			echo "Set systems to terminate a session after a period of inactivity - /etc/profile.d/IBMsinit.sh" >>p2
			echo "File not found /etc/profile.d/IBMsinit.sh" >>p3
			echo "IZ.1.4.6.3">>p12
			echo "no" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
fi

#IZ.1.4.6.4
if [ -f /etc/profile.d/IBMsinit.csh ] ; then
	sk=`grep '^[^#]*set \s*autologout' /etc/profile.d/IBMsinit.csh | awk -F '=' '{print $2}'`
	if [ $? -eq 0 ]; then
		if [ "$sk" == "$AUTOLOGOUT" ] ; then
			echo "System Settings" >>p1
			echo "Set systems to terminate a session after a period of inactivity - /etc/profile.d/IBMsinit.csh" >>p2
			echo "autologout setting is set as $AUTOLOGOUT in /etc/profile.d/IBMsinit.csh - valid" >>p3
			echo "IZ.1.4.6.4">>p12
			echo "yes" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
		else

			echo "System Settings" >>p1
			echo "Set systems to terminate a session after a period of inactivity - /etc/profile.d/IBMsinit.csh" >>p2
			echo "autologout setting is set as $AUTOLOGOUT in /etc/profile.d/IBMsinit.csh - invalid" >>p3
			echo "IZ.1.4.6.4">>p12
			echo "no" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
		fi
	else
		echo "System Settings" >>p1
		echo "Set systems to terminate a session after a period of inactivity - /etc/profile.d/IBMsinit.csh" >>p2
		echo "autologout setting not available in /etc/profile.d/IBMsinit.csh" >>p3
		echo "IZ.1.4.6.4">>p12
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	fi
else

	echo "System Settings" >>p1
	echo "Set systems to terminate a session after a period of inactivity - /etc/profile.d/IBMsinit.csh" >>p2
	echo "File not found /etc/profile.d/IBMsinit.csh" >>p3
	echo "IZ.1.4.6.4">>p12
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
fi


#IZ.1.4.6.5
flag=0
if [ -f /etc/skel/.cshrc ] ; then
	sk=`grep '^[^#]*TMOUT' /etc/skel/.cshrc | grep '^\s*TMOUT' | awk -F '=' '{print $2}'`
	if [ "$sk" != '' ] && [ $sk -le $TMOUT ] ; then
		sk=`grep '^[^#]*set \s*autologout' /etc/skel/.cshrc | awk -F '=' '{print $2}'`
		if [ "$sk" != '' ] && [ $sk -le $AUTOLOGOUT ] ; then
			flag=1
		else
			flag=0
		fi
	else
		flag=0
	fi
else
	flag=1
fi
if [ -f /etc/skel/.login ] ; then
	sk=`grep '^[^#]*TMOUT' /etc/skel/.login | grep '^\s*TMOUT' | awk -F '=' '{print $2}'`
	if [ "$sk" != '' ] && [ $sk -le $TMOUT ] ; then
		sk=`grep '^[^#]*set \s*autologout' /etc/skel/.login | awk -F '=' '{print $2}'`
		if [ "$sk" != '' ] && [ $sk -le $AUTOLOGOUT ] ; then
			flag=1
		else
			flag=0
		fi
	else
		flag=0
	fi
else
	flag=1
fi
if [ -f /etc/skel/.profile ] ; then
	sk=`grep '^[^#]*TMOUT' /etc/skel/.profile | grep '^\s*TMOUT' | awk -F '=' '{print $2}'`
	if [ "$sk" != '' ] && [ $sk -le $TMOUT ] ; then
		sk=`grep '^[^#]*set \s*autologout' /etc/skel/.profile | awk -F '=' '{print $2}'`
		if [ "$sk" != '' ] && [ $sk -le $AUTOLOGOUT ] ; then
			flag=1
		else
			flag=0
		fi
	else
		flag=0
	fi
else
	flag=1
fi
if [ -f /etc/skel/.tcshrc ] ; then
	sk=`grep '^[^#]*TMOUT' /etc/skel/.tcshrc | grep '^\s*TMOUT' | awk -F '=' '{print $2}'`
	if [ "$sk" != '' ] && [ $sk -le $TMOUT ] ; then
		sk=`grep '^[^#]*set \s*autologout' /etc/skel/.tcshrc | awk -F '=' '{print $2}'`
		if [ "$sk" != '' ] && [ $sk -le $AUTOLOGOUT ] ; then
			flag=1
		else
			flag=0
		fi
	else
		flag=0
	fi
else
	flag=1
fi
if [ -f /etc/skel/.bashrc ] ; then
	sk=`grep '^[^#]*TMOUT' /etc/skel/.bashrc | grep '^\s*TMOUT' | awk -F '=' '{print $2}'`
	if [ "$sk" != '' ] && [ $sk -le $TMOUT ] ; then
		sk=`grep '^[^#]*set \s*autologout' /etc/skel/.bashrc | awk -F '=' '{print $2}'`
		if [ "$sk" != '' ] && [ $sk -le $AUTOLOGOUT ] ; then
			flag=1
		else
			flag=0
		fi
	else
		flag=0
	fi
else
	flag=1
fi
if [ -f /etc/skel/.bash_profile ] ; then
	sk=`grep '^[^#]*TMOUT' /etc/skel/.bash_profile | grep '^\s*TMOUT' | awk -F '=' '{print $2}'`
	if [ "$sk" != '' ] && [ $sk -le $TMOUT ] ; then
		sk=`grep '^[^#]*set \s*autologout' /etc/skel/.bash_profile | awk -F '=' '{print $2}'`
		if [ "$sk" != '' ] && [ $sk -le $AUTOLOGOUT ] ; then
			flag=1
		else
			flag=0
		fi
	else
		flag=0
	fi
else
	flag=1
fi
if [ -f /etc/skel/.bash_login ] ; then
	sk=`grep '^[^#]*TMOUT' /etc/skel/.bash_login | grep '^\s*TMOUT' | awk -F '=' '{print $2}'`
	if [ "$sk" != '' ] && [ $sk -le $TMOUT ] ; then
		sk=`grep '^[^#]*set \s*autologout' /etc/skel/.bash_login | awk -F '=' '{print $2}'`
		if [ "$sk" != '' ] && [ $sk -le $AUTOLOGOUT ] ; then
			flag=1
		else
			flag=0
		fi
	else
		flag=0
	fi
else
	flag=1
fi
if [ $flag == 1 ] ; then

	echo "System Settings" >>p1
	echo "Ensure time out value is not overridden or is correctly established inside skeleton files." >>p2
	echo "time out value is not overridden or is correctly established inside skeleton files." >>p3
	echo "IZ.1.4.6.5">>p12
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
else

	echo "System Settings" >>p1
	echo "Ensure time out value is not overridden or is correctly established inside skeleton files." >>p2
	echo "time out value is overridden or is not correctly established inside skeleton files." >>p3
	echo "IZ.1.4.6.5">>p12
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
fi

#IZ.1.4.6.6
flag=1
Shells='/bin/csh|/bin/tcsh|/bin/sh|/bin/ksh|/bin/bash|/bin/sh|/bin/false|/sbin/nologin|/usr/bin/sh|/usr/bin/bash|/usr/sbin/nologin|/bin/ksh93|/usr/bin/ksh|/usr/bin/rksh|/usr/bin/ksh93|'
cat /etc/passwd | egrep -v '^sync:.*:/bin/sync\s*$|^halt:.*:/sbin/halt\s*$|^shutdown:.*:/sbin/shutdown\s*$' |
{ while read ENTRY
do
	SHELL=$(echo $ENTRY | awk -F: '{printf $7"\n"}')
	Uid=$(echo $ENTRY | awk -F: '{printf $1"\n"}')
	[[ "$SHELL" != @($Shells) ]] && flag=0
done 
if [ $flag == 1 ] ; then

	echo "System Settings" >>p1
	echo "Ensure login shell supports autologout/TMOUT function" >>p2
	echo "login shell supports autologout/TMOUT function" >>p3
	echo "IZ.1.4.6.6">>p12
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
else

	echo "System Settings" >>p1
	echo "Ensure login shell supports autologout/TMOUT function" >>p2
	echo "login shell does not support autologout/TMOUT function" >>p3
	echo "IZ.1.4.6.6">>p12
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
fi
}

#IZ.1.4.6.7
SHELLS=/etc/shells
OPTIONAL="/bin/false|/bin/ksh93|/usr/bin/ksh|/usr/bin/rksh|/usr/bin/ksh93"
printf "/bin/sh\n/bin/bash\n/sbin/nologin\n/usr/bin/sh\n/usr/bin/bash\n/usr/sbin/nologin\n/bin/tcsh\n/bin/csh\n/bin/ksh\n/bin/rksh\n" | sort -u >t1
sort -u "$SHELLS" | egrep -v "$OPTIONAL" >t2
sk=`diff t1 t2 | sed "s~<~/etc/shells is missing:~g;s~>~/etc/shells has this non-compliant entry:~g"`
if [ "$sk" == '' ] ; then

	echo "System Settings" >>p1
	echo "Restrict user selection to login shells which supports time out" >>p2
	echo "user selection to login shells supports time out" >>p3
	echo "IZ.1.4.6.7">>p12
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
else

	echo "System Settings" >>p1
	echo "Restrict user selection to login shells which supports time out" >>p2
	echo "user selection to login shells does not support time out" >>p3
	echo "IZ.1.4.6.7">>p12
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
fi
rm -rf t1 t2

#IZ.1.5.9.20.9

if [[ "$(sysctl net.ipv4.conf.all.rp_filter)" == "net.ipv4.conf.all.rp_filter = 1" ]]
then

	echo "Network Settings" >>p1
	echo "Ensure Reverse Path Filtering is enabled" >>p2
	echo "net.ipv4.conf.all.rp_filter value is set to 1" >>p3
	echo "IZ.1.5.9.20.9">>p12
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
else

	echo "Network Settings" >>p1
	echo "Ensure Reverse Path Filtering is enabled" >>p2
	echo "net.ipv4.conf.all.rp_filter value is not set to 1" >>p3
	echo "IZ.1.5.9.20.9">>p12
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
fi

if [[ "$(sysctl net.ipv4.conf.default.rp_filter)" == "net.ipv4.conf.default.rp_filter = 1" ]]
then

	echo "Network Settings" >>p1
	echo "Ensure Reverse Path Filtering is enabled" >>p2
	echo "sysctl net.ipv4.conf.default.rp_filter value is set to 1" >>p3
	echo "IZ.1.5.9.20.9">>p12
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
else

	echo "Network Settings" >>p1
	echo "Ensure Reverse Path Filtering is enabled" >>p2
	echo "sysctl net.ipv4.conf.default.rp_filter value is not set to 1" >>p3
	echo "IZ.1.5.9.20.9">>p12
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
fi

#IZ.1.5.10.3
rp=`rpm -q ypbind`
if [ $? -ne 0 ] ; then

	echo "Network Settings" >>p1
	echo "Ensure ypbind is not installed" >>p2
	echo "ypbind is not installed" >>p3
	echo "IZ.1.5.10.3">>p12
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
else

	echo "Network Settings" >>p1
	echo "Ensure ypbind is not installed" >>p2
	echo "ypbind is installed" >>p3
	echo "IZ.1.5.10.3">>p12
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
fi



##IZ.1.1.11.1;IZ.1.1.13.1;IZ.1.1.13.2:Non-expiring ID's
for i in `cat /etc/passwd | egrep -v "/sbin/nologin|sync|shutdown|halt|/bin/false" | awk -F":" '{print $1}'`; do
sk=`chage -l $i | grep "Password expires" |sed -e 's/://' | awk '{ print $3}'`
if [ "$sk" == "never" ]; then
	sk1=`passwd -S $i |awk '{print $2}'`
        if [ "$sk1" == "LK" ]; then
		echo "Password Requirementss" >>p1
		echo "direct_or_remote_login" >>p2
		echo "User $i has non-expiring password but the account is locked" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.1.11.1:IZ.1.1.13.1:IZ.1.1.13.2" >>p12
	else
		echo "Password Requirementss" >>p1
		echo "direct_or_remote_login" >>p2
		echo "User $i has non-expiring password but the account is not locked" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.1.11.1:IZ.1.1.13.1:IZ.1.1.13.2" >>p12
	fi
else
	echo "Password Requirementss" >>p1
	echo "direct_or_remote_login" >>p2
	echo "User $i has expiry password set" >>p3
	echo "yes" >>p4
	echo "$c" >>p5
	echo "$z" >>p6
	echo "IZ.1.1.11.1:IZ.1.1.13.1:IZ.1.1.13.2" >>p12	
fi
done

#IZ.1.1.13.3,IZ.1.1.10.2:FTP filecheck
ftpRPM=`rpm -q vsftpd`
if [ $? -ne 0 ]
then
		echo "Password Requirementss" >>p1
		echo "Restrict ftp access" >>p2
		echo "IZ.1.1.13.3:IZ.1.1.10.2" >>p12
		echo "Base package vsftpd is not installed" >> p3
		echo "Not_Applicable" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
else
if [ -f /etc/ftpusers ] || [ -f /etc/vsftpd.ftpusers ] || [ -f /etc/vsftpd/ftpusers ]
then
	smt=`cat /etc/ftpusers | wc -c`
	smr=`cat /etc/vsftpd.ftpusers | wc -c`
	smt1=`cat /etc/vsftpd/ftpusers | wc -c`
	if [ $smt -eq 0 ] || [ $smr -eq 0 ] || [ $smt1 -eq 0 ]
	then
		echo "Password Requirementss" >>p1
		echo "Restrict ftp access" >>p2
		echo "IZ.1.1.13.3:IZ.1.1.10.2" >>p12
		echo "ftp_file_exist-but-no-ftp-id" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	else
		echo "Password Requirementss" >>p1
		echo "Restrict ftp access" >>p2
		echo "ftp_file_exist-with-ftp-id" >> p3
		echo "no" >>p4
		echo "IZ.1.1.13.3:IZ.1.1.10.2" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
	fi
else
		echo "Password Requirementss" >>p1
		echo "Restrict ftp access" >>p2
		echo "IZ.1.1.13.3:IZ.1.1.10.2" >>p12
		echo "ftp_file_doesnt-exist" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
fi
fi


#IZ.1.1.13.4:PAM-yes
sk=`cat /etc/ssh/sshd_config |grep -v '#' |grep ^UsePAM |awk '{print $2}'`
if [ "$sk" == "yes" ]
then
	echo "Password Requirementss" >>p1
	echo "/etc/ssh/sshd_config" >>p2
	echo "UsePAM_yes_is_valid" >> p3
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
	echo "IZ.1.1.13.4" >>p12
else
	echo "Password Requirementss" >>p1
	echo "/etc/ssh/sshd_config" >>p2
	echo "IZ.1.1.13.4" >>p12
	echo "UsePAM_yes_is_invalid" >> p3
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
fi

#IZ.1.2.2:file-check
if [ -f /var/log/wtmp ]
then
	echo "Logging" >>p1
	echo "/var/log/wtmp" >>p2
	echo "/var/log/wtmp_exist" >> p3
	echo "yes" >>p4
	echo "$c" >> p5
	echo IZ.1.2.2 >>p12
	echo "$z" >>p6
else
	echo "Logging" >>p1
	echo "/var/log/wtmp" >>p2
	echo "/var/log/wtmp_doesnt_exist" >> p3
	echo "no" >>p4
	echo IZ.1.2.2 >>p12
	echo "$c" >> p5
	echo "$z" >>p6
fi

#IZ.1.2.3.1:file-check	
if [ -f /var/log/messages ]
then
	echo "Logging" >>p1
	echo "/var/log/messages" >>p2
	echo "/var/log/messsages_exist" >> p3
	echo "yes" >>p4
	echo "$c" >> p5
	echo IZ.1.2.3.1 >>p12
	echo "$z" >>p6
else
	echo "Logging" >>p1
	echo IZ.1.2.3.1 >>p12
	echo "/var/log/messages" >>p2
	echo "/var/log/messages_doesnt_exist" >> p3
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
fi


#IZ.1.2.4.2
if [ $(grep -v '^\s*#' /etc/pam.d/system-auth | grep pam_tally2.so |wc -l) -gt 0 ] || [ $(grep -v '^\s*#' /etc/pam.d/password-auth | grep pam_tally2.so |wc -l) -gt 0 ]
then
	if [ -f /var/log/tallylog ]
	then
		echo "Logging" >>p1
		echo "/var/log/tallylog" >>p2
		echo "file-exists-/var/log/tallylog">>p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "IZ.1.2.4.2" >>p12
	else
		echo "Logging" >>p1
		echo "/var/log/tallylog-permissions" >>p2
		echo "missing-file-/var/log/tallylog">>p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "IZ.1.2.4.2" >>p12
	fi
else
		echo "Logging" >>p1
		echo "/var/log/tallylog-permissions" >>p2
		echo "pam_tally2.so is not in use in /etc/pam.d/password-auth or /etc/pam.d/system-auth">>p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "IZ.1.2.4.2" >>p12
fi


#IZ.1.2.5:file-check
if [ -f /var/log/secure ]
then
		echo "Logging" >>p1
		echo "/var/log/secure" >>p2
		echo "File /var/log/secure exist" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo IZ.1.2.5 >>p12
else
		echo "Logging" >>p1
		echo "/var/log/secure" >>p2
		echo "File /var/log/secure not exist" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo IZ.1.2.5 >>p12
fi


#IZ.1.2.7.1:Logging
if [ "$(systemctl is-active chronyd)" == "active" ] && [ "$(systemctl is-enabled chronyd)" == "enabled" ]
then
	echo "Logging" >>p1
        echo "Synchronized system clocks, ensure it is active" >>p2
	echo "chronyd is active and running" >>p3
	echo "IZ.1.2.7.1">>p12
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
else

if [ "$(systemctl is-active ntpd)" == "active" ] && [ "$(systemctl is-enabled ntpd)" == "enabled" ]
then
	echo "Logging" >>p1
        echo "Synchronized system clocks, ensure it is active" >>p2
	echo "ntpd is active and running" >>p3
	echo "IZ.1.2.7.1">>p12
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
else
	echo "Logging" >>p1
        echo "Synchronized system clocks, ensure it is active" >>p2
	echo "chronyd or ntpd is not active and running" >>p3
	echo "IZ.1.2.7.1">>p12
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
fi
fi


#IZ.1.2.7.2:Logging
if [ "$(systemctl is-active chronyd)" == "active" ]
then
	egrep "^(server|pool)" /etc/chrony.conf
	if [ $? -eq 0 ]
	then
		sp=`timedatectl |grep 'synchronized' |awk -F: '{print $2}' |sed -e 's/ //'`
		if [ "$sp" == "yes" ]
		then
			echo "Logging" >>p1
			echo "Synchronized system clocks - chronyd has a server" >>p2
			echo "chronyd-is-active and time-is-synchronised" >>p3
			echo "IZ.1.2.7.2" >>p12
			echo "yes" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
		else
			echo "Logging" >>p1
			echo "Synchronized system clocks - chronyd has a server" >>p2
			echo "chronyd-is-active but time-is-not-synchronised" >>p3
			echo "IZ.1.2.7.2">>p12
			echo "no" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
		fi
	else
			echo "Logging" >>p1
			echo "Synchronized system clocks - chronyd has a server" >>p2
			echo "chronyd-is-active but no time server or pool configured" >>p3
			echo "IZ.1.2.7.2">>p12
			echo "no" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
	fi
else
		echo "Logging" >>p1
		echo "Synchronized system clocks - chronyd has a server" >>p2
		echo "chronyd-is-not-active" >>p3
		echo "IZ.1.2.7.2">>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
fi


#IZ.1.2.7.3:Logging - updated
if [ "$(systemctl is-active chronyd)" == "active" ]
then
	sm=`ps -ef |grep chronyd |grep -v "grep" |awk '{print $1}'`
	if [ "$sm" == "chrony" ] ; then
		echo "Logging" >>p1
                echo "Synchronized system clocks - chronyd does not have excess privilege" >>p2
		echo "The task is running as chrony ID" >>p3
		echo "IZ.1.2.7.3">>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	else
		echo "Logging" >>p1
                echo "Synchronized system clocks - chronyd does not have excess privilege" >>p2
		echo "The task is not running as chrony ID" >>p3
		echo "IZ.1.2.7.3">>p12
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	fi
else
		echo "Logging" >>p1
                echo "Synchronized system clocks - chronyd does not have excess privilege" >>p2
		echo "Chrony service is not active" >>p3
		echo "IZ.1.2.7.3">>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
fi

#IZ.1.2.7.4:Logging - updated
if [ "$(systemctl is-active ntpd)" == "active" ]
then
	val1=`cat /etc/ntp.conf |grep 'restrict default kod nomodify notrap nopeer noquery' |wc -c`
	val2=`cat /etc/ntp.conf |grep 'restrict -6 default kod nomodify notrap nopeer noquery' |wc -c`
	if [ $val1 -gt 0 ] || [ $val2 -gt 0 ] ; then
		echo "Logging" >>p1
        	echo "Synchronized system clocks - ntpd has secure defaults" >>p2
		echo "ntpd-is-active and key-defaults-for-both-ip4-and-ip6-is-set" >>p3
		echo "IZ.1.2.7.4">>p12
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
		echo "IZ.1.2.7.4">>p12
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
        	echo "Synchronized system clocks - ntpd has secure defaults" >>p2
		echo "ntpd is not active" >>p3
		echo "IZ.1.2.7.4">>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
		echo "$timestamp" >>en4
fi

#IZ.1.2.7.5:Logging - updated
if [ "$(systemctl is-active ntpd)" == "active" ]
then
	egrep "^(server|pool)" /etc/ntp.conf
	if [ $? -eq 0 ]
	then
		sp=`/usr/bin/ntpstat`
		if [ $? -eq 0 ]
		then
			echo "Logging" >>p1
			echo "Synchronized system clocks - ntpd has a server" >>p2
			echo "ntpd-is-active, time server is configured and time-is-synchronised" >>p3
			echo "IZ.1.2.7.5">>p12
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
			echo "ntpd-is-active, time server is configured but time-is-not-synchronised" >>p3
			echo "IZ.1.2.7.5">>p12
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
			echo "Synchronized system clocks - ntpd has a server" >>p2
			echo "ntpd-is-active but time server is not configured" >>p3
			echo "IZ.1.2.7.5">>p12
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
        	echo "Synchronized system clocks - ntpd has a server" >>p2
		echo "ntpd is not active" >>p3
		echo "IZ.1.2.7.5">>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
		echo "$timestamp" >>en4
fi

#IZ.1.2.7.6
if [ "$(systemctl is-active ntpd)" == "active" ]
then
	sm=`ps -ef |grep ntpd |grep -v "grep" |awk '{print $1}'`
	if [ "$sm" == "ntp" ]
	then
		echo "Logging" >>p1
                echo "Synchronized system clocks, ensure it is active" >>p2
		echo "ntpd is running with ntp ID" >>p3
		echo "IZ.1.2.7.6">>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	else
		echo "Logging" >>p1
                echo "Synchronized system clocks, ensure it is active" >>p2
		echo "ntpd is not running with ntp ID" >>p3
		echo "IZ.1.2.7.6">>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	fi
else
		echo "Logging" >>p1
                echo "Synchronized system clocks, ensure it is active" >>p2
		echo "ntpd is not active" >>p3
		echo "IZ.1.2.7.6">>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
fi


#IZ.1.4.1
sk=`cat /etc/pam.d/other |grep ^auth |grep required |grep pam_deny.so |wc -l`
sl=`cat /etc/pam.d/other |grep ^account |grep required |grep pam_deny.so |wc -l`
if [ $sk -gt 0 ] && [ $sl -gt 0 ]
then
	echo "System Settings" >>p1
	echo "/etc/pam.d/other" >>p2
	echo "auth-required-account-required-has-pam_deny.so in file /etc/pam.d/other" >>p3
	echo "yes" >>p4
	echo "$c" >>p5
	echo "$z" >>p6
	echo "IZ.1.4.1" >>p12
else
	if [ $sk -eq 0 ] 
	then
		echo "System Settings" >>p1
		echo "/etc/pam.d/other" >>p2
		echo "auth-required-doesnt-have-pam_deny.so in file /etc/pam.d/other" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.4.1" >>p12
	else
		echo "System Settings" >>p1
		echo "/etc/pam.d/other" >>p2
		echo "auth-required-has-pam_deny.so in file /etc/pam.d/other" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.4.1" >>p12
	fi

	if [ $sl -eq 0 ]
	then
			echo "System Settings" >>p1
			echo "/etc/pam.d/other" >>p2
			echo "account-required-doesnt-have-pam_deny.so in file /etc/pam.d/other" >>p3
			echo "no" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "IZ.1.4.1" >>p12
	else
			echo "System Settings" >>p1
			echo "/etc/pam.d/other" >>p2
			echo "account-required-has-pam_deny.so in file /etc/pam.d/other" >>p3
			echo "yes" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "IZ.1.4.1" >>p12
	fi
fi

#IZ.1.5.1.1
if [ "$(rpm -q ftp)" != "package ftp is not installed" ] || [ "$(rpm -q vsftpd)" != "package vsftpd is not installed" ]
then
	sk=`systemctl is-enabled ftpd`
	sl=`systemctl is-enabled vsftpd`
	if [ "$sk" == "enabled" ] || [ "$sl" == "enabled" ]
	then
		sp=`cat /etc/vsftpd/vsftpd.conf |grep ^anonymous_enable |awk -F"=" '{print $2}'`
		if [ "$sp" == "YES" ]
		then
			grep "^ftp" /etc/xinetd.d/wu-ftpd | grep "-u" | grep -q 027
			if [ $? -eq 0 ]
			then
					echo "Network Settingss" >> p1
					echo "Anonymous FTP System Settings" >>p2
					echo "FTP service is running and anonymous write is allowed and wu-ftpd is in use" >>p3
					echo "IZ.1.5.1.1">>p12
					echo "yes" >>p4
					echo "$c" >>p5
					echo "$z" >>p6
			else
					echo "Network Settingss" >> p1
					echo "Anonymous FTP System Settings" >>p2
					echo "FTP service is running but anonymous write setting is not correct" >>p3
					echo "IZ.1.5.1.1">>p12
					echo "no" >>p4
					echo "$c" >>p5
					echo "$z" >>p6
			fi
		else
			echo "Network Settingss" >> p1
			echo "Anonymous FTP System Settings" >>p2
			echo "ftpd or vsftpd service is enabled but anonymous FTP setting is disabled " >>p3
			echo "IZ.1.5.1.1">>p12
			echo "yes" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
		fi
	else
			echo "Network Settingss" >> p1
			echo "Anonymous FTP System Settings" >>p2
			echo "ftpd or vsftpd package is installed but ftpd or vsftpd service is not enabled " >>p3
			echo "IZ.1.5.1.1">>p12
			echo "yes" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
	fi
else
			echo "Network Settingss" >> p1
			echo "Anonymous FTP System Settings" >>p2
			echo "ftpd or vsftpd package is not installed" >>p3
			echo "IZ.1.5.1.1">>p12
			echo "yes" >>p4
			echo "$c" >>p5
			echo "$z" >>p6

fi

#IZ.1.5.1.2:IZ.1.5.1.3:IZ.1.5.1.4:IZ.1.5.1.5:IZ.1.5.1.6:IZ.1.5.1.7:IZ.1.5.1.8
if [ "$(rpm -q ftp)" != "package ftp is not installed" ] || [ "$(rpm -q vsftpd)" != "package vsftpd is not installed" ]
then
	sk=`systemctl is-enabled ftpd`
	sl=`systemctl is-enabled vsftpd`
	if [ "$sk" == "enabled" ] || [ "$sl" == "enabled" ]
	then
		sp=`cat /etc/vsftpd/vsftpd.conf |grep ^anonymous_enable |awk -F"=" '{print $2}'`
		if [ "$sp" == "YES" ]
		then
			echo "Network Settingss" >> p1
			echo "Anonymous FTP System Settings" >>p2
			echo "Anonymous FTP is enabled. Please check Techspec for correct setting" >>p3
			echo "IZ.1.5.1.2:IZ.1.5.1.3:IZ.1.5.1.4:IZ.1.5.1.5:IZ.1.5.1.6:IZ.1.5.1.7:IZ.1.5.1.8">>p12
			echo "no" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
		else
			echo "Network Settingss" >> p1
			echo "Anonymous FTP System Settings" >>p2
			echo "Anonymous FTP is disabled" >>p3
			echo "IZ.1.5.1.2:IZ.1.5.1.3:IZ.1.5.1.4:IZ.1.5.1.5:IZ.1.5.1.6:IZ.1.5.1.7:IZ.1.5.1.8">>p12
			echo "yes" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
		fi

	else
			echo "Network Settingss" >> p1
			echo "Anonymous FTP System Settings" >>p2
			echo "ftpd or vsftpd package is installed but ftpd or vsftpd service is not enabled " >>p3
			echo "IZ.1.5.1.2:IZ.1.5.1.3:IZ.1.5.1.4:IZ.1.5.1.5:IZ.1.5.1.6:IZ.1.5.1.7:IZ.1.5.1.8">>p12
			echo "yes" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
	fi
else
			echo "Network Settingss" >> p1
			echo "Anonymous FTP System Settings" >>p2
			echo "ftpd or vsftpd package is not installed" >>p3
			echo "IZ.1.5.1.2:IZ.1.5.1.3:IZ.1.5.1.4:IZ.1.5.1.5:IZ.1.5.1.6:IZ.1.5.1.7:IZ.1.5.1.8">>p12
			echo "yes" >>p4
			echo "$c" >>p5
			echo "$z" >>p6

fi

#IZ.1.5.2.1;IZ.1.5.2.2:TFTP filecheck
rpm -qa |egrep "tftp-server|tftp"
if [ $? -ne 0 ]
then
		echo "Network Settings" >>p1
		echo "TFTP System Setting" >>p2
		echo "IZ.1.5.2.1" >>p12
		echo "Base package tftp or tftp-server is not installed" >> p3
		echo "Not_Applicable" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
else
		echo "Network Settings" >>p1
		echo "TFTP System Setting" >>p2
		echo "IZ.1.5.2.1" >>p12
		echo "Base package tftp or tftp-server is installed. Please check the Techspec for Additional check" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
fi

#IZ.1.5.3.1
systemctl is-enabled nfs-server
if [ $? -eq 0 ]
then
	sk=`ls -ld /etc/exports |awk '{print $3}'` 
	szm=$(stat -c "%a %n" /etc/exports |awk '{print $1}')
	if [ "$sk" == "root" ] && [[ "$szm" == "644" || "$szm" == "640" || "$szm" == "600" ]]
	then
		echo "Network Settingss" >>p1
		echo "/etc/exports" >>p2
		echo "NFS service is enabled and file permission is correct" >> p3
		echo "yes" >>p4
		echo "IZ.1.5.3.1" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
	else
		echo "Network Settingss" >>p1
		echo "/etc/exports" >>p2
		echo "NFS service is enabled and file permission is incorrect" >> p3
		echo "no" >>p4
		echo "$z" >>p6
		echo "$c" >> p5
		echo "IZ.1.5.3.1" >>p12
	fi
else
		echo "Network Settingss" >>p1
		echo "/etc/exports" >>p2
		echo "NFS service is not enabled" >> p3
		echo "yes" >>p4
		echo "$z" >>p6
		echo "$c" >> p5
		echo "IZ.1.5.3.1" >>p12
fi

#IZ.1.5.4.1
if [ -f /etc/hosts.equiv ]
then
	echo "Network Settings" >>p1
	echo "/etc/hosts.equiv" >>p2
	echo "/etc/hosts.equiv-file-exist" >> p3
	echo "IZ.1.5.4.1" >>p12
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
else
	echo "Network Settings" >>p1
	echo "/etc/hosts.equiv" >>p2
	echo "/etc/hosts.equiv-file-not-exist" >> p3
	echo "IZ.1.5.4.1" >>p12
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6

fi

#IZ.1.5.3.3
systemctl is-enabled nfs-server
if [ $? -eq 0 ]
then
	sk=`grep no_root_squash /etc/exports |wc -l`
	if [ $sk -gt 0 ]
	then
		echo "Network Settingss" >>p1
		echo "/etc/exports" >>p2
		echo "NFS service is enabled and no_root_squash option is there in /etc/exports" >> p3
		echo "no" >>p4
		echo "IZ.1.5.3.3" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
	else
		echo "Network Settingss" >>p1
		echo "/etc/exports" >>p2
		echo "NFS service is enabled and no_root_squash option is not there in /etc/exports" >> p3
		echo "yes" >>p4
		echo "$z" >>p6
		echo "$c" >> p5
		echo "IZ.1.5.3.3" >>p12
	fi
else
		echo "Network Settingss" >>p1
		echo "/etc/exports" >>p2
		echo "NFS service is not enabled" >> p3
		echo "yes" >>p4
		echo "$z" >>p6
		echo "$c" >> p5
		echo "IZ.1.5.3.3" >>p12
fi

#IZ.1.5.4.2
if [ -f /etc/pam.d/rlogin ] || [ -f  /etc/pam.d/rsh ]
then
	sm=`grep "^[^#]*pam_rhosts_auth.so" /etc/pam.d/rlogin | grep -v no_hosts_equiv |wc -l`
	sn=`grep "^[^#]*pam_rhosts_auth.so" /etc/pam.d/rsh | grep -v no_hosts_equiv |wc -l`
	if [ $sm -eq 0 ] || [ $sn -eq 0 ] 
	then
		echo "Network Settingss" >>p1
		echo "/etc/pam.d-and-etc/pam.d/rlogin" >>p2
		echo "pam_rhosts_auth.so and no_hosts_equiv stanza is not present in-/etc/pam.d/rlogin or /etc/pam.d/rsh" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo IZ.1.5.4.2 >>p12
		echo "$z" >>p6
	else
		echo "Network Settingss" >>p1
		echo "/etc/pam.d-and-etc/pam.d/rlogin" >>p2
		echo "Required-settings-not-found-in-file-/etc/pam.d/rlogin-and-/etc/pam.d/rsh" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo IZ.1.5.4.2 >>p12
	fi
else
		echo "Network Settingss" >>p1
		echo "/etc/pam.d-and-etc/pam.d/rlogin" >>p2
		echo "Files /etc/pam.d/rlogin or /etc/pam.d/rsh not exists" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo IZ.1.5.4.2 >>p12
fi


#IZ.1.5.5:rexd daemon
if [ -f /etc/inetd.conf ] || [ -f /etc/xinetd.d/xinted.conf ]
then
	sk=`cat /etc/inetd.conf | grep -v "#" | grep -i ^rexd |wc -l`
	sl=`cat /etc/xinetd.d/xinted.conf | grep -v "#" | grep -i ^rexd |wc -l`
	if [ $sk -gt 0 ] || [ $sl -gt 0 ]
	then
		echo "Network Settingss" >>p1
		echo "rexd daemon" >>p2
		echo "rexd deamon is runnig" >> p3
		echo "no" >>p4
		echo  "IZ.1.5.5">>p12
		echo "$c" >> p5
		echo "$z" >>p6
	else
		echo "Network Settingss" >>p1
		echo "rexd daemon" >>p2
		echo "rexd deamon is not runnig" >> p3
		echo "yes" >>p4
		echo  "IZ.1.5.5">>p12
		echo "$c" >> p5
		echo "$z" >>p6
	fi
else
		echo "Network Settingss" >>p1
		echo "rexd daemon" >>p2
		echo "File /etc/inetd.conf or /etc/xinetd.d/xinted.conf not exists " >> p3
		echo "yes" >>p4
		echo  "IZ.1.5.5">>p12
		echo "$c" >> p5
		echo "$z" >>p6
fi


#IZ.1.5.7
if [ $(rpm -qa xorg-x11* | wc -l) -eq 0 ]
then
	echo "Network Settings" >>p1
	echo "X-server access control" >>p2
	echo "X-server packages not installed" >>p3
	echo "Not_Applicable" >>p4
	echo "$c" >>p5
	echo "$z" >>p6
	echo "IZ.1.5.7" >>p12
else
sk=`which xhost`
if [ $? -eq 0 ]
then
	$sk
	if [ $? -eq 0 ]
	then
		$sk |grep enabled
		if [ $? -eq 0 ]
		then
			echo "Network Settings" >>p1
			echo "X-server access control" >>p2
			echo "X-server packages installed and Access control is enabled via xhost" >>p3
			echo "yes" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "IZ.1.5.7" >>p12
		else
			echo "Network Settings" >>p1
			echo "X-server access control" >>p2
			echo "Access control is disabled via xhost. Please check xhost command output and run 'xhost -'" >>p3
			echo "no" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "IZ.1.5.7" >>p12
		fi
	else
		echo "Network Settings" >>p1
		echo "X-server access control" >>p2
		echo "X-server packages installed but xhost is not enabled or disabled" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.5.7" >>p12
	fi	
else
	echo "Network Settings" >>p1
	echo "X-server access control" >>p2
	echo "X-server packages installed but Xhost command not found" >>p3
	echo "yes" >>p4
	echo "$c" >>p5
	echo "$z" >>p6
	echo "IZ.1.5.7" >>p12
fi
fi

#IZ.1.5.9.1;IZ.1.5.9.2;IZ.1.5.9.7;IZ.1.5.9.8;IZ.1.5.9.9
for service in chargen-dgram chargen-stream daytime-dgram daytime-stream discard-dgram discard-stream echo-dgram echo-stream time-dgram time-stream bootps
do
sk=`chkconfig --list 2>/dev/null |awk '{$1=$1};1' |grep ^$service |awk -F":" '{print $2}' |awk '{$1=$1};1'`
if [ "$sk" == "on" ]
then
	echo "Network Settings" >>p1
	echo "Denial of Service through xinetd or inetd" >>p2
	echo "Service $service is enabled in chkconfig" >>p3
	echo "no" >>p4
	echo "IZ.1.5.9.1;IZ.1.5.9.2;IZ.1.5.9.7;IZ.1.5.9.8;IZ.1.5.9.9" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
else
	echo "Network Settings" >>p1
	echo "Denial of Service through xinetd or inetd" >>p2
	echo "Service $service is not enabled in chkconfig" >>p3
	echo "yes" >>p4
	echo "IZ.1.5.9.1;IZ.1.5.9.2;IZ.1.5.9.7;IZ.1.5.9.8;IZ.1.5.9.9" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
done


#IZ.1.5.9.23
rpm -qa |grep telnet-server
if [ $? -eq 0 ]
then
	systemctl is-enabled telnet.socket
	if [ $? -eq 0 ]
	then
		echo "Network Settings" >>p1
		echo "telnet-service" >>p2
		echo "telnet-server package is installed and telnet.socket service is enabled" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.5.9.23" >>p12
	else
		echo "Network Settings" >>p1
		echo "telnet-service" >>p2
		echo "telnet-server package is installed but telnet.socket service is disabled" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.5.9.23" >>p12
	fi
else
		echo "Network Settings" >>p1
		echo "telnet-service" >>p2
		echo "telnet-server package is not installed" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.5.9.23" >>p12
fi

#IZ.1.5.9.24.2
systemctl is-enabled vsftpd
if [ $? -eq 0 ] ; then
sp=`cat /etc/vsftpd/vsftpd.conf |grep ^anonymous_enable |awk -F"=" '{print $2}'`
	if [ "$sp" == "YES" ]
	then	
		echo "Network Settings" >>p1
		echo "Disable anonymous ftp if vsftpd is enabled" >>p2
		echo "vsftpd service is enabled and anonymous_enable is set as YES" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "IZ.1.5.9.24.2" >>p12
	else
		echo "Network Settings" >>p1
		echo "Disable anonymous ftp if vsftpd is enabled" >>p2
		echo "vsftpd service is enabled and anonymous_enable is set as $sp" >> p3
		echo "yes" >>p4
		echo "IZ.1.5.9.24.2" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
	fi
else
	echo "Network Settings" >>p1
	echo "Disable anonymous ftp if vsftpd is enabled" >>p2
	echo "vsftpd service is disabled" >> p3
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
	echo "IZ.1.5.9.24.2" >>p12
fi



#IZ.1.5.10.1
rpm -q ypserv ypbind portmap yp-tools
if [ $? -eq 0 ]
then
	sl=`which service`
	$sl yppasswdd status
	if [ $? -eq 0 ]
	then
			echo "Network Settings" >>p1
			echo "yppasswdd-daemon" >>p2
			echo "yppasswdd-daemon-is-running" >>p3
			echo "no" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "IZ.1.5.10.1" >>p12
	else
			echo "Network Settings" >>p1
			echo "yppasswdd-daemon" >>p2
			echo "yppasswdd-daemon-is-not-running" >>p3
			echo "yes" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "IZ.1.5.10.1" >>p12
	fi
else
	echo "Network Settings" >>p1
	echo "yppasswdd-daemon" >>p2
	echo "NIS packages not installed." >>p3
	echo "yes" >>p4
	echo "$c" >>p5
	echo "$z" >>p6
	echo "IZ.1.5.10.1" >>p12
fi


#IZ.1.5.10.2
rpm -q ypbind
if [ $? -eq 0 ]
then
	echo "Network Settings" >>p1
	echo "NIS and NIS+ maps" >>p2
	echo "ypbind package is installed. Please check techspec for settings" >>p3
	echo "no" >>p4
	echo "$c" >>p5
	echo "$z" >>p6
	echo "IZ.1.5.10.2" >>p12
else
	echo "Network Settings" >>p1
	echo "NIS and NIS+ maps" >>p2
	echo "ypbind package is not installed" >>p3
	echo "yes" >>p4
	echo "$c" >>p5
	echo "$z" >>p6
	echo "IZ.1.5.10.2" >>p12
fi

#IZ.1.8.1.2
echo "/etc/init.d,/etc/rc.d,/etc/cron.d,/var/spool/cron/tabs/root,/opt,/var,/usr/local,/tmp,/etc,/usr,/,/etc/security/opasswd,/etc/shadow,/etc/passwd,/etc,/var/log,/var/log/faillog,/var/log/tallylog,/var/log/wtmp,/var/log/secure,/var/log/lastlog,/var/log/cron,/var/log/btmp,/var/log/hist,/var/log/sa,/var/log/maillog,/var/log/auth.log,/var/tmp,/var/log/messages,/etc/profile.d/IBMsinit.sh,/etc/profile.d/IBMsinit.csh,/etc/inittab,/var/spool/cron/root,/etc/crontab,/etc/xinetd.conf" > temp

tr "," "\n" < temp > temp1

Release=`cat /etc/os-release |grep -w "VERSION="|awk -F"=" '{print $2}'|cut -c2-|awk -F"." '{print $1}'`

if [ "$Release" == "7" ]
then
uid_minimum=`cat /etc/login.defs |grep ^UID_MIN|awk '{print $2}'`
	for i in `cat temp1`
	do
	if [ -f $i ] || [ -d $i ]
	then
		sj=`ls -lnd $i |awk '{print $3}'`
		ss=`ls -ld $i |awk '{print $3}'`
		if [ $sj -le $uid_minimum ]
		then
			echo "Protecting Resources - OSRs" >>p1
			echo "User Ownership" >>p2
			echo "The file or dir $i is owned by $ss - Permission is Valid" >>p3 
			echo "yes" >>p4
			echo "$c"  >>p5
			echo "$z"  >>p6
			echo "IZ.1.8.1.2" >>p12
		else
			echo "Protecting Resources - OSRs" >>p1
			echo "User Ownership" >>p2
			echo "The file or dir $i is owned by $ss - Permission is invalid" >>p3
			echo "no" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "IZ.1.8.1.2" >>p12
		fi
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "User Ownership" >>p2
		echo "The file or dir $i - File Doesnt Exists" >>p3
		echo "yes" >>p4
		echo "$c"  >>p5
		echo "$z"  >>p6
		echo "IZ.1.8.1.2" >>p12
	fi
	done
elif [ "$Release" == "8" ]
then
sys_uid_max=`cat /etc/login.defs |grep ^SYS_UID_MAX|awk '{print $2}'`

	for i in `cat temp1`
	do
	if [ -f $i ] || [ -d $i ]
	then
		sj=`ls -lnd $i |awk '{print $3}'`
		ss=`ls -ld $i |awk '{print $3}'`
		if [ $sj -le $sys_uid_max ]
		then
			echo "Protecting Resources - OSRs" >>p1
			echo "User Ownership" >>p2
			echo "The file or dir $i is owned by $ss - Permission is Valid" >>p3
			echo "yes" >>p4
			echo "$c" >>p5 
			echo "$z" >>p6
			echo "IZ.1.8.1.2" >>p12
		else
			echo "Protecting Resources - OSRs" >>p1
			echo "User Ownership" >>p2
			echo "The file or dir $i is owned by $ss - Permission is invalid" >>p3
			echo "no" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "IZ.1.8.1.2" >>p12
		fi
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "User Ownership" >>p2
		echo "The file or dir $i - File Doesnt Exists" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.8.1.2" >>p12
	fi
	done
else
	echo "Protecting Resources - OSRs" >>p1
	echo "User Ownership" >>p2
	echo "Its not RHEL"  >>p3
	echo "yes" >>p4
	echo "$c" >>p5
	echo "$z" >>p6
	echo "IZ.1.8.1.2" >>p12
fi


##########################################################################################################################333333

#IZ.1.8.1.3
echo "/etc/init.d,/etc/rc.d,/etc/cron.d,/var/spool/cron/tabs/root,/opt,/var,/usr/local,/tmp,/etc,/usr,/,/etc/security/opasswd,/etc/shadow,/etc/passwd,/etc,/var/log,/var/log/faillog,/var/log/tallylog,/var/log/wtmp,/var/log/secure,/var/log/lastlog,/var/log/cron,/var/log/btmp,/var/log/hist,/var/log/sa,/var/log/maillog,/var/log/auth.log,/var/tmp,/var/log/messages,/etc/profile.d/IBMsinit.sh,/etc/profile.d/IBMsinit.csh,/etc/inittab,/var/spool/cron/root,/etc/crontab,/etc/xinetd.conf" > temp

tr "," "\n" < temp > temp1

Release=`cat /etc/os-release |grep -w "VERSION="|awk -F"=" '{print $2}'|cut -c2-|awk -F"." '{print $1}'`
if [ $Release == "7" ]
then

gid_minimum=`cat /etc/login.defs |grep ^GID_MIN|awk '{print $2}'`
	for i in `cat temp1`
	do
	if [ -f $i ] || [ -d $i ]
	then
		sk=`ls -lnd $i |awk '{print $4}'`
		ss=`ls -ld $i |awk '{print $4}'`
		if [ $sk -le $gid_minimum ] && [ $sk -ne 100 ]
		then
			echo "Protecting Resources - OSRs" >>p1
			echo "Groupids assigned to OSRs" >>p2
			echo "This file or dir $i group is owned by $ss - Permission is Valid" >>p3
			echo "yes" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "IZ.1.8.1.3" >>p12
		else
			echo "Protecting Resources - OSRs" >>p1
			echo "Groupids assigned to OSRs"  >>p2
			echo "This file or dir $i is group owned by $ss - Permission is invalid" >>p3
			echo "no" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "IZ.1.8.1.3" >>p12
		fi
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "Groupids assigned to OSRs" >>p2
		echo "This file or dir $i - File Doesnt Exists" >>p3
		echo "yes" >>p4
		echo "$c"  >>p5
		echo "$z"  >>p6
		echo "IZ.1.8.1.3" >>p12
	fi
	done

elif [ $Release == "8" ]
then

sys_gid_max=`cat /etc/login.defs |grep ^SYS_GID_MAX |awk '{print $2}'`
	for i in `cat temp1`
	do
	if [ -f $i ] || [ -d $i ]
	then
		sk=`ls -lnd $i |awk '{print $4}'`
		ss=`ls -ld $i |awk '{print $4}'`
		if [ $sk -le $sys_gid_max ] && [ $sk -ne 100 ]
		then
			echo "Protecting Resources - OSRs" >>p1
			echo "Groupids assigned to OSRs"  >>p2
			echo "This file or dir $i group is owned by $ss - Permission is Valid" >>p3
			echo "yes" >>p4
			echo "$c"  >>p5
			echo "$z"  >>p6
			echo "IZ.1.8.1.3" >>p12
		else
			echo "Protecting Resources - OSRs" >>p1
			echo "Groupids assigned to OSRs" >>p2
			echo "This file or dir $i group is owned by $ss - Permission is invalid" >>p3
			echo "no" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "IZ.1.8.1.3" >>p12
		fi
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "Groupids assigned to OSRs" >>p2
		echo "This file or dir $i - File Doesnt Exists" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.8.1.3" >>p12
	fi
	done

else
	echo "Protecting Resources - OSRs" >>p1
	echo "User Ownership" >>p2
	echo "Its not RHEL" >>p3
	echo "yes" >>p4
	echo "$c" >>p5
	echo "$z" >>p6
	echo "IZ.1.8.1.3" >>p12
fi

#IZ.1.8.2.1
if [ -f ~root/.rhosts ]
then
	sz=$(stat -c "%a %n" ~root/.rhosts |awk '{print $1}')
	sk=`ls -ld ~root/.rhosts |awk '{print $4}'`
	if [ "$sz" == "600" ] && [ "$sk" == "root" ]
	then
		echo "Protecting Resources - OSRs" >>p1
		echo "~root/.rhosts" >>p2
		echo "The-file-is-read-write-only-by-root" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.8.2.1" >>p12
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "~root/.rhosts" >>p2
		echo "The-file-permission-is-set-incorrect" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.8.2.1" >>p12
	fi
else
		echo "Protecting Resources - OSRs" >>p1
		echo "~root/.rhosts" >>p2
		echo "The-file-is-not-available" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.8.2.1" >>p12
fi


#IZ.1.8.2.2
if [ -f ~root/.netrc ]
then
	sz=$(stat -c "%a %n" ~root/.netrc |awk '{print $1}')
	sk=`ls -ld ~root/.rhosts |awk '{print $4}'`
	if [ "$sz" == "600" ] && [ "$sk" == "root" ]
	then
		echo "Protecting Resources - OSRs" >>p1
		echo "~root/.netrc" >>p2
		echo "The-file-is-read-write-only-by-root" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.8.2.2" >>p12
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "~root/.netrc" >>p2
		echo "The-file-permission-is-set-incorrect" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.8.2.2" >>p12
	fi
else
		echo "Protecting Resources - OSRs" >>p1
		echo "~root/.netrc" >>p2
		echo "The-file-is-not-available" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.8.2.2" >>p12
fi

#IZ.1.8.3.1
str=`ls -ld / |awk '{print $1}' |cut -c9`
str1=`getfacl / |grep other |awk -F"::" '{print $2}' |cut -c 2`
sp=`getfacl / |grep other`
if [ "$str" == "w" ] || [ "$str1" == "w" ]
then
		echo "Protecting Resources - OSRs" >>p1
		echo "/-dir-permission" >>p2
		echo "/-dir-is-writtable-by-others and ACL for / is set as '$sp'" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.8.3.1" >>p12
else
		echo "Protecting Resources - OSRs" >>p1
		echo "/-dir-permission" >>p2
		echo "/-dir-permission-is-correctly-set" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.8.3.1" >>p12
fi

#IZ.1.8.3.3
str=`ls -ld /etc |awk '{print $1}' |cut -c9`
if [ "$str" == "w" ]
then
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc-dir-permission" >>p2
		echo "/etc-dir-is-writtable-by-others" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.8.3.3" >>p12
else
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc-dir-permission" >>p2
		echo "/etc-dir-permission-is-correctly-set" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.8.3.3" >>p12
fi

#IZ.1.8.4.1
if [ -f /etc/security/opasswd ]
then
str=$(stat -c "%a %n" /etc/security/opasswd |awk '{print $1}')
if [ "$str" == "600" ]
then
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/security/opasswd-permission" >>p2
		echo "/etc/security/opasswd-permission-is-correctly-set" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.8.4.1" >>p12
else
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/security/opasswd-permission" >>p2
		echo "/etc/security/opasswd-permission-is-incorrect" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.8.4.1" >>p12
fi
else
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/security/opasswd-permission" >>p2
		echo "/etc/security/opasswd file not exist" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.8.4.1" >>p12
fi

#IZ.1.8.5.1
str=`ls -ld /var |awk '{print $1}' |cut -c9`
if [ "$str" == "w" ]
then
		echo "Protecting Resources - OSRs" >>p1
		echo "/var-dir-permission" >>p2
		echo "/var-dir-is-writtable-by-others" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.8.5.1" >>p12
else
		echo "Protecting Resources - OSRs" >>p1
		echo "/var-dir-permission" >>p2
		echo "/var-dir-permission-is-correctly-set" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.8.5.1" >>p12
fi


#IZ.1.8.5.2
find /var/log -type d -perm /o+w \! -perm -1000 >world-writable-test
sk=`cat world-writable-test |wc -l`
if [ $sk -gt 0 ]
then
for i in `cat world-writable-test |grep -v "/bin/slogin"`
do
	echo "Protecting Resources - OSRs" >>p1
	echo "/var/log and it's sub-directories permissions" >>p2
	echo "Permission is invalid for $i" >> p3
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
	echo IZ.1.8.5.2 >>p12
done
else
	echo "Protecting Resources - OSRs" >>p1
	echo "/var/log and it's sub-directories permissions" >>p2
	echo "Permission-is-valid for /var/log and it's sub-directories" >> p3
	echo "yes" >>p4
	echo "$c" >> p5
	echo IZ.1.8.5.2 >>p12
	echo "$z" >>p6
fi
rm -rf world-writable-test



#IZ.1.8.6.2
if [ $(grep -v '^\s*#' /etc/pam.d/system-auth | grep pam_tally2.so |wc -l) -gt 0 ] || [ $(grep -v '^\s*#' /etc/pam.d/password-auth | grep pam_tally2.so |wc -l) -gt 0 ]
then
	str6=$(stat -c "%a %n" /var/log/tallylog |awk '{print $1}')
	if [ "$str6" == "600" ]
	then
			echo "Protecting Resources - OSRs" >>p1
			echo "/var/log/tallylog" >>p2
			echo "/var/log/tallylog-Permission-is-valid" >> p3
			echo "yes" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
			echo "IZ.1.8.6.2" >>p12
	else
			echo "Protecting Resources - OSRs" >>p1
			echo "/var/log/tallylog" >>p2
			echo "/var/log/tallylog-Permission-is-invalid" >> p3
			echo "no" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
			echo "IZ.1.8.6.2" >>p12
	fi
else
			echo "Protecting Resources - OSRs" >>p1
			echo "/var/log/tallylog" >>p2
			echo "Not applicable as pam_tally2 is not in use" >> p3
			echo "Not_Applicable" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
			echo "IZ.1.8.6.2" >>p12
fi


#IZ.1.8.7.1
str1=`ls -ld /var/log/messages | awk '{print $1}' | cut -c6`
str2=`ls -ld /var/log/messages | awk '{print $1}' | cut -c9`
#str5=$(stat -c "%a %n" /var/log/messages |awk '{print $1}')
#if [ "$str5" == "600" ] || [ "$str5" == "644" ] || [ "$str5" == "755" ]
if [ "$str1" != "w" ] && [ "$str2" != "w" ]
then
	echo "Protecting Resources - OSRs" >>p1
	echo "/var/log/messages-permissions" >>p2
	echo "/var/log/messages-permissions is set correct" >> p3
	echo "yes" >>p4
	echo "$c" >> p5
	echo "IZ.1.8.7.1" >>p12
	echo "$z" >>p6
else
	echo "Protecting Resources - OSRs" >>p1
	echo "/var/log/messages-permissions" >>p2
	echo "IZ.1.8.7.1" >>p12
	echo "/var/log/messages-permissions is not set correct" >> p3
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
fi

#IZ.1.8.7.2
str1=`ls -ld /var/log/wtmp | awk '{print $1}' | cut -c9`
if [ "$str1" != "w" ]
then
		echo "Protecting Resources - OSRs" >>p1
		echo "/var/log/wtmp-permission" >>p2
		echo "Permission-is-valid for /var/log/wtmp" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "IZ.1.8.7.2" >>p12
else
		echo "Protecting Resources - OSRs" >>p1
		echo "/var/log/wtmp-permission" >>p2
		echo "Permission-is-invalid for /var/log/wtmp" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "IZ.1.8.7.2" >>p12
fi

#IZ.1.8.8
str5=$(stat -c "%a %n" /var/log/secure |awk '{print $1}')
if [ "$str5" == "600" ] || [ "$str5" == "640" ] || [ "$str5" == "700" ] || [ "$str5" == "740" ]
then
		echo "Protecting Resources - OSRs" >>p1
		echo "/var/log/secure-permission" >>p2
		echo "Permission-is-valid for /var/log/secure" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "IZ.1.8.8" >>p12
else
		echo "Protecting Resources - OSRs" >>p1
		echo "/var/log/secure-permission" >>p2
		echo "Permission-is-invalid for /var/log/secure" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "IZ.1.8.8" >>p12
fi

#IZ.1.8.9
str7=$(stat -c "%a %n" /tmp |awk '{print $1}')
if [ "$str7" == "1777" ]
then
	echo "Protecting Resources - OSRs" >>p1
	echo "/tmp-permission" >>p2
	echo "/tmp-permission-is-valid" >> p3
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
	echo IZ.1.8.9 >>p12
else
	echo "Protecting Resources - OSRs" >>p1
	echo "/tmp-permission" >>p2
	echo "/tmp-permission-is-invalid" >> p3
	echo IZ.1.8.9 >>p12
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
fi

#IZ.1.8.15.2:IZ.1.8.15.3:IZ.1.8.18.2:IZ.1.8.20.2:IZ.1.8.22.1:IZ.1.8.22.2:IZ.1.8.22.3:IZ.1.8.22.4:IZ.1.8.13.1.2

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

fc=`cat world-writable-test|wc -l`

if [ $fc == 0 ] 
then
	echo "Protecting Resources - OSRs" >>p1
	echo "File-Directory-write-permissions-for-others" >>p2
	echo "No files found deviation $i" >> p3
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
	echo IZ.1.8.15.2:IZ.1.8.15.3:IZ.1.8.18.2:IZ.1.8.20.2:IZ.1.8.22.1:IZ.1.8.22.2:IZ.1.8.22.3:IZ.1.8.22.4:IZ.1.8.13.1.2 >>p12
else
	for i in `cat world-writable-test`
	do
		echo "Protecting Resources - OSRs" >>p1
		echo "File-Directory-write-permissions-for-others" >>p2
		echo "$i" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo IZ.1.8.15.2:IZ.1.8.15.3:IZ.1.8.18.2:IZ.1.8.20.2:IZ.1.8.22.1:IZ.1.8.22.2:IZ.1.8.22.3:IZ.1.8.22.4:IZ.1.8.13.1.2 >>p12
	done
fi
rm -rf world-writable-test

#IZ.1.8.10
if [ -f /etc/snmpd.conf ] || [ -f /etc/snmp/snmpd.conf ] || [ -f /etc/snmpd/snmpd.conf ]
then
str1=$(stat -c "%a %n" /etc/snmpd.conf |awk '{print $1}')
str2=$(stat -c "%a %n" /etc/snmp/snmpd.conf |awk '{print $1}')
str3=$(stat -c "%a %n" /etc/snmpd/snmpd.conf |awk '{print $1}')
	if [ "$str1" == "640" ] || [ "$str2" == "640" ] || [ "$str3" == "640" ]
	then
		echo "Protecting Resources - OSRs" >>p1
		echo "snmpd.conf-permission" >>p2
		echo "snmpd.conf-permission-is-valid" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "IZ.1.8.10" >>p12
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "snmpd.conf-permission" >>p2
		echo "snmpd.conf-permission-is-invalid" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "IZ.1.8.10" >>p12
	fi
else
		echo "Protecting Resources - OSRs" >>p1
		echo "snmpd.conf-permission" >>p2
		echo "snmpd.conf-file-not-exist" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "IZ.1.8.10" >>p12
fi


#IZ.1.8.11
str7=$(stat -c "%a %n" /var/tmp |awk '{print $1}')
if [ "$str7" == "1777" ]
then
	echo "Protecting Resources - OSRs" >>p1
	echo "/var/tmp-permission" >>p2
	echo "/var/tmp-permission-is-valid" >> p3
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
	echo IZ.1.8.11 >>p12
else
	echo "Protecting Resources - OSRs" >>p1
	echo "/var/tmp-permission" >>p2
	echo "/var/tmp-permission-is-invalid" >> p3
	echo IZ.1.8.11 >>p12
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
fi


#IZ.1.8.12.6
if [ -f /etc/profile.d/IBMsinit.sh ]
then
str4=`ls -l /etc/profile.d/IBMsinit.sh | awk '{print $1}' | cut -c9`
str5=`ls -l /etc/profile.d/IBMsinit.sh | awk '{print $1}' | cut -c6`
str6=`ls -l /etc/profile.d/IBMsinit.sh | awk '{print $3}'`
str7=`ls -l /etc/profile.d/IBMsinit.sh | awk '{print $4}'`
	if [ "$str4" != "w" ] && [ "$str5" != "w" ] && [ "$str6" == "root" ] && [ "$str7" == "root" ]
	then
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/profile.d/IBMsinit.sh-permissions" >>p2
		echo "/etc/profile.d/IBMsinit.sh-permission-is-valid" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo IZ.1.8.12.6 >>p12
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/profile.d/IBMsinit.sh-permissions" >>p2
		echo "/etc/profile.d/IBMsinit.sh-permission-is-not-valid" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo IZ.1.8.12.6 >>p12
	fi
else
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/profile.d/IBMsinit.sh-permissions" >>p2
		echo "/etc/profile.d/IBMsinit.sh-file-not-exist" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo IZ.1.8.12.6 >>p12
fi

#IZ.1.8.12.7
if [ -f /etc/profile.d/IBMsinit.csh ]
then
str4=`ls -l /etc/profile.d/IBMsinit.csh | awk '{print $1}' | cut -c9`
str5=`ls -l /etc/profile.d/IBMsinit.csh | awk '{print $1}' | cut -c6`
str6=`ls -l /etc/profile.d/IBMsinit.csh | awk '{print $3}'`
str7=`ls -l /etc/profile.d/IBMsinit.csh | awk '{print $4}'`
	if [ "$str4" != "w" ] && [ "$str5" != "w" ] && [ "$str6" == "root" ] && [ "$str7" == "root" ]
	then
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/profile.d/IBMsinit.csh-permissions" >>p2
		echo "/etc/profile.d/IBMsinit.csh-permission-is-valid" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo IZ.1.8.12.7 >>p12
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/profile.d/IBMsinit.csh-permissions" >>p2
		echo "/etc/profile.d/IBMsinit.csh-permission-is-not-valid" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo IZ.1.8.12.7 >>p12
	fi
else
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/profile.d/IBMsinit.csh-permissions" >>p2
		echo "/etc/profile.d/IBMsinit.csh-file-not-exist" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo IZ.1.8.12.7 >>p12
fi


#IZ.1.8.14.1
sk=`cat /var/spool/cron/root |grep -v '#' |grep -v '^$' |awk '{print $6}' |wc -l`
if [ $sk -gt 0 ]
then
cat /var/spool/cron/root |grep -v '#' |grep -v '^$' |awk '{print $6}' >t1
while IFS= read -r line
do
        sk1=`echo $line |cut -c 1`
        if [ "$sk1" == "/" ]
        then
                echo "Protecting Resources - OSRs" >>p1
                echo "/var/spool/cron/root" >>p2
		echo "Full-path-is-specified-for-command- $line in-/var/spool/cron/root" >>p3
		echo "IZ.1.8.14.1" >>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	else
                echo "Protecting Resources - OSRs" >>p1
                echo "/var/spool/cron/root" >>p2
		echo "Full-path-is-not-specified-for-command- $line in-/var/spool/cron/root" >>p3
		echo "no" >>p4
		echo "IZ.1.8.14.1" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
        fi
done <t1
else
		echo "Protecting Resources - OSRs" >>p1
                echo "/var/spool/cron/root" >>p2
		echo "No entry found in-/var/spool/cron/root" >>p3
		echo "IZ.1.8.14.1" >>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
fi
rm -rf t1


#IZ.1.8.14.2;IZ.1.8.14.3
sk=`cat /var/spool/cron/root |grep -v '#' |grep -v '^$' |awk '{print $6}' |wc -l`
if [ $sk -gt 0 ]
then
cat /var/spool/cron/root |grep -v '#' |grep -v '^$' |awk '{print $6}' >t1
while IFS= read -r line
do
        str=`find $line -type f -perm /o+w \! -perm -1000 |wc -l`
	if [ $str -eq 0 ]
        then
                echo "Protecting Resources - OSRs" >>p1
                echo "/var/spool/cron/root" >>p2
		echo "Permission for others in $line in /var/spool/cron/root is valid" >>p3
		echo "IZ.1.8.14.2;IZ.1.8.14.3" >>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	else
                echo "Protecting Resources - OSRs" >>p1
                echo "/var/spool/cron/root" >>p2
		echo "Permission for others in $line in /var/spool/cron/root is invalid" >>p3
		echo "no" >>p4
		echo "IZ.1.8.14.2;IZ.1.8.14.3" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
        fi
done <t1
else
		echo "Protecting Resources - OSRs" >>p1
                echo "/var/spool/cron/root" >>p2
		echo "No system facility entries exist in-/var/spool/cron/root" >>p3
		echo "yes" >>p4
		echo "IZ.1.8.14.2;IZ.1.8.14.3" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
fi
rm -rf t1

#IZ.1.8.15.1
cat /etc/crontab |grep -v '#' |egrep -v 'SHELL|PATH|MAILTO|HOME' |grep -v '^$' |awk '{print $6}' >t1
if [ $? -ne 0 ]
then
while IFS= read -r line
do
        sk1=`echo $line |cut -c 1`
        if [ "$sk1" == "/" ]
        then
                echo "Protecting Resources - OSRs" >>p1
                echo "/etc/crontab" >>p2
		echo "Full-path-is-specified-for-command- $line in-/etc/crontab" >>p3
		echo "IZ.1.8.15.1" >>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	else
                echo "Protecting Resources - OSRs" >>p1
                echo "/etc/crontab" >>p2
		echo "Full-path-is-not-specified-for-command- $line in-/etc/crontab" >>p3
		echo "no" >>p4
		echo "IZ.1.8.15.1" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
        fi
done <t1
else
		echo "Protecting Resources - OSRs" >>p1
                echo "/etc/crontab" >>p2
		echo "No-cron-entry-found-in-/etc/crontab" >>p3
		echo "yes" >>p4
		echo "IZ.1.8.15.1" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
fi
rm -rf t1

#IZ.1.8.15.2;IZ.1.8.15.3
cat /etc/crontab |grep -v '#' |egrep -v 'SHELL|PATH|MAILTO|HOME' |grep -v '^$' |awk '{print $6}' >t1
if [ $? -ne 0 ]
then
while IFS= read -r line
do
        str=`ls -ld $line |awk '{print $1}' |cut -c9`
	if [ "$str" != "w" ]
        then
                echo "Protecting Resources - OSRs" >>p1
                echo "/etc/crontab" >>p2
		echo "Permission for others in $line in /etc/crontab is valid" >>p3
		echo "IZ.1.8.15.2;IZ.1.8.15.3" >>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	else
                echo "Protecting Resources - OSRs" >>p1
                echo "/etc/crontab" >>p2
		echo "Permission for others in $line in /etc/crontab is invalid" >>p3
		echo "no" >>p4
		echo "IZ.1.8.15.2;IZ.1.8.15.3" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
        fi
done <t1
else
		echo "Protecting Resources - OSRs" >>p1
                echo "/etc/crontab" >>p2
		echo "No system facility entries exist in-/etc/crontab" >>p3
		echo "yes" >>p4
		echo "IZ.1.8.15.2;IZ.1.8.15.3" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
fi

#IZ.1.8.20.1

entries=/etc/cron.d/*
ls $entries | while read DIR
do
cPath=$(echo $(grep PATH $DIR | sed 's/^PATH=/:/')":" | sed 's~:/sbin:~:~g'| sed 's~:/bin:~:~g' | sed 's~:/usr/sbin:~:~g')
removeRun=''
[[ "$cPath" == ":/usr/bin:" ]] && removeRun='run-parts'
tVar=$(grep -v '^[[:space:]]*#' $DIR | awk '{print $7}' | awk '{print $1}' | grep -v '/' | grep -v internal | grep -v "^$removeRun$" | grep -v '^$')
if [ -n "$tVar" ]

then
        echo "Protecting Resources - User Resources" >>p1
        echo "/etc/cron.d/-directory-structure" >>p2
        echo "Full-path-is-not specified-for-command- $tVar in-/etc/cron.d/$DIR" >>p3
        echo "IZ.1.8.20.1" >>p12
        echo "No" >>p4
        echo "$c" >> p5
        echo "$z" >>p6
else
	echo "Protecting Resources - User Resources" >>p1
        echo "/etc/cron.d/-directory-structure" >>p2
        echo "Full-path-is specified-for-command- $tVar in-/etc/cron.d/$DIR">>p3
        echo "IZ.1.8.20.1" >>p12
        echo "Yes" >>p4
        echo "$c" >> p5
        echo "$z" >>p6
fi



done

rm -rf t1 file2

#IZ.1.9.1.2
sk=`cat /etc/bashrc |grep -v '#'  |sed -n '/$UID -gt 199/,/fi/p' |head -2 |grep umask |awk '{print $2}'`
if [ "$sk" == "002" ]
then
                echo "Protecting Resources - User Resources" >>p1
                echo "umask-value-in-/etc/bashrc" >>p2
		echo "umask-value-set-as-$sk" >>p3
		echo "IZ.1.9.1.2" >>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
else
                echo "Protecting Resources - User Resources" >>p1
                echo "umask-value-in-/etc/bashrc" >>p2
		echo "umask-value-set-incorrect-as $sk" >>p3
		echo "no" >>p4
		echo "IZ.1.9.1.2" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
fi


#IZ.1.9.1.2.1
sk=`grep "^[^#]*UMASK " /etc/login.defs |uniq |awk '{print $2}'`
if [ "$sk" == "077" ]
then
	echo "Protecting Resources - User Resources" >>p1
	echo "umask-value-in-/etc/login.defs" >>p2
	echo "umask-value set as 077 in /etc/login.defs" >>p3
	echo "IZ.1.9.1.2.1" >>p12
	echo "yes" >>p4
else
	echo "Protecting Resources - User Resources" >>p1
	echo "umask-value-in-/etc/login.defs" >>p2
	echo "umask-value not set as 077 in /etc/login.defs" >>p3
	echo "no" >>p4
	echo "IZ.1.9.1.2.1" >>p12
fi


#IZ.1.9.1.3
if [ -f /etc/profile.d/IBMsinit.sh ]
then
	cat /etc/profile.d/IBMsinit.sh |sed -n '/if/,/fi/p' |grep -v '#' |grep -i umask
	if [ $? -eq 0 ]
	then
		cat /etc/profile.d/IBMsinit.sh |grep -v '#' |grep -i umask >t1
		while IFS= read -r line
		do
		sk1=`echo $line | awk '{print $2}'`
	       		if [ "$sk1" == "077" ]
			then
		        	echo "Protecting Resources - User Resources" >>p1
		        	echo "umask-value-in-/etc/profile.d/IBMsinit.sh" >>p2
				echo "umask-value-set-as-$line" >>p3
				echo "IZ.1.9.1.3" >>p12
				echo "yes" >>p4
				echo "$c" >> p5
				echo "$z" >>p6
			else
		        	echo "Protecting Resources - User Resources" >>p1
		        	echo "umask-value-in-/etc/profile.d/IBMsinit.sh" >>p2
				echo "umask-value-set-as-$line" >>p3
				echo "no" >>p4
				echo "IZ.1.9.1.3" >>p12
				echo "$c" >> p5
				echo "$z" >>p6
			fi	
		done <t1
	else
		echo "Protecting Resources - User Resources" >>p1
                echo "umask-value-in-/etc/profile.d/IBMsinit.sh" >>p2
		echo "umask entry not exist in /etc/profile.d/IBMsinit.sh" >>p3
		echo "no" >>p4
		echo "IZ.1.9.1.3" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
	fi
		
else
		echo "Protecting Resources - User Resources" >>p1
                echo "umask-value-in-/etc/profile.d/IBMsinit.sh" >>p2
		echo "File-doesnt-exist-/etc/profile.d/IBMsinit.sh" >>p3
		echo "no" >>p4
		echo "IZ.1.9.1.3" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
fi
rm -rf t1

#IZ.1.9.1.4
if [ -f /etc/profile.d/IBMsinit.csh ]
then
	cat /etc/profile.d/IBMsinit.csh |sed -n '/if/,/endif/p' |grep -v '#' |grep -i umask
	if [ $? -eq 0 ]
	then
		cat /etc/profile.d/IBMsinit.csh |grep -v '#' |grep -i umask >t1
		while IFS= read -r line
		do
		sk1=`echo $line | awk '{print $2}'`
	       		if [ "$sk1" == "077" ]
			then
		        	echo "Protecting Resources - User Resources" >>p1
		        	echo "umask-value-in-/etc/profile.d/IBMsinit.csh" >>p2
				echo "umask-value-set-as-$line" >>p3
				echo "IZ.1.9.1.4" >>p12
				echo "yes" >>p4
				echo "$c" >> p5
				echo "$z" >>p6
			else
		        	echo "Protecting Resources - User Resources" >>p1
		        	echo "umask-value-in-/etc/profile.d/IBMsinit.csh" >>p2
				echo "umask-value-set-as-$line" >>p3
				echo "no" >>p4
				echo "IZ.1.9.1.4" >>p12
				echo "$c" >> p5
				echo "$z" >>p6
			fi	
		done <t1
	else
				echo "Protecting Resources - User Resources" >>p1
		        	echo "umask-value-in-/etc/profile.d/IBMsinit.csh" >>p2
				echo "umask-value not exist in /etc/profile.d/IBMsinit.csh" >>p3
				echo "no" >>p4
				echo "IZ.1.9.1.4" >>p12
				echo "$c" >> p5
				echo "$z" >>p6
	fi
else
		echo "Protecting Resources - User Resources" >>p1
                echo "umask-value-in-/etc/profile.d/IBMsinit.csh" >>p2
		echo "File-doesnt-exist-/etc/profile.d/IBMsinit.csh" >>p3
		echo "no" >>p4
		echo "IZ.1.9.1.4" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
fi
rm -rf t1

#IZ.1.9.1.5:IBMsinit.sh
if [ -f /etc/profile.d/IBMsinit.sh ]
then
cat /etc/profile  |grep '.*/etc/profile.d/IBMsinit.sh'
if [ $? -eq 0 ]
then
		echo "Protecting Resources - User Resources" >>p1
                echo "/etc/profile " >>p2
		echo "/etc/profile.d/IBMsinit.sh_is_enabled" >>p3
		echo "IZ.1.9.1.5">>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
else
		echo "Protecting Resources - User Resources" >>p1
                echo "/etc/profile " >>p2
		echo "/etc/profile.d/IBMsinit.sh_is_not_enabled" >>p3
		echo "IZ.1.9.1.5">>p12
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
fi
else
		echo "Protecting Resources - User Resources" >>p1
                echo "/etc/profile " >>p2
		echo "File /etc/profile.d/IBMsinit.sh not exists" >>p3
		echo "IZ.1.9.1.5">>p12
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
fi

#IZ.1.9.1.6:IBMsinit.csh
if [ -f /etc/profile.d/IBMsinit.csh ]
then
cat /etc/csh.login | grep 'source.*/etc/profile.d/IBMsinit.csh'
if [ $? -eq 0 ]
then
		echo "Protecting Resources - User Resources" >>p1
                echo "/etc/csh.login " >>p2
		echo "/etc/profile.d/IBMsinit.csh_is_enabled" >>p3
		echo "IZ.1.9.1.6">>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
else
		echo "Protecting Resources - User Resources" >>p1
                echo "/etc/csh.login" >>p2
		echo "/etc/profile.d/IBMsinit.csh_is_not_enabled" >>p3
		echo "IZ.1.9.1.6">>p12
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
fi
else
		echo "Protecting Resources - User Resources" >>p1
                echo "/etc/csh.login" >>p2
		echo "/etc/profile.d/IBMsinit.csh file not exists" >>p3
		echo "IZ.1.9.1.6">>p12
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
fi

#IZ.1.9.1.7
echo "/etc/skel/.cshrc,/etc/skel/.login,/etc/skel/.profile,/etc/skel/.bashrc,/etc/skel/.bash_profile,/etc/skel/.bash_login,/etc/skel/.tcshrc" >temp
tr "," "\n" < temp > temp1
for i in `cat temp1`
do
if [ -f $i ]
then
	cat $i | grep -v '#' |grep -i umask
	if [ $? -eq 0 ]
	then
	cat $i |grep -v '#' |grep -i umask >t1
	while IFS= read -r line
	do
      		sk1=`echo $line | awk '{print $2}'`
      		if [ "$sk1" == "077" ]
       		then
            		echo "Protecting Resources - User Resources" >>p1
       			echo "Default UMASK value in skeleton files" >>p2
			echo "umask-value-set-as-$line for $i" >>p3
			echo "IZ.1.9.1.7" >>p12
			echo "yes" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
		else
          		echo "Protecting Resources - User Resources" >>p1
            		echo "Default UMASK value in skeleton files" >>p2
			echo "umask-value-set-as-$line for $i" >>p3
			echo "no" >>p4
			echo "IZ.1.9.1.7" >>p12
			echo "$c" >> p5
			echo "$z" >>p6
       		fi
	done <t1
	else
			echo "Protecting Resources - User Resources" >>p1
                        echo "Default UMASK value in skeleton files" >>p2
                        echo "umask-value-is-not-set in $i" >>p3
                        echo "yes" >>p4
                        echo "IZ.1.9.1.7" >>p12
                        echo "$c" >> p5
                        echo "$z" >>p6
	fi
else
			echo "Protecting Resources - User Resources" >>p1
                        echo "Default UMASK value in skeleton files" >>p2
                        echo "File $i not exist on the server" >>p3
                        echo "yes" >>p4
                        echo "IZ.1.9.1.7" >>p12
                        echo "$c" >> p5
                        echo "$z" >>p6
fi
done
rm -rf t1 temp temp1

#IZ.2.1.4.0
Release=`cat /etc/os-release |grep -w "VERSION="|awk -F"=" '{print $2}'|cut -c2-|awk -F"." '{print $1}'`
if [ "$Release" == "8" ]
then
	sk=`update-crypto-policies --show`
	if [ "$sk" == "LEGACY" ]
	then
		echo "Encryption" >>p1
		echo "System-wide Cryptographic policies" >>p2
		echo "cryptographic methods is set as \"$sk\" " >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.2.1.4.0" >>p12
	else
		echo "Encryption" >>p1
		echo "Crypto Policies" >>p2
		echo "cryptographic methods is set as valid" >>p3
		echo "Yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.2.1.4.0" >>p12
	fi
else
		echo "Encryption" >>p1
		echo "Crypto Policies" >>p2
		echo "Not applicable as the OS is not RHEL-8" >>p3
		echo "Yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.2.1.4.0" >>p12
fi


#IZ.C.1.1.2
ping -c2 8.8.8.8
if [ $? -eq 0 ] ; then

mount| awk -F " " '{print $3}'| grep ^/tmp$

if [ $? -eq 0 ] ; then

	echo "Filesystem Configuration" >>p1
	echo "Ensure separate partition exists for /tmp" >>p2
	echo "Internet is enabled. Separate partition exists for /tmp" >>p3
	echo "IZ.C.1.1.2">>p12
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
else

	echo "Filesystem Configuration" >>p1
	echo "Ensure separate partition exists for /tmp" >>p2
	echo "Internet is enabled. Separate partition does not exist for /tmp" >>p3
	echo "IZ.C.1.1.2">>p12
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
fi
else
	echo "Filesystem Configuration" >>p1
	echo "Ensure separate partition exists for /tmp" >>p2
	echo "Not applicable for /tmp as separate FS as internet is disabled on server" >>p3
	echo "IZ.C.1.1.2">>p12
	echo "Yes" >>p4
fi



#IZ.C.1.1.3 - updated (06-05-2021)

mount | egrep '/tmp\s'
if [ $? -eq 0 ] ; then

mount | egrep '/tmp\s' |grep nodev

if [ $? -eq 0 ] ; then

	echo "Filesystem Configuration" >>p1
	echo "Ensure nodev option set on /tmp partition" >>p2
	echo "nodev option is set on /tmp partition" >>p3
	echo "IZ.C.1.1.3">>p12
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
else

	echo "Filesystem Configuration" >>p1
	echo "Ensure nodev option set on /tmp partition" >>p2
	echo "nodev option is not set on /tmp partition" >>p3
	echo "IZ.C.1.1.3">>p12
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
fi
else
	echo "Filesystem Configuration" >>p1
	echo "Ensure nodev option set on /tmp partition" >>p2
	echo "FileSystem /tmp does not exist in the server" >>p3
	echo "IZ.C.1.1.3">>p12
	echo "Yes" >>p4
fi



#IZ.C.1.1.4

mount | egrep '/tmp\s'
if [ $? -eq 0 ] ; then

mount | egrep '/tmp\s' |grep nosuid

if [ $? -eq 0 ] ; then

	echo "Filesystem Configuration" >>p1
	echo "Ensure nosuid option set on /tmp partition" >>p2
	echo "nosuid option is set on /tmp partition" >>p3
	echo "IZ.C.1.1.4">>p12
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
else

	echo "Filesystem Configuration" >>p1
	echo "Ensure nosuid option set on /tmp partition" >>p2
	echo "nosuid option is not set on /tmp partition" >>p3
	echo "IZ.C.1.1.4">>p12
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
fi
else
	echo "Filesystem Configuration" >>p1
	echo "Ensure nosuid option set on /tmp partition" >>p2
	echo "FileSystem /tmp does not exist in the server" >>p3
	echo "IZ.C.1.1.4">>p12
	echo "Yes" >>p4
fi



#IZ.C.1.1.5 - updated (6-05-2021)

mount | egrep '/tmp\s'
if [ $? -eq 0 ] ; then

mount | egrep '/tmp\s' |grep noexec

if [ $? -eq 0 ] ; then

	echo "Filesystem Configuration" >>p1
	echo "Ensure noexec option set on /tmp partition" >>p2
	echo "noexec option is set on /tmp partition" >>p3
	echo "IZ.C.1.1.5">>p12
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
else

	echo "Filesystem Configuration" >>p1
	echo "Ensure noexec option set on /tmp partition" >>p2
	echo "noexec option is not set on /tmp partition" >>p3
	echo "IZ.C.1.1.5">>p12
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
fi
else
	echo "Filesystem Configuration" >>p1
	echo "Ensure noexec option set on /tmp partition" >>p2
	echo "Filesystem /tmp does not exist in the server" >>p3
	echo "IZ.C.1.1.5">>p12
	echo "Yes" >>p4
fi



#IZ.C.1.1.6
ping -c2 8.8.8.8
if [ $? -eq 0 ] ; then

mount| awk -F " " '{print $3}'| grep ^/var$

if [ $? -eq 0 ]
then
	echo "Filesystem Configuration" >>p1
	echo "Ensure separate partition exists for /var" >>p2
	echo "Internet is enabled. Separate partition exists for /var" >>p3
	echo "IZ.C.1.1.6">>p12
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
else
	echo "Filesystem Configuration" >>p1
	echo "Ensure separate partition exists for /var" >>p2
	echo "Internet is enabled. Separate partition does not exist for /var" >>p3
	echo "IZ.C.1.1.6">>p12
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
fi
else
	echo "Filesystem Configuration" >>p1
	echo "Ensure separate partition exists for /var" >>p2
	echo "Not applicable for /var as separate FS as internet is disabled on server" >>p3
	echo "IZ.C.1.1.6">>p12
	echo "Yes" >>p4
fi



#IZ.C.1.1.7
ping -c2 8.8.8.8 
if [ $? -eq 0 ] ; then

mount| awk -F " " '{print $3}'| grep ^/var/tmp$

if [ $? -eq 0 ] ; then

	echo "Filesystem Configuration" >>p1
	echo "Ensure separate partition exists for /var/tmp" >>p2
	echo "Internet is enabled. Separate partition exists for /var/tmp" >>p3
	echo "IZ.C.1.1.7">>p12
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
else

	echo "Filesystem Configuration" >>p1
	echo "Ensure separate partition exists for /var/tmp" >>p2
	echo "Internet is enabled. Separate partition does not exist for /var/tmp" >>p3
	echo "IZ.C.1.1.7">>p12
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
fi

else
	echo "Filesystem Configuration" >>p1
	echo "Ensure separate partition exists for /var/tmp" >>p2
	echo "Filesystem Configuration and separate partition  no need to check as internet is disabled on server" >>p3
	echo "IZ.C.1.1.7">>p12
	echo "Yes" >>p4

fi



#IZ.C.1.1.8 - updated (06-05-2021)

mount |egrep '/var/tmps\s'
if [ $? -eq 0 ] ; then
mount |egrep '/var/tmp\s' |grep nodev
	if [ $? -eq 0 ] ; then

		echo "Filesystem Configuration" >>p1
		echo "Ensure nodev option set on /var/tmp partition" >>p2
		echo "nodev option is set on /var/tmp partition" >>p3
		echo "IZ.C.1.1.8">>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	else

		echo "Filesystem Configuration" >>p1
		echo "Ensure nodev option set on /var/tmp partition" >>p2
		echo "nodev option is not set on /var/tmp partition" >>p3
		echo "IZ.C.1.1.8">>p12
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	fi

else
	echo "Filesystem Configuration" >>p1
	echo "Ensure separate partition exists for /var/tmp partition" >>p2
	echo "Filesystem /var/tmps does not exist in the server" >>p3
	echo "IZ.C.1.1.8">>p12
	echo "Yes" >>p4

fi


#IZ.C.1.1.9 - updated (06-05-2021)
mount |egrep '/var/tmp\s'
if [ $? -eq 0 ] ; then 
mount |egrep '/var/tmp\s' |grep nosuid
if [ $? -eq 0 ] ; then

	echo "Filesystem Configuration" >>p1
	echo "Ensure nosuid option set on /var/tmp partition" >>p2
	echo "nosuid option is set on /var/tmp partition" >>p3
	echo "IZ.C.1.1.9">>p12
	echo "yes" >>p4
else

	echo "Filesystem Configuration" >>p1
	echo "Ensure nosuid option set on /var/tmp partition" >>p2
	echo "nosuid option is not set on /var/tmp partition" >>p3
	echo "IZ.C.1.1.9">>p12
	echo "no" >>p4
fi
else
	echo "Filesystem Configuration" >>p1
	echo "Ensure nosuid option set on /var/tmp partition" >>p2
	echo "Filesystem /var/tmp does not existing in the server" >>p3
	echo "IZ.C.1.1.9">>p12
	echo "Yes" >>p4
fi



#IZ.C.1.1.10 - updated (06-05-2021)
mount |egrep '/var/tmp\s'
if [ $? -eq 0 ] ; then

mount |egrep '/var/tmp\s' |grep noexec

if [ $? -eq 0 ] ; then

	echo "Filesystem Configuration" >>p1
	echo "Ensure noexec option set on /var/tmp partition" >>p2
	echo "noexec option is set on /var/tmp partition" >>p3
	echo "IZ.C.1.1.10">>p12
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
else

	echo "Filesystem Configuration" >>p1
	echo "Ensure noexec option set on /var/tmp partition" >>p2
	echo "noexec option is not set on /var/tmp partition" >>p3
	echo "IZ.C.1.1.10">>p12
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
fi
else
	echo "Filesystem Configuration" >>p1
	echo "Ensure nosuid option set on /var/tmp partition" >>p2
	echo "Filesystem /var/tmp does not exist in the server" >>p3
	echo "IZ.C.1.1.10">>p12
	echo "Yes" >>p4

fi

#IZ.C.1.1.11
ping -c2 8.8.8.8 
if [ $? -eq 0 ] ; then

mount| awk -F " " '{print $3}'| grep ^/var/log$

ts=`mount | grep /var/log`
if [ $? -eq 0 ] ; then

	echo "Filesystem Configuration" >>p1
	echo "Ensure separate partition exists for /var/log" >>p2
	echo "Internet is enabled. Separate partition exists for /var/log" >>p3
	echo "IZ.C.1.1.11">>p12
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
else

	echo "Filesystem Configuration" >>p1
	echo "Ensure separate partition exists for /var/log" >>p2
	echo "Internet is enabled. Separate partition does not exist for /var/log" >>p3
	echo "IZ.C.1.1.11">>p12
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
fi
else
	echo "Filesystem Configuration" >>p1
	echo "Ensure separate partition exists for /var/log" >>p2
	echo "Filesystem Configuration and separate partition   no need to check as internet is disabled on server" >>p3
	echo "IZ.C.1.1.11">>p12
	echo "Yes" >>p4

fi

#IZ.C.1.1.12
ping -c2 8.8.8.8 
if [ $? -eq 0 ] ; then

mount| awk -F " " '{print $3}'| grep ^/var/log/audit$

if [ $? -eq 0 ] ; then

	echo "Filesystem Configuration" >>p1
	echo "Ensure separate partition exists for /var/log/audit" >>p2
	echo "Internet is enabled. Separate partition exists for /var/log/audit" >>p3
	echo "IZ.C.1.1.12">>p12
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
else

	echo "Filesystem Configuration" >>p1
	echo "Ensure separate partition exists for /var/log/audit" >>p2
	echo "Internet is enabled. Separate partition does not exist for /var/log/audit" >>p3
	echo "IZ.C.1.1.12">>p12
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
fi
else
	echo "Filesystem Configuration" >>p1
	echo "Ensure nosuid option set on /var/log/audit" >>p2
	echo "Filesystem Configuration and separate partition  no need to check as internet is disabled on server" >>p3
	echo "IZ.C.1.1.12">>p12
	echo "Yes" >>p4

fi

#IZ.C.1.1.13
ping -c2 8.8.8.8 
if [ $? -eq 0 ] ; then

mount| awk -F " " '{print $3}'| grep ^/home$

if [ $? -eq 0 ] ; then

	echo "Filesystem Configuration" >>p1
	echo "Ensure separate partition exists for /home" >>p2
	echo "Internet is enabled. Separate partition exists for /home" >>p3
	echo "IZ.C.1.1.13">>p12
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
else

	echo "Filesystem Configuration" >>p1
	echo "Ensure separate partition exists for /home" >>p2
	echo "Internet is enabled. Separate partition does not exist for /home" >>p3
	echo "IZ.C.1.1.13">>p12
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
fi
else
	echo "Filesystem Configuration" >>p1
	echo "Ensure nosuid option set on /home" >>p2
	echo "Filesystem Configuration and separate partition  no need to check as internet is disabled on server" >>p3
	echo "IZ.C.1.1.13">>p12
	echo "Yes" >>p4

fi

#IZ.C.1.1.14 - updated (06-05-2021)
mount |grep '/home\s'
if [ $? -eq 0 ] ; then

mount |grep '/home\s' |grep nodev

if [ $? -eq 0 ] ; then

	echo "Filesystem Configuration" >>p1
	echo "Ensure nodev option set on /home partition" >>p2
	echo "nodev option is set on /home partition" >>p3
	echo "IZ.C.1.1.14">>p12
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
else

	echo "Filesystem Configuration" >>p1
	echo "Ensure nodev option set on /home partition" >>p2
	echo "nodev option is not set on /home partition" >>p3
	echo "IZ.C.1.1.14">>p12
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
fi
else
	echo "Filesystem Configuration" >>p1
	echo "Ensure  nodev option set on /home partition" >>p2
	echo "Filesystem /home does not exist in the server" >>p3
	echo "IZ.C.1.1.14">>p12
	echo "Yes" >>p4

fi

#IZ.C.1.1.15
ping -c2 8.8.8.8 
if [ $? -eq 0 ] ; then

mount| awk -F " " '{print $3}'| grep ^/dev/shm$

if [ $? -eq 0 ] ; then

	echo "Filesystem Configuration" >>p1
	echo "Ensure nodev option set on /dev/shm partition" >>p2
	echo "Internet is enabled. nodev option is set on /dev/shm partition" >>p3
	echo "IZ.C.1.1.15">>p12
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
else

	echo "Filesystem Configuration" >>p1
	echo "Ensure nodev option set on /dev/shm partition" >>p2
	echo "Internet is enabled. nodev option is not set on /dev/shm partition" >>p3
	echo "IZ.C.1.1.15">>p12
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
fi
else
	echo "Filesystem Configuration" >>p1
	echo "Ensure nodev  option set on /dev/shm partition" >>p2
	echo "Filesystem Configuration and nodev  option  no need to check as internet is disabled on server" >>p3
	echo "IZ.C.1.1.15">>p12
	echo "Yes" >>p4

fi

#IZ.C.1.1.16
ping -c2 8.8.8.8 
if [ $? -eq 0 ] ; then

mount |grep '/dev/shm\s' |grep nosuid

if [ $? -eq 0 ] ; then

	echo "Filesystem Configuration" >>p1
	echo "Ensure nosuid option set on /dev/shm partition" >>p2
	echo "Internet is enabled. nosuid option is set on /dev/shm partition" >>p3
	echo "IZ.C.1.1.16">>p12
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
else

	echo "Filesystem Configuration" >>p1
	echo "Ensure nosuid option set on /dev/shm partition" >>p2
	echo "Internet is enabled. nosuid option is not set on /dev/shm partition" >>p3
	echo "IZ.C.1.1.16">>p12
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
fi
else
	echo "Filesystem Configuration" >>p1
	echo "Ensure nosuid option set on /dev/shm partition" >>p2
	echo "Filesystem Configuration and nosuid  option  no need to check as internet is disabled on server" >>p3
	echo "IZ.C.1.1.16">>p12
	echo "Yes" >>p4

fi

#IZ.C.1.1.17
ping -c2 8.8.8.8 
if [ $? -eq 0 ] ; then

mount |grep '/dev/shm\s' |grep noexec

if [ $? -eq 0 ] ; then

	echo "Filesystem Configuration" >>p1
	echo "Ensure noexec option set on /dev/shm partition" >>p2
	echo "Internet is enabled. noexec option is set on /dev/shm partition" >>p3
	echo "IZ.C.1.1.17">>p12
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
else

	echo "Filesystem Configuration" >>p1
	echo "Ensure noexec option set on /dev/shm partition" >>p2
	echo "Internet is enabled. noexec option is not set on /dev/shm partition" >>p3
	echo "IZ.C.1.1.17">>p12
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
fi

else
	echo "Filesystem Configuration" >>p1
	echo "Ensure noexec option set on /dev/shm partition" >>p2
	echo "Filesystem Configuration and noexec  option  no need to check as internet is disabled on server" >>p3
	echo "IZ.C.1.1.17">>p12
	echo "Yes" >>p4

fi

#IZ.C.1.1.1.1

ts=`modprobe -n -v cramfs |awk '{if($2 =="/bin/true" && $1=="install") {print $0}'}`
if [ $? -eq 0 ] ; then
	ts=`lsmod | grep cramfs`
	if ! [ $? -eq 0 ] ; then
		echo "Filesystem Configuration" >>p1
		echo "Ensure mounting of cramfs filesystems is disabled">>p2
		echo "mounting of cramfs filesystems is disabled">>p3
		echo "IZ.C.1.1.1.1">>p12
		echo "yes" >>p4
	
	fi
else
	echo "Filesystem Configuration" >>p1
	echo "Ensure mounting of cramfs filesystems is disabled" >>p2
	echo "mounting of cramfs filesystems is not disabled" >>p3
	echo "IZ.C.1.1.1.1">>p12
	echo "no"  >p4
fi



#IZ.C.1.1.1.2

ts=`modprobe -n -v freevxfs |awk '{if($2 =="/bin/true" && $1=="install") {print $0}'}`
if [ $? -eq 0 ] ; then
	ts=`lsmod | grep freevxfs`
	if ! [ $? -eq 0 ] ; then
		echo "Filesystem Configuration" >>p1
		echo "Ensure mounting of cramfs filesystems is disabled">>p2
		echo "mounting of freevxfs filesystems is disabled">>p3
		echo "IZ.C.1.1.1.2">>p12
		echo "yes" >>p4
	
	fi
else
	echo "Filesystem Configuration" >>p1
	echo "Ensure mounting of freevxfs filesystems is disabled" >>p2
	echo "mounting of freevxfs filesystems is not disabled" >>p3
	echo "IZ.C.1.1.1.2">>p12
	echo "no"  >p4
fi




#IZ.C.1.1.1.3

ts=`modprobe -n -v  jffs2 |awk '{if($2 =="/bin/true" && $1=="install") {print $0}'}`
if [ $? -eq 0 ] ; then
	ts=`lsmod | grep  jffs2`
	if ! [ $? -eq 0 ] ; then
		echo "Filesystem Configuration" >>p1
		echo "Ensure mounting of cramfs filesystems is disabled">>p2
		echo "mounting of  jffs2 filesystems is disabled">>p3
		echo "IZ.C.1.1.1.3">>p12
		echo "yes" >>p4
	
	fi
else
	echo "Filesystem Configuration" >>p1
	echo "Ensure mounting of  jffs2 filesystems is disabled" >>p2
	echo "mounting of  jffs2 filesystems is not disabled" >>p3
	echo "IZ.C.1.1.1.3">>p12
	echo "no"  >p4
fi





#IZ.C.1.1.1.4

ts=`modprobe -n -v hfs |awk '{if($2 =="/bin/true" && $1=="install") {print $0}'}`
if [ $? -eq 0 ] ; then
	ts=`lsmod | grep hfs`
	if ! [ $? -eq 0 ] ; then
		echo "Filesystem Configuration" >>p1
		echo "Ensure mounting of cramfs filesystems is disabled">>p2
		echo "mounting of hfs filesystems is disabled">>p3
		echo "IZ.C.1.1.1.4">>p12
		echo "yes" >>p4
	
	fi
else
	echo "Filesystem Configuration" >>p1
	echo "Ensure mounting of hfs filesystems is disabled" >>p2
	echo "mounting of hfs filesystems is not disabled" >>p3
	echo "IZ.C.1.1.1.4">>p12
	echo "no"  >p4
fi

#IZ.C.1.1.1.5

ts=`modprobe -n -v  hfsplus |awk '{if($2 =="/bin/true" && $1=="install") {print $0}'}`
if [ $? -eq 0 ] ; then
	ts=`lsmod | grep  hfsplus`
	if ! [ $? -eq 0 ] ; then
		echo "Filesystem Configuration" >>p1
		echo "Ensure mounting of cramfs filesystems is disabled">>p2
		echo "mounting of  hfsplus filesystems is disabled">>p3
		echo "IZ.C.1.1.1.5">>p12
		echo "yes" >>p4
	
	fi
else
	echo "Filesystem Configuration" >>p1
	echo "Ensure mounting of  hfsplus filesystems is disabled" >>p2
	echo "mounting of  hfsplus filesystems is not disabled" >>p3
	echo "IZ.C.1.1.1.5">>p12
	echo "no"  >p4
fi

#IZ.C.1.1.1.6

ts=`modprobe -n -v   squashfs |awk '{if($2 =="/bin/true" && $1=="install") {print $0}'}`
if [ $? -eq 0 ] ; then
	ts=`lsmod | grep   squashfs`
	if ! [ $? -eq 0 ] ; then
		echo "Filesystem Configuration" >>p1
		echo "Ensure mounting of cramfs filesystems is disabled">>p2
		echo "mounting of   squashfs filesystems is disabled">>p3
		echo "IZ.C.1.1.1.6">>p12
		echo "yes" >>p4
	
	fi
else
	echo "Filesystem Configuration" >>p1
	echo "Ensure mounting of   squashfs filesystems is disabled" >>p2
	echo "mounting of   squashfs filesystems is not disabled" >>p3
	echo "IZ.C.1.1.1.6">>p12
	echo "no"  >p4
fi



#IZ.C.1.1.1.7

ts=`modprobe -n -v   udf |awk '{if($2 =="/bin/true" && $1=="install") {print $0}'}`
if [ $? -eq 0 ] ; then
	ts=`lsmod | grep   udf`
	if ! [ $? -eq 0 ] ; then
		echo "Filesystem Configuration" >>p1
		echo "Ensure mounting of cramfs filesystems is disabled">>p2
		echo "mounting of   udf filesystems is disabled">>p3
		echo "IZ.C.1.1.1.7">>p12
		echo "yes" >>p4
	
	fi
else
	echo "Filesystem Configuration" >>p1
	echo "Ensure mounting of   udf filesystems is disabled" >>p2
	echo "mounting of   udf filesystems is not disabled" >>p3
	echo "IZ.C.1.1.1.7">>p12
	echo "no"  >p4
fi

#IZ.C.1.6.1.5
ping -c1 8.8.8.8 

if [ $? -eq 0 ] ; then

ts=`rpm -qa |grep mcstrans`
if [ $? -eq 0 ] ; then
	echo "Mandatory Access Control" >>p1
	echo "Ensure the MCS Translation Service (mcstrans) is not installed" >>p2
	echo "MCS Translation Service (mcstrans) is   installed" >>p3
	echo "IZ.C.1.6.1.5">>p12
	echo "no" >>p4
else
	echo "Mandatory Access Control" >>p1
	echo "Ensure the MCS Translation Service (mcstrans) is not installed" >>p2
	echo "MCS Translation Service (mcstrans) is not installed" >>p3
	echo "IZ.C.1.6.1.5">>p12
	echo "Yes" >>p4
fi

else
	echo "Mandatory Access Control" >>p1
	echo "Ensure the MCS Translation Service (mcstrans) is not installed" >>p2
	echo "MCS Translation Service (mcstrans) no need to check as internet is disabled on server" >>p3
	echo "IZ.C.1.6.1.5">>p12
	echo "Yes" >>p4

fi



#IZ.1.5.11.1
if [[ "$(rpm -q rsh-server)" != "package rsh-server is not installed" ]]
then
	systemctl is-enabled rlogin
	if [ $? -eq 0 ]
	then
		echo "Network Settings" >>p1
		echo "rlogin" >>p2
		echo "rlogin service is enabled" >>p3
		echo "no" >>p4
		echo "IZ.1.5.11.1" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Network Settings" >>p1
		echo "rlogin" >>p2
		echo "rlogin service is not enabled" >>p3
		echo "yes" >>p4
		echo "IZ.1.5.11.1" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
		echo "Network Settings" >>p1
		echo "rlogin" >>p2
		echo "rsh-server package is not installed" >>p3
		echo "yes" >>p4
		echo "IZ.1.5.11.1" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
fi



#IZ.1.5.11.2
if [[ "$(rpm -q rsh-server)" != "package rsh-server is not installed" ]]
then
	systemctl is-enabled rsh.socket
	if [ $? -eq 0 ] ; then
		echo "Network Settings" >>p1
		echo "rsh service" >>p2
		echo "rsh.socket service is running" >>p3
		echo "IZ.1.5.11.2">>p12
		echo "no" >>p4
	else
		echo "Network Settings" >>p1
		echo "rsh service" >>p2
		echo "rsh.socket service is not running" >>p3
		echo "IZ.1.5.11.2">>p12
		echo "yes" >>p4
	fi
else
		echo "Network Settings" >>p1
		echo "rsh service" >>p2
		echo "rsh-server package is not installed" >>p3
		echo "IZ.1.5.11.2">>p12
		echo "yes" >>p4
fi




#IZ.C.4.1.3 - updated
timeout 10s ping -c 1 8.8.8.8
if [ $? -eq 0 ]
then
sk=`grep "^\s*linux" /boot/grub2/grub.cfg |grep audit |awk -F= '{print $2}' |sed -e 's/ //'`
sl=`grep "^\s*linux" /boot/efi/EFI/redhat/grub.cfg |grep audit |awk -F= '{print $2}' |sed -e 's/ //'`
echo $sk
echo $sl
	if [ $? -eq 1 ] || [ $? -eq 1 ] ; 	then
		echo "Configure System Accounting" >>p1
		echo "Ensure auditing for processes that start prior to auditd is enabled" >>p2
		echo "auditing for processes that start prior to auditd is enabled" >>p3
		echo "IZ.C.4.1.3">>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
    	echo "$fqdn" >>en1
    	echo "$ipAddress" >>en2
    	echo "$osName" >>en3
		echo "$timestamp" >>en4
	else
		echo "Configure System Accounting" >>p1
		echo "Ensure auditing for processes that start prior to auditd is enabled" >>p2
		echo "auditing for processes that start prior to auditd is not enabled" >>p3
		echo "IZ.C.4.1.3">>p12
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
    	echo "$fqdn" >>en1
    	echo "$ipAddress" >>en2
    	echo "$osName" >>en3
		echo "$timestamp" >>en4
	fi
else
echo "Configure System Accounting" >>p1
		echo "Ensure auditing for processes that start prior to auditd is enabled" >>p2
		echo "Not applicable as internet is disabled on the server" >>p3
		echo "IZ.C.4.1.3">>p12
		echo "Yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
    	echo "$fqdn" >>en1
    	echo "$ipAddress" >>en2
    	echo "$osName" >>en3
		echo "$timestamp" >>en4
fi


#IZ.C.6.2.6
msg=''
if [ "`echo $PATH | grep :: `" != "" ]; then 
  msg="Empty Directory in PATH (::)" 
fi 
if [ "`echo $PATH | grep :$`" != "" ]; then 
  msg="Trailing : in PATH" 
fi 
p=`echo $PATH | tr ":" "\n" |grep -v "/root/bin"` 
set -- $p 
while [ "$1" != "" ]; do
  if [ "$1" = "." ]; then
    msg="PATH contains ." 
    shift 
    continue 
  fi 
  if [ -d $1 ] ; then
    dirperm=`ls -ldH $1 | cut -f1 -d" "` 
    if [ `echo $dirperm | cut -c6 ` != "-" ]; then
      msg="Group Write permission set on directory $1" 
    fi 
	  if [ `echo $dirperm | cut -c9 ` != "-" ]; then
	    msg="Other Write permission set on directory $1" 
	  fi 
		  dirown=`ls -ldH $1 | awk '{print $3}'` 
		  if [ "$dirown" != "root" ] ; then
		    msg="$1 is not owned by root "
		  fi 
  else 
    msg="$1 is not a directory"
  fi 
  shift 
done
if [ "$msg" == "" ] ; then
	echo "Filesystem Configuration" >>p1
	echo "Ensure root PATH Integrity in the default root environment" >>p2
	echo "root PATH Integrity in the default root environment " >>p3
	echo "IZ.C.6.2.6">>p12
	echo "yes" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
			echo "$timestamp" >>en4
else
	echo "Filesystem Configuration" >>p1
	echo "Ensure root PATH Integrity in the default root environment " >>p2
	echo "$msg - check the PATH variable if all directory exists in server" >>p3
	echo "IZ.C.6.2.6">>p12
	echo "no" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
			echo "$timestamp" >>en4
fi

#IZ.C.6.2.11
flag=1
for dir in `cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' |grep -v "/sbin/nologin" | awk -F: '{ print $6 }'`; do
	if [ ! -h "$dir/.forward" -a -f "$dir/.forward" ]; then
		flag=0
		break
	fi 
done
if [ $flag == 1 ] ; then

	echo "User and Group Settings" >>p1
	echo "Ensure no users have .forward files in directories located in local file systems." >>p2
	echo "no users have .forward file available in their home directory" >>p3
	echo "IZ.C.6.2.11">>p12
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
else

	echo "User and Group Settings" >>p1
	echo "Ensure no users have .forward files in directories located in local file systems." >>p2
	echo ".forward file exists for user home directory $dir" >>p3
	echo "IZ.C.6.2.11">>p12
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
fi

#IZ.C.6.2.12
flag=1
for dir in `cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' |grep -v "/sbin/nologin" | awk -F: '{ print $6 }'`; do
  if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then
    	flag=0
	break
  fi 
done
if [ $flag == 1 ] ; then

	echo "User and Group Settings" >>p1
	echo "Ensure no users have .netrc files in directories located in local file systems." >>p2
	echo "no users have .netrc files in directories located in local file systems." >>p3
	echo "IZ.C.6.2.12">>p12
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
else

	echo "User and Group Settings" >>p1
	echo "Ensure no users have .netrc files in directories located in local file systems." >>p2
	echo ".netrc file exists in user home directory $dir" >>p3
	echo "IZ.C.6.2.12">>p12
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
fi

#IZ.C.6.2.13
msg=''
for dir in `cat /etc/passwd | egrep -v '(root|sync|halt|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin") { print $6 }'`; do
  for file in $dir/.netrc; do
    if [ ! -h "$file" -a -f "$file" ]; then
      fileperm=`ls -ld $file | cut -f1 -d" "` 
      if [ `echo $fileperm | cut -c5 ` != "-" ]; then
        msg="Group Read set on $file" 
      fi 
      if [ `echo $fileperm | cut -c6 ` != "-" ]; then
        msg="Group Write set on $file" 
      fi 
      if [ `echo $fileperm | cut -c7 ` != "-" ]; then 
        msg="Group Execute set on $file" 
      fi 
      if [ `echo $fileperm | cut -c8 ` != "-" ]; then 
        msg="Other Read set on $file" 
      fi 
      if [ `echo $fileperm | cut -c9 ` != "-" ]; then 
        msg="Other Write set on $file" 
      fi 
      if [ `echo $fileperm | cut -c10 ` != "-" ]; then 
        msg="Other Execute set on $file" 
      fi 
    fi 
  done 
done
if [ "$msg" == "" ] ; then

	echo "User and Group Settings" >>p1
	echo "Ensure users' .netrc Files are not group or world accessible in directories located in local file systems." >>p2
	echo "users' .netrc Files are not group or world accessible in directories located in local file systems." >>p3
	echo "IZ.C.6.2.13">>p12
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
else

	echo "User and Group Settings" >>p1
	echo "Ensure users' .netrc Files are not group or world accessible in directories located in local file systems." >>p2
	echo "$msg" >>p3
	echo "IZ.C.6.2.13">>p12
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
fi

#IZ.C.6.2.14
msg=''
for dir in `cat /etc/passwd | egrep -v '(root|halt|sync|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin") { print $6 }'`; do
  for file in $dir/.rhosts; do
    if [ ! -h "$file" -a -f "$file" ]; then
      msg=".rhosts file in $dir" 
    fi 
  done 
done
if [ "$msg" == "" ] ; then

	echo "User and Group Settings" >>p1
	echo "Ensure no users have .rhosts files in directories located in local file systems." >>p2
	echo "no users have .rhosts files in directories located in local file systems." >>p3
	echo "IZ.C.6.2.14">>p12
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
else

	echo "User and Group Settings" >>p1
	echo "Ensure no users have .rhosts files in directories located in local file systems." >>p2
	echo "$msg" >>p3
	echo "IZ.C.6.2.14">>p12
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
fi

#IZ.C.6.2.18
msg=''
cat /etc/passwd | cut -f1 -d":" | sort -n | uniq -c | while read x ; do
  [ -z "${x}" ] && break 
  set - $x 
  if [ $1 -gt 1 ]; then 
    uids=`awk -F: '($1 == n) { print $3 }' n=$2 /etc/passwd | xargs` 
    msg="Duplicate User Name ($2): ${uids}" 
  fi 
done
if [ "$msg" == "" ] ; then

	echo "User and Group Settings" >>p1
	echo "Ensure no duplicate user names exist" >>p2
	echo "no duplicate user names exist" >>p3
	echo "IZ.C.6.2.18">>p12
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
else

	echo "User and Group Settings" >>p1
	echo "Ensure no duplicate user names exist" >>p2
	echo "$msg" >>p3
	echo "IZ.C.6.2.18">>p12
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
fi

#IZ.C.6.2.19
msg=''
cat /etc/group | cut -f1 -d":" | sort -n | uniq -c | while read x ; do
  [ -z "${x}" ] && break 
  set - $x 
  if [ $1 -gt 1 ]; then
    gids=`gawk -F: '($1 == n) { print $3 }' n=$2 /etc/group | xargs` 
    msg="Duplicate Group Name ($2): ${gids}" 
  fi 
done
if [ "$msg" == "" ] ; then

	echo "User and Group Settings" >>p1
	echo "Ensure no duplicate group names exist" >>p2
	echo "no duplicate group names exist" >>p3
	echo "IZ.C.6.2.19">>p12
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
else

	echo "User and Group Settings" >>p1
	echo "Ensure no duplicate group names exist" >>p2
	echo "$msg" >>p3
	echo "IZ.C.6.2.19">>p12
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
fi





#AV.2.0.1.1
sk=`cat /etc/ssh/sshd_config | grep -i "^PrintMotd" |uniq |wc -l`
if [ $sk -gt 0 ]
then
	szk=`cat /etc/ssh/sshd_config | grep "^PrintMotd" | awk '{print $2}' |uniq`
	if [ "$szk" == "$PRINTMOTD" ]
	then
		echo "Business Use Notice " >>p1
		echo "PrintMotd" >>p2
		echo "PrintMotd is set as \"$szk\" in /etc/ssh/sshd_config" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AV.2.0.1.1" >>p12

	else
		echo "Business Use Notice " >>p1
		echo "PrintMotd" >>p2
		echo "Value-is-not-set in /etc/ssh/sshd_config" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AV.2.0.1.1" >>p12

		
	fi
else
	szk=`cat /etc/ssh/sshd_config | grep "^#PrintMotd" | awk '{print $2}' |uniq`
	if [ "$szk" == "$PRINTMOTD" ]
	then
		echo "Business Use Notice " >>p1
		echo "PrintMotd" >>p2
		echo "PrintMotd is set as \"$szk\" in /etc/ssh/sshd_config" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AV.2.0.1.1" >>p12

		
	else
		echo "Business Use Notice " >>p1
		echo "PrintMotd" >>p2
		echo "Value-is-not-set in /etc/ssh/sshd_config" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AV.2.0.1.1" >>p12


	fi
fi

#AV.1.7.2
cat /etc/passwd | egrep -v "/sbin/nologin|sync|shutdown|halt|/bin/false"|awk -F":" '{print $6}'>temp_home
for i in `cat temp_home`
do
if [ -f $i/.ssh/id_rsa ] || [ -f $i/.ssh/authorized_keys ] || [ -f $i/.ssh/authorized_keys2 ] || [ -f $i/.ssh/id_ecdsa ]
then
	ss1=`ssh-keygen -l -f $i/.ssh/id_rsa |awk '{print $1}'`
	ss2=`ssh-keygen -l -f $i/.ssh/authorized_keys |awk '{print $1}'`
	ss3=`ssh-keygen -l -f $i/.ssh/authorized_keys2 |awk '{print $1}'`
	ss4=`ssh-keygen -l -f $i/.ssh/id_ecdsa |awk '{print $1}'`
	if [ $ss1 -ge 2048 ] || [ $ss2 -ge 2048 ] || [ $ss3 -ge 2048 ] || [ $ss4 -ge 256 ]
	then
		echo "Identify and Authenticate Users" >>p1
		echo "Public Key Authentication: Key Strength and Algorithm" >>p2
		echo "Public key strength is valid in $i/.ssh as per techspec guidelines" >>p3
		echo "yes" >> p4
		echo "AV.1.7.2" >>p12
		echo "$c" >> p5
		echo "$z" >>p6	
	else
		echo "Identify and Authenticate Users" >>p1
		echo "Public Key Authentication: Key Strength and Algorithm" >>p2
		echo "Public key strength is invalid in $i/.ssh as per techspec guidelines" >>p3
		echo "no" >> p4
		echo "AV.1.7.2" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
	fi
else

		echo "Identify and Authenticate Users" >>p1
		echo "Public Key Authentication: Key Strength and Algorithm" >>p2
		echo "Public key not exists in user home dir $i/.ssh/" >>p3
		echo "yes" >> p4
		echo "AV.1.7.2" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
fi
done
rm -rf temp_home




#AV.2.1.1.2,AV.2.1.1.3,AV.2.1.1.4
ss=`cat /etc/ssh/sshd_config | grep ^Ciphers |wc -c`
if [ $ss -ne 0 ]
then
	sl=`cat /etc/ssh/sshd_config | grep ^Ciphers | egrep -i 'des|64' |wc -c`
	if [ $sl -ne 0 ]
	then
		echo "Encryption" >>p1
		echo "Ciphers-value-in-file-/etc/ssh/sshd_config" >>p2
		echo "des-and-64-bit-algorithm-exist-in-ciphers" >>p3
		echo "no" >> p4
		echo "AV.2.1.1.2,AV.2.1.1.3,AV.2.1.1.4" >>p12
		echo "$c" >> p5
		echo "$z" >>p6	
	else
		echo "Encryption" >>p1
		echo "Ciphers-value-in-file-/etc/ssh/sshd_config" >>p2
		echo "des-and-64-bit-algorithm-not-exist-in-ciphers" >>p3
		echo "yes" >> p4
		echo "AV.2.1.1.2,AV.2.1.1.3,AV.2.1.1.4" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
	fi
else

		echo "Encryption" >>p1
		echo "Ciphers-value-in-file-/etc/ssh/sshd_config" >>p2
		echo "Ciphers-entry-doesnot-exist-in-/etc/ssh/sshd_config" >>p3
		echo "no" >> p4
		echo "AV.2.1.1.2,AV.2.1.1.3,AV.2.1.1.4" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
fi

#IZ.2.1.3.0:IZ.2.1.3.1:IZ.2.1.3.2
grep ^password /etc/pam.d/* | egrep 'required|sufficient' | grep  pam_unix.so |awk -F: '{print $1}' > temp_pam.so
for i in `cat temp_pam.so`
do
sk=`cat $i |egrep 'md5|sha512' |grep shadow |wc -l`
	if [ $sk -gt 0 ]
	then
		echo "Encryption" >>p1
		echo "Password-EncryptionRequired" >>p2
		echo "sha512-and-shadow-is-set-in-file-$i" >>p3
		echo "yes" >>p4
		echo "IZ.2.1.3.0" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Encryption" >>p1
		echo "Password-EncryptionRequired" >>p2
		echo "sha512-and-shadow-is-not-set-in-file-$i" >>p3
		echo "no" >>p4
		echo "IZ.2.1.3.0" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
done
rm -rf temp_pam.so






#IZ.1.1.4.6:loginretries value in password-auth and system-auth
if [ -f /etc/pam.d/system-auth ] 
then
sk=`cat /etc/pam.d/system-auth | grep "pam_deny.so" | grep "auth" |awk '{print $2}'`

	if [ $sk == required ]
	then
		echo "auth _requirement" >>p1
		echo "loginretries" >>p2
		echo "Consecutive failed login attempts is set in /etc/pam.d/system-auth" >>p3
		echo "IZ.1.1.4.6" >>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	else
		echo "auth _requirement" >>p1
		echo "loginretries" >>p2
		echo "Consecutive failed login attempts is not set in /etc/pam.d/system-auth" >>p3
		echo "IZ.1.1.4.6" >>p12
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	fi
else
		echo "auth _requirement" >>p1
		echo "loginretries" >>p2
		echo "File not found /etc/pam.d/system-auth" >>p3
		echo "IZ.1.1.4.6" >>p12
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
fi

if [ -f /etc/pam.d/password-auth ] 
then
sk=`cat /etc/pam.d/system-auth | grep "pam_deny.so" | grep "password" |awk '{print $2}'`

	if [ $sk == required ]
	then
		echo "Password_requirement" >>p1
		echo "loginretries" >>p2
		echo "Consecutive failed login attempts is set in /etc/pam.d/password-auth" >>p3
		echo "IZ.1.1.4.6" >>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	else
		echo "Password_requirement" >>p1
		echo "loginretries" >>p2
		echo "Consecutive failed login attempts is not set in /etc/pam.d/password-auth" >>p3
		echo "IZ.1.1.4.6" >>p12
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	fi
else
		echo "Password_requirement" >>p1
		echo "loginretries" >>p2
		echo "File not found /etc/pam.d/system-auth" >>p3
		echo "IZ.1.1.4.6" >>p12
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
fi


#IZ.1.1.4.7
for file in /etc/pam.d/password-auth /etc/pam.d/system-auth; do
egrep "^password\s" $file |grep pam_unix.so |grep "remember="
if [ $? -eq 0 ]
then
	sk1=`egrep "^password\s" $file | awk '{print $3}' |head -1`
	sk2=`egrep "^password\s" $file | awk '{print $3}' |head -2 |tail -1`
	sk3=`egrep "^password\s" $file | awk '{print $3}' |tail -1`

	if [[ "$sk1" == "pam_pwquality.so" || "$sk1" == "pam_cracklib.so" ]] && [ "$sk2" == "pam_unix.so" ] && [ "$sk3" == "pam_deny.so" ]
	then
		echo "Password Requirements" >>p1
		echo "Ensure pam modules are in correct order" >>p2
		echo "PAM password modules are in correct order in $file" >>p3
		echo "yes" >>p4
		echo "IZ.1.1.4.7" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Password Requirements" >>p1
		echo "Ensure pam modules are in correct order" >>p2
		echo "All are in correct order $file" >>p3
		echo "yes" >>p4
		echo "IZ.1.1.4.7" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	egrep "^password\s" $file |grep pam_pwhistory.so
	if [ $? -eq 0 ]
	then
		sk1=`egrep "^password\s" $file | awk '{print $3}' |head -1`
		sk2=`egrep "^password\s" $file | awk '{print $3}' |head -2 |tail -1`
		sk3=`egrep "^password\s" $file | awk '{print $3}' |head -3 |tail -1`
		sk4=`egrep "^password\s" $file | awk '{print $3}' |tail -1`
		if [[ "$sk1" == "pam_pwquality.so" || "$sk1" == "pam_cracklib.so" ]] && [ "$sk2" == "pam_pwhistory.so" ] && [ "$sk3" == "pam_unix.so" ] && [ "$sk4" == "pam_deny.so" ]
		then
			echo "Password Requirements" >>p1
			echo "Ensure pam modules are in correct order" >>p2
			echo "PAM password modules are in correct order in $file" >>p3
			echo "yes" >>p4
			echo "IZ.1.1.4.7" >>p12
			echo "$c" >>p5
			echo "$z" >>p6
		else
			echo "Password Requirements" >>p1
			echo "Ensure pam modules are in correct order" >>p2
			echo "PAM password modules are not in correct order in $file" >>p3
			echo "no" >>p4
			echo "IZ.1.1.4.7" >>p12
			echo "$c" >>p5
			echo "$z" >>p6
		fi
	else
			echo "Password Requirements" >>p1
			echo "Ensure pam modules are in correct order" >>p2
			echo "remember= is not coded on the pam_unix.so module and pam_pwhistory.so not available in $file" >>p3
			echo "no" >>p4
			echo "IZ.1.1.4.7" >>p12
			echo "$c" >>p5
			echo "$z" >>p6
	fi
fi
done




#IZ.1.1.7.3
echo "bin,daemon,IZm,lp,sync,shutdown,halt,mail,uucp,operator,games,gopher,ftp,nobody,dbus,usbmuxd,rpc,avahi-autoipd,vcsa,rtkit,saslauth,postfix,avahi,ntp,apache,rIZvd,rpcuser,nfsnobody,qemu,haldaemon,nm-openconnect,pulse,gsanslcd,gdm,sshd,tcpdump" >temp
tr "," "\n" < temp > temp1
             
	for i in `cat temp1`
        do
		#cat /etc/shadow | awk -F":" '{print $1}' | grep -w ^$i
		getent passwd $i
		if [ $? -eq 0 ]
		then
		sk=`passwd -S $i |awk '{print $2}'`
		if [ "$sk" == "PS" ]
                then
                        echo "IZ.1.1.7.3" >>p12
                        echo "Password_requirement" >>p1
                        echo "Password for system ID's" >>p2
                        echo "Password is set for system ID $i" >> p3
                        echo "no" >>p4
                        echo "$c" >> p5
                        echo "$z" >>p6
		else
			echo "IZ.1.1.7.3" >>p12
                        echo "Password_requirement" >>p1
                        echo "Password for system ID's" >>p2
                        echo "Password is not set for system ID $i" >> p3
                        echo "yes" >>p4
                        echo "$c" >> p5
                        echo "$z" >>p6
		fi
		fi
        done
rm -rf temp temp1

#IZ.1.1.8.3.1:GID-validation
cat /etc/group | awk -F":" '{print $3}'| sort  | uniq -cd | awk '{print $2}'> temp_gid
sp=`cat temp_gid | wc -c`
if [ "$sp" == 0 ]
then
		echo "Password_requirement" >>p1
		echo "GID_validation" >>p2
		echo "No_duplicate_GID-value_for_users_in_/etc/group" >>p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "IZ.1.1.8.3.1" >>p12
		echo "$z" >>p6	
else
		for i in `cat temp_gid`
		do
		echo "Password_requirement" >>p1
		echo "gid_validation" >>p2
		echo "Duplicate-gid-value-for-GID-$i in /etc/group" >>p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "IZ.1.1.8.3.1" >>p12
		echo "$z" >>p6	
		done
fi

#IZ.1.2.1.4.1
rsyslogStatus=`systemctl is-enabled rsyslog`
if [ "$rsyslogStatus" == "enabled" ] ; then
	echo "Logging" >>p1
	echo "Login success or failure, logging enabled." >>p2
	echo "rsyslog is enabled." >>p3
	echo "IZ.1.2.1.4.1">>p12
		echo "$fqdn" >>e1
		echo "$ipAddress" >>e2
		echo "$osName" >>e3
		echo "$z" >>e4
		echo "$c" >>e5
		echo "$timestamp" >>e6
	echo "yes" >>p4
else
	echo "Logging" >>p1
	echo "Login success or failure, logging enabled." >>p2
	echo "rsyslog is not enabled." >>p3
	echo "IZ.1.2.1.4.1">>p12
		echo "$fqdn" >>e1
		echo "$ipAddress" >>e2
		echo "$osName" >>e3
		echo "$z" >>e4
		echo "$c" >>e5
		echo "$timestamp" >>e6
	echo "no" >>p4
fi

#IZ.1.2.1.4.2
Release=`cat /etc/redhat-release |awk '{print $1}'`
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
			echo "IZ.1.2.1.4.2" >>p12
		echo "$fqdn" >>e1
		echo "$ipAddress" >>e2
		echo "$osName" >>e3
		echo "$z" >>e4
		echo "$c" >>e5
		echo "$timestamp" >>e6
		else
			echo "Logging" >>p1
			echo "Login success or failure" >>p2
			echo "/etc/rsyslog.conf entry missing for '$skl'" >>p3
			echo "no" >>p4
			echo "IZ.1.2.1.4.2" >>p12
		echo "$fqdn" >>e1
		echo "$ipAddress" >>e2
		echo "$osName" >>e3
		echo "$z" >>e4
		echo "$c" >>e5
		echo "$timestamp" >>e6
		fi
		skz=`cat /etc/rsyslog.conf | grep "*.info;mail.none;authpriv.none;cron.none" |grep /var/log/messages`
		if [ $? -eq 0 ] ; then
			echo "Logging" >>p1
			echo "Login success or failure" >>p2
			echo "/etc/rsyslog.conf entry exist for '$skz'" >>p3
			echo "yes" >>p4
			echo "IZ.1.2.1.4.2" >>p12
		echo "$fqdn" >>e1
		echo "$ipAddress" >>e2
		echo "$osName" >>e3
		echo "$z" >>e4
		echo "$c" >>e5
		echo "$timestamp" >>e6
		else
			echo "Logging" >>p1
			echo "Login success or failure" >>p2
			echo "/etc/rsyslog.conf entry not exist for '$skz'" >>p3
			echo "no" >>p4
			echo "IZ.1.2.1.4.2" >>p12
		echo "$fqdn" >>e1
		echo "$ipAddress" >>e2
		echo "$osName" >>e3
		echo "$z" >>e4
		echo "$c" >>e5
		echo "$timestamp" >>e6
		fi
	else
		echo "Logging" >>p1
		echo "Login success or failure" >>p2
		echo "/etc/rsyslog.conf entry not exist for '$skl' and '$$kz'" >>p3
		echo "no" >>p4
		echo "IZ.1.2.1.4.2" >>p12
		echo "$fqdn" >>e1
		echo "$ipAddress" >>e2
		echo "$osName" >>e3
		echo "$z" >>e4
		echo "$c" >>e5
		echo "$timestamp" >>e6                			
	fi	
else
	echo "Logging" >>p1
	echo "Login success or failure" >>p2
	echo "Not for Redhat Linux" >>p3
	echo "Not_Applicable" >>p4
	echo "IZ.1.2.1.4.2" >>p12
		echo "$fqdn" >>e1
		echo "$ipAddress" >>e2
		echo "$osName" >>e3
		echo "$z" >>e4
		echo "$c" >>e5
		echo "$timestamp" >>e6			    	
fi


#IZ.1.4.3.1.1
sk=`rpm -q libselinux | awk -F'-' '{print $1}' |uniq`
if [ "$sk" == "libselinux" ]
then
	echo "System-Settings" >>p1
	echo "Ensure SELinux is installed" >>p2
	echo "libselinux package in installed" >>p3	
	echo "yes" >>p4
	echo "$c" >>p5
	echo "$z" >>p6
	echo "IZ.1.4.3.1.1" >>p12
else
	echo "System-Settings" >>p1
	echo "Ensure Selinux is installed" >>p2
	echo "libselinux package in not installed" >>p3
	echo "no" >>p4
	echo "$c" >>p5
	echo "$z" >>p6
	echo "IZ.1.4.3.1.1" >>p12	
fi



#IZ.1.4.3.1.2:IZ.1.4.3.1.3
sk=`cat /etc/selinux/config |grep ^SELINUX= |awk -F= '{print $2}'`
if [ "$sk" == "enforcing" ] || [ "$sk" == "permissive" ]
then
	echo "System-Settings" >>p1
	echo "Ensure the SELinux state is enforcing or permissive" >>p2
	echo "$sk-set-in-file-/etc/selinux/config" >>p3	
	echo "yes" >>p4
	echo "$c" >>p5
	echo "$z" >>p6
	echo "IZ.1.4.3.1.2:IZ.1.4.3.1.3" >>p12
else
	echo "System-Settings" >>p1
	echo "Ensure the SELinux state is enforcing or permissive" >>p2
	echo "$sk-set-in-file-/etc/selinux/config" >>p3
	echo "no" >>p4
	echo "$c" >>p5
	echo "$z" >>p6
	echo "IZ.1.4.3.1.2:IZ.1.4.3.1.3" >>p12	
fi



#IZ.1.4.3.1.4
st=$(sestatus |grep "Loaded policy name:" | awk '{ print $4 }')
if [ "$st" == "targeted" ]
then
	echo "System-Settings" >>p1
	echo "SeLinux Loaded policy" >>p2
	echo "Policy is set to Targeted" >>p3	
	echo "yes" >>p4
	echo "$c" >>p5
	echo "$z" >>p6
	echo "IZ.1.4.3.1.4" >>p12
else
	echo "System-Settings" >>p1
	echo "SeLinux Loaded policy" >>p2
	echo "Policy is not set to Targeted" >>p3
	echo "no" >>p4
	echo "$c" >>p5
	echo "$z" >>p6
	echo "IZ.1.4.3.1.4" >>p12	
fi



#IZ.1.5.9.18.1
rpm -qa | grep net-snmp
if [ $? -eq 0 ]
then
	systemctl is-enabled snmpd
	if [ $? -eq 0 ]
	then
		echo "Network Settings" >>p1
		echo "SNMP Service, disabled" >>p2
		echo "net-snmp package is installed and snmpd service is enabled" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.5.9.18.1" >>p12
	else
		echo "Network Settings" >>p1
		echo "SNMP Service, disabled" >>p2
		echo "net-snmp package is installed and snmpd service is not enabled" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.5.9.18.1" >>p12
	fi
else
		echo "Network Settings" >>p1
		echo "SNMP Service, disabled" >>p2
		echo "net-snmp package is not installed" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.5.9.18.1" >>p12
fi	

#IZ.1.5.9.18.2
systemctl is-enabled snmpd
if [ $? -eq 0 ]
then
	sk=`cat /etc/snmp/snmpd.conf |grep ^rocommunity |grep -i public |wc -l`
	if [ $sk -gt 0 ]
	then
		echo "Network Settings" >>p1
		echo "SNMP Service, no 'public'" >>p2
		echo "snmpd service is enabled and Public community is enabled in /etc/snmp/snmpd.conf" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.5.9.18.2" >>p12
	else
		echo "Network Settings" >>p1
		echo "SNMP Service, no 'public'" >>p2
		echo "snmpd service is enabled and Public community is not enabled in /etc/snmp/snmpd.conf" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.5.9.18.2" >>p12
	fi
else
		echo "Network Settings" >>p1
		echo "SNMP Service, no 'public'" >>p2
		echo "snmpd service is disabled" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.5.9.18.2" >>p12
fi

#IZ.1.5.9.18.3
systemctl is-enabled snmpd
if [ $? -eq 0 ]
then
	sk=`cat /etc/snmp/snmpd.conf |grep ^rocommunity |grep -i private |wc -l`
	if [ $sk -gt 0 ]
	then
		echo "Network Settings" >>p1
		echo "SNMP Service, no 'private'" >>p2
		echo "snmpd service is enabled and private community is enabled in /etc/snmp/snmpd.conf" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.5.9.18.3" >>p12
	else
		echo "Network Settings" >>p1
		echo "SNMP Service, no 'private'" >>p2
		echo "snmpd service is enabled and private community is not enabled in /etc/snmp/snmpd.conf" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.5.9.18.3" >>p12
	fi
else
		echo "Network Settings" >>p1
		echo "SNMP Service, no 'private'" >>p2
		echo "snmpd service is disabled" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.5.9.18.3" >>p12
fi

#IZ.1.5.9.20.1
if [[ "$(sysctl net.ipv4.tcp_syncookies)" == "net.ipv4.tcp_syncookies = 1" ]];then
	echo "Network Settingss" >>p1
 	echo "/etc/sysctl.conf" >>p2
	echo "Correct-setting-net.ipv4.tcp_syncookies = 1 in /etc/sysctl.conf" >>p3
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
	echo IZ.1.5.9.20.1 >>p12
else
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "Incorrect-value-set-for-net.ipv4.tcp_syncookies-in-/etc/sysctl.conf" >> p3
	echo "no" >>p4	
	echo "$c" >> p5
	echo "$z" >>p6
	echo IZ.1.5.9.20.1 >>p12
fi


#IZ.1.5.9.20.2
if [[ "$(sysctl net.ipv4.icmp_echo_ignore_broadcasts)" == "net.ipv4.icmp_echo_ignore_broadcasts = 1" ]];then
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "Correct-setting-net.ipv4.icmp_echo_ignore_broadcasts=1-in-/etc/sysctl.conf" >>p3
	echo IZ.1.5.9.20.2 >>p12
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
else
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "net.ipv4.icmp_echo_ignore_broadcasts=1_is_not_set-in-/etc/sysctl.conf" >>p3
	echo "no" >>p4
	echo IZ.1.5.9.20.2 >>p12
	echo "$c" >> p5
	echo "$z" >>p6	
fi


#IZ.1.5.9.20.3
if [[ "$(sysctl net.ipv4.conf.all.accept_redirects)" == "net.ipv4.conf.all.accept_redirects = 0" ]];then
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "Correct-setting-net.ipv4.conf.all.accept_redirects=0-in-/etc/sysctl.conf" >>p3
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
	echo IZ.1.5.9.20.3 >>p12
else
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "net.ipv4.conf.all.accept_redirects=0_is_not_set-in-/etc/sysctl.conf" >>p3
	echo "no" >>p4
	echo IZ.1.5.9.20.3 >>p12
	echo "$c" >> p5
	echo "$z" >>p6	
fi


#IZ.1.5.9.20.4
if [[ "$(sysctl net.ipv4.ip_forward)" == "net.ipv4.ip_forward = 0" ]];then
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "Correct-setting-net.ipv4.ip_forward=0-in-/etc/sysctl.conf" >>p3
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
	echo IZ.1.5.9.20.4 >>p12
else
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "net.ipv4.ip_forward=0_is_not_set-in-/etc/sysctl.conf" >>p3
	echo "no" >>p4
	echo IZ.1.5.9.20.4 >>p12
	echo "$c" >> p5
	echo "$z" >>p6	
fi

#IZ.1.5.9.20.5
if [[ "$(sysctl net.ipv4.conf.all.accept_source_route)" == "net.ipv4.conf.all.accept_source_route = 0" ]];then
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "Correct-setting-net.ipv4.conf.all.accept_source_route=0-in-/etc/sysctl.conf" >>p3
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
	echo IZ.1.5.9.20.5 >>p12
else
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "net.ipv4.conf.all.accept_source_route=0_is_not_set-in-/etc/sysctl.conf" >>p3
	echo "no" >>p4
	echo IZ.1.5.9.20.5 >>p12
	echo "$c" >> p5
	echo "$z" >>p6	
fi

if [[ "$(sysctl net.ipv4.conf.default.accept_source_route)" == "net.ipv4.conf.default.accept_source_route = 0" ]];then
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "Correct-setting-net.ipv4.conf.default.accept_source_route=0-in-/etc/sysctl.conf" >>p3
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
	echo IZ.1.5.9.20.5 >>p12
else
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "net.ipv4.conf.default.accept_source_route=0_is_not_set-in-/etc/sysctl.conf" >>p3
	echo "no" >>p4
	echo IZ.1.5.9.20.5 >>p12
	echo "$c" >> p5
	echo "$z" >>p6	
fi



#IZ.1.5.9.20.6
if [[ "$(sysctl net.ipv4.conf.all.secure_redirects)" == "net.ipv4.conf.all.secure_redirects = 0" ]];then
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "Correct-setting-net.ipv4.conf.all.secure_redirects=0-in-/etc/sysctl.conf" >>p3
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
	echo IZ.1.5.9.20.6 >>p12
else
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "net.ipv4.conf.all.secure_redirects=0_is_not_set-in-/etc/sysctl.conf" >>p3
	echo "no" >>p4
	echo IZ.1.5.9.20.6 >>p12
	echo "$c" >> p5
	echo "$z" >>p6	
fi

if [[ "$(sysctl net.ipv4.conf.default.secure_redirects)" == "net.ipv4.conf.default.secure_redirects = 0" ]];then
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "Correct-setting-net.ipv4.conf.default.secure_redirects=0-in-/etc/sysctl.conf" >>p3
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
	echo IZ.1.5.9.20.6 >>p12
else
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "net.ipv4.conf.default.secure_redirects=0_is_not_set-in-/etc/sysctl.conf" >>p3
	echo "no" >>p4
	echo IZ.1.5.9.20.6 >>p12
	echo "$c" >> p5
	echo "$z" >>p6	
fi



#IZ.1.5.9.20.7
if [[ "$(sysctl net.ipv4.conf.all.log_martians)" == "net.ipv4.conf.all.log_martians = 1" ]];then
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "Correct-setting-net.ipv4.conf.all.log_martians=1-in-/etc/sysctl.conf" >>p3
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
	echo IZ.1.5.9.20.7 >>p12
else
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "net.ipv4.conf.all.log_martians=1_is_not_set-in-/etc/sysctl.conf" >>p3
	echo "no" >>p4
	echo IZ.1.5.9.20.7 >>p12
	echo "$c" >> p5
	echo "$z" >>p6	
fi

if [[ "$(sysctl net.ipv4.conf.default.log_martians)" == "net.ipv4.conf.default.log_martians = 1" ]];then
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "Correct-setting-net.ipv4.conf.default.log_martians=1-in-/etc/sysctl.conf" >>p3
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
	echo IZ.1.5.9.20.7 >>p12
else
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "net.ipv4.conf.default.log_martians=1_is_not_set-in-/etc/sysctl.conf" >>p3
	echo "no" >>p4
	echo IZ.1.5.9.20.7 >>p12
	echo "$c" >> p5
	echo "$z" >>p6	
fi

#IZ.1.5.9.20.8
if [[ "$(sysctl net.ipv4.icmp_ignore_bogus_error_responses)" == "net.ipv4.icmp_ignore_bogus_error_responses = 1" ]];then
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "Correct-setting-net.ipv4.icmp_ignore_bogus_error_responses=1-in-/etc/sysctl.conf" >>p3
	echo "yes" >>p4
        echo IZ.1.5.9.20.8 >>p12
	echo "$c" >> p5
	echo "$z" >>p6
	
else
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "net.ipv4.icmp_ignore_bogus_error_responses=1_is_not_set-in-/etc/sysctl.conf" >>p3
	echo "no" >>p4
	echo IZ.1.5.9.20.8 >>p12
	echo "$c" >> p5
	echo "$z" >>p6	
fi


#IZ.1.5.9.21.1
if [[ "$(sysctl net.ipv6.conf.all.accept_ra)" == "net.ipv6.conf.all.accept_ra = 0" ]];then
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "Correct-setting-net.ipv6.conf.all.accept_ra=0-in-/etc/sysctl.conf" >>p3
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
	echo IZ.1.5.9.21.1 >>p12
else
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "net.ipv6.conf.all.accept_ra=0_is_not_set-in-/etc/sysctl.conf" >>p3
	echo "no" >>p4
	echo IZ.1.5.9.21.1 >>p12
	echo "$c" >> p5
	echo "$z" >>p6	
fi

if [[ "$(sysctl net.ipv6.conf.default.accept_ra)" == "net.ipv6.conf.default.accept_ra = 0" ]];then
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "Correct-setting-net.ipv6.conf.default.accept_ra=0-in-/etc/sysctl.conf" >>p3
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
	echo IZ.1.5.9.21.1 >>p12
else
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "net.ipv6.conf.default.accept_ra=0_is_not_set-in-/etc/sysctl.conf" >>p3
	echo "no" >>p4
	echo IZ.1.5.9.21.1 >>p12
	echo "$c" >> p5
	echo "$z" >>p6	
fi


#IZ.1.5.9.21.2
if [[ "$(sysctl net.ipv6.conf.all.accept_redirects)" == "net.ipv6.conf.all.accept_redirects = 0" ]];then
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "Correct-setting-net.ipv6.conf.all.accept_redirects=0-in-/etc/sysctl.conf" >>p3
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
	echo IZ.1.5.9.21.2 >>p12
else
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "net.ipv6.conf.all.accept_redirects=0_is_not_set-in-/etc/sysctl.conf" >>p3
	echo "no" >>p4
	echo IZ.1.5.9.21.2 >>p12
	echo "$c" >> p5
	echo "$z" >>p6	
fi

if [[ "$(sysctl net.ipv6.conf.default.accept_redirects)" == "net.ipv6.conf.default.accept_redirects = 0" ]];then
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "Correct-setting-net.ipv6.conf.default.accept_redirects=0-in-/etc/sysctl.conf" >>p3
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
	echo IZ.1.5.9.21.2 >>p12
else
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "net.ipv6.conf.default.accept_redirects=0_is_not_set-in-/etc/sysctl.conf" >>p3
	echo "no" >>p4
	echo IZ.1.5.9.21.2 >>p12
	echo "$c" >> p5
	echo "$z" >>p6	
fi


#IZ.1.5.9.24.1.1
if [ "$(rpm -q ftp)" != "package ftp is not installed" ] || [ "$(rpm -q vsftpd)" != "package vsftpd is not installed" ]

then
  
systemctl status vsftpd |grep loaded |grep  enabled

 if [ $? -eq 0 ] ; then
	
		echo "Network Settings" >>p1
		echo "vsftpd service must be disabled" >>p2
		echo "vsftpd service is not  disabled" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "IZ.1.5.9.24.1.1" >>p12
                echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
			echo "$timestamp" >>en4 
	else
		echo "Network Settings" >>p1
		echo "vsftpd service must be disabled." >>p2
		echo "vsftpd service is  disabled." >> p3
		echo "yes" >>p4
		echo "IZ.1.5.9.24.1.1" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
                echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
		echo "$timestamp" >>en4
	fi
else
	echo "Network Settings" >>p1
	echo "vsftpd service must be disabled" >>p2
	echo "vsftpd package is not installed" >> p3
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
	echo "IZ.1.5.9.24.1.1" >>p12
        echo "$fqdn" >>en1
    	echo "$ipAddress" >>en2
    	echo "$osName" >>en3
	echo "$timestamp" >>en4
fi

#IZ.1.5.9.24.1.2
if [ -f /etc/vsftpd/vsftpd.conf ] || [ -f /etc/vsftpd/user_list ] 

then

 if [ "$(stat --format %a /etc/vsftpd/vsftpd.conf)" == 600 ] && [ "$(stat --format %a /etc/vsftpd/user_list)" == 600 ]; then
  

		echo "Network Settings" >>p1
		echo "protect vsftpd control files if they exist" >>p2
		echo "/etc/vsftpd/vsftpd.conf and /etc/vsftpd/user_list have permission set as 600" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "IZ.1.5.9.24.1.2" >>p12

	else
		echo "Network Settings" >>p1
		echo "protect vsftpd control files if they exist" >>p2
		echo "/etc/vsftpd/vsftpd.conf and /etc/vsftpd/user_list do_not have permission set as 600" >> p3
		echo "no" >>p4
		echo "IZ.1.5.9.24.1.2" >>p12
		echo "$c" >> p5
		echo "$z" >>p6

	fi
else
	echo "Network Settings" >>p1
	echo "protect vsftpd control files if they exist" >>p2
	echo "Files /etc/vsftpd/vsftpd.conf and /etc/vsftpd/user_list not exists" >> p3
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
	echo "IZ.1.5.9.24.1.2" >>p12

fi


#IZ.1.5.9.24.4.1;IZ.1.5.9.24.4.2 - updated
systemctl is-enabled vsftpd
if [ $? -eq 0 ];then
if [ -f /etc/vsftpd/vsftpd.conf ] ; then
flag=0
if [ -f /etc/vsftpd/vsftpd.conf ] ; then
	rsa_cert_file=`grep '^rsa_cert_file' /etc/vsftpd/vsftpd.conf |awk -F'=' '{print $2}'`
	rsa_private_key_file=`grep '^rsa_private_key_file' /etc/vsftpd/vsftpd.conf |awk -F'=' '{print $2}'`
	if [ "$rsa_cert_file" != '' ] && [ "$rsa_private_key_file" != '' ]; then		
		if [ -f $rsa_cert_file ] && [ -f $rsa_cert_file ] ; then
			sl1=`stat -c "%a" $rsa_cert_file`
			sl2=`stat -c "%a" $rsa_private_key_file`
			if [ $? -eq 0 ] && [ $sl1 == 600 ] && [ $sl2 == 600 ] ; then
				grep -q '^ssl_enable\s*=\s*YES' /etc/vsftpd/vsftpd.conf
				if [ $? -eq 0 ] ; then
					grep -q '^allow_anon_ssl\s*=\s*YES' /etc/vsftpd/vsftpd.conf
					if [ $? -eq 0 ] ; then
						grep -q '^force_local_data_ssl\s*=\s*YES' /etc/vsftpd/vsftpd.conf
						if [ $? -eq 0 ] ; then
							grep -q '^force_local_logins_ssl\s*=\s*YES' /etc/vsftpd/vsftpd.conf
							if [ $? -eq 0 ] ; then
								grep -q '^ssl_sslv2\s*=\s*NO' /etc/vsftpd/vsftpd.conf
								if [ $? -eq 0 ] ; then
									grep -q '^ssl_sslv3\s*=\s*NO' /etc/vsftpd/vsftpd.conf
									if [ $? -eq 0 ] ; then
										grep -q '^ssl_tlsv1\s*=\s*NO' /etc/vsftpd/vsftpd.conf
										if [ $? -eq 0 ] ; then
											grep -q '^ssl_tlsv1_1\s*=\s*NO' /etc/vsftpd/vsftpd.conf
											if [ $? -eq 0 ] ; then
												grep -q '^ssl_tlsv1_2\s*=\s*YES' /etc/vsftpd/vsftpd.conf
												if [ $? -eq 0 ] ; then
													flag=1
												fi									
											fi										
										fi
									fi
								fi
							fi
						fi
					fi				
				fi
			fi
		fi
	fi
fi
if [ $flag == 1 ] ; then	
	echo "Network Settings" >>p1
	echo "Configure vsftpd service where secure ftp is permitted" >>p2
	echo "secure ftp is permitted" >>p3
	echo "yes" >>p4
	echo "IZ.1.5.9.24.4.1:IZ.1.5.9.24.4.2" >>p12
	echo "$c" >> p5
	echo "$z" >>p6

else
	echo "Network Settings" >>p1
	echo "Configure vsftpd service where secure ftp is permitted" >>p2
	echo "secure ftp is not permitted" >>p3
	echo "no" >>p4
	echo "IZ.1.5.9.24.4.1:IZ.1.5.9.24.4.2" >>p12
	echo "$c" >> p5
	echo "$z" >>p6

fi
else
	echo "Network Settings" >>p1
	echo "Configure vsftpd service where anonymous ftp is permitted." >>p2
	echo "/etc/vsftpd/vsftpd.conf file does not exist" >>p3
	echo "Yes" >>p4
	echo "IZ.1.5.9.24.4.1:IZ.1.5.9.24.4.2" >>p12
	echo "$c" >> p5
	echo "$z" >>p6

fi
else
	echo "Network Settings" >>p1
	echo "Configure vsftpd service where anonymous ftp is permitted." >>p2
	echo "vsftpd service is not enabled" >>p3
	echo "yes" >>p4
	echo "IZ.1.5.9.24.4.1:IZ.1.5.9.24.4.2" >>p12
	echo "$c" >> p5
	echo "$z" >>p6
fi


#IZ.1.5.9.25
rpm -qa | grep nfs-utils
if [ $? -eq 0 ]
then
systemctl is-enabled nfs-server
if [ $? -eq 0 ]
then
	echo "Network Settingss" >>p1
	echo "Network file system (nfs) settings" >>p2
	echo "nfs-server service is enabled" >> p3
	echo "no" >>p4
	echo "IZ.1.5.9.25" >>p12
	echo "$c" >> p5
	echo "$z" >>p6
else
	echo "Network Settingss" >>p1
	echo "Network file system (nfs) settings" >>p2
	echo "nfs-server service is not enabled" >> p3
	echo "yes" >>p4
	echo "IZ.1.5.9.25" >>p12
	echo "$c" >> p5
	echo "$z" >>p6
fi		
else
	echo "Network Settingss" >>p1
	echo "Network file system (nfs) settings" >>p2
	echo "nfs-utils package not installed" >> p3
	echo "yes" >>p4
	echo "IZ.1.5.9.25" >>p12
	echo "$c" >> p5
	echo "$z" >>p6
fi



#IZ.1.4.2.1

if [ "$(rpm -q ftp)" != "package ftp is not installed" ] || [ "$(rpm -q vsftpd)" != "package vsftpd is not installed" ]
then
      if [  -f /etc/ftpusers ] || [ -f /etc/vsftpd.ftpusers ] || [ -f /etc/vsftpd/ftpusers ]
      then


        aa=`cat /etc/ftpusers | grep -i ^root |wc -c`
        bb=`cat /etc/vsftpd.ftpusers | grep -i ^root |wc -c`
        cc=`cat /etc/vsftpd/ftpusers |grep -i ^root |wc -c`
        if [ $aa -gt 0 ] || [ $bb -gt 0 ] || [ $cc -gt 0 ]
        then
                echo "System Settings">> p1
                echo "root-user-in-/etc/ftpusers-or-/etc/vsftpd.ftpusers-or-/etc/vsftp/ftpusers"  >>p2
                echo "root_id_exist in /etc/ftpusers-or-/etc/vsftpd.ftpusers" >>p3
                echo "yes" >>p4
                echo "$c">>p5
                echo "$z" >>p6
                echo "IZ.1.4.2.1" >>p12
        else
                echo "System Settings">> p1
                echo "root-user-in-/etc/ftpusers-or-/etc/vsftpd.ftpusers-or-/etc/vsftp/ftpusers">>p2
                echo "root_id_not_exist" >>p3
                echo "no" >>p4
                echo "IZ.1.4.2.1" >>p12
                echo "$c">>p5
                echo "$z" >>p6
        fi

else
         echo "System Settings" >> p1
        echo "root-user-in-/etc/ftpusers-or-/etc/vsftpd.ftpusers-or-/etc/vsftp/ftpusers" >>p2
        echo "/etc/ftpusers-or-/etc/vsftpd.ftpusers-or-/etc/vsftp/ftpusers does not exist " >>p3
        echo "yes">>p4
        echo "$c" >>p5
        echo "$z">>p6
        echo "IZ.1.4.2.1" >>p12
fi
else
        echo "System Settings">> p1
        echo "root-user-in-/etc/ftpusers-or-/etc/vsftpd.ftpusers-or-/etc/vsftp/ftpusers">> p2
        echo "FTP package is not installed on the server" >>p3
        echo "yes" >>p4
        echo "$c" >>p5
        echo "$z" >>p6
        echo "IZ.1.4.2.1" >>p12
fi


#IZ.2.0.1.0 
if [ -f /etc/motd ] || [ -f /etc/issue ]
then
	str=`cat /etc/motd |wc -c`
	if [ "$str" -gt "0" ]
	then
		echo "Business Use Notice" >>p1
		echo "Business Use Notice exists" >>p2
		echo "Business use notice mentioned in /etc/motd" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "IZ.2.0.1.0" >>p12
	else 
		echo "Business Use Notice" >>p1
		echo "Business Use Notice exists" >>p2
		echo "Business use notice not mentioned in /etc/motd" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "IZ.2.0.1.0" >>p12
	fi
else
		echo "Business Use Notice" >>p1
		echo "Business_use_notice_entry_not_exist_in_file_/etc/motd" >>p2
		echo "/etc/motd_or_/etc/issue_file_not_exist" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "IZ.2.0.1.0" >>p12
fi

#IZ.1.5.9.24.3
if [ "$(rpm -q ftp)" != "package ftp is not installed" ] || [ "$(rpm -q vsftpd)" != "package vsftpd is not installed" ]

then
  
systemctl status vsftpd |grep loaded |grep  enabled

 if [ $? -eq 0 ] ; then
sk=` cat /etc/vsftpd/vsftpd.conf | grep -v '^\s*#' |  grep 'userlist_deny'|awk -F= '{if($2=="NO") {print $2}'}`
sk1=`cat /etc/vsftpd/vsftpd.conf | grep -v '^\s*#' | grep 'userlist_enable'|awk -F= '{if($2=="YES") {print $2}'}`
sk2=`/etc/vsftpd/user_list| grep -v '^\s*#' |grep -w ftp `
sk3=`/etc/vsftpd/user_list | grep -v '^\s*#' |grep -w anonymous ` 

  if [ "$sk" == "NO" ] && [ "$sk1" == "YES" ] && [ "$sk2" == "ftp" ] && [ "$sk3" == "anonymous" ]
    then

   
	
		echo "Network Settings" >>p1
		echo "Configure vsftpd service where anonymous ftp is permitted." >>p2
		echo " vsftpd service where anonymous ftp is permitted." >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "IZ.1.5.9.24.3" >>p12
                echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
		echo "$timestamp" >>en4
	else
		echo "Network Settings" >>p1
		echo "Configure vsftpd service where anonymous ftp is permitted" >>p2
		echo "vsftpd service where anonymous ftp is not  permitted" >> p3
		echo "no" >>p4
		echo "IZ.1.5.9.24.3" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
                echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
		echo "$timestamp" >>en4
	fi
fi
else
	echo "Network Settings" >>p1
	echo "vsftpd service must be disabled" >>p2
	echo "vsftpd package is not installed" >> p3
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
	echo "IZ.1.5.9.24.3" >>p12
        echo "$fqdn" >>en1
    	echo "$ipAddress" >>en2
    	echo "$osName" >>en3
	echo "$timestamp" >>en4
fi






#IZ.1.4.2.2:Root
sk=`cat /etc/passwd |grep ^root| awk -F":" '{print $4}'`

	if [ "$sk" == "0" ]
	then
		echo "System Settings" >>p1
		echo "Ensure default group for the root account is GID 0" >>p2
		echo "Root GID is set to $sk" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo IZ.1.4.2.2 >>p12
	else	
		echo "System Settings" >>p1
		echo "Ensure default group for the root account is GID 0" >>p2
		echo "Root GID is not set to 0. It is Set as $sk" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "IZ.1.4.2.2" >>p12
	fi



####################### Updates ##################################################
#IZ.1.5.9.26
for service in time-dgram time-stream
do
sk=`chkconfig --list 2>/dev/null |awk '{$1=$1};1' |grep ^$service |awk -F":" '{print $2}' |awk '{$1=$1};1'`
	if [ "$sk" == "on" ]
	then
		echo "Network Settings" >>p1
		echo "Time network service" >>p2
		echo "$service setting is on in chkconfig" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.5.9.26" >>p12
	else
		echo "Network Settings" >>p1
		echo "Time network service" >>p2
		echo "$service setting is off in chkconfig" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.5.9.26" >>p12
	fi
done


#IZ.1.5.9.27 - updated
for service in tftp tftp.orig
do
sk=`chkconfig --list 2>/dev/null |awk '{$1=$1};1' |grep ^$service |awk -F":" '{print $2}' |awk '{$1=$1};1'`
	if [ "$sk" == "on" ]
	then
		echo "Network Settings" >>p1
		echo "tftp service" >>p2
		echo "$service service is enabled in chkconfig" >>p3
		echo "IZ.1.5.9.27">>p12
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	else
		echo "Network Settings" >>p1
		echo "tftp service" >>p2
		echo "$service service is not enabled in chkconfig" >>p3
		echo "IZ.1.5.9.27">>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	fi
done

#IZ.1.5.9.28
rpm -qa |grep "xinetd"
if [ $? -eq 0 ]
then
for service in chargen-dgram chargen-stream daytime-dgram daytime-stream discard-dgram discard-stream echo-dgram echo-stream tcpmux-server time-dgram time-stream
do
	sk=`chkconfig --list 2>/dev/null |awk '{$1=$1};1' |grep ^$service |awk -F":" '{print $2}' |awk '{$1=$1};1'`
	if [ "$sk" == "off" ]
	then
		echo "Network Settings" >>p1
		echo "Ensure xinetd is not enabled" >>p2
		echo "Xinetd Service $service is disabled in chkconfig" >>p3
		echo "yes" >>p4
		echo "IZ.1.5.9.28" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Network Settings" >>p1
		echo "Ensure xinetd is not enabled" >>p2
		echo "Xinetd Service $service is enabled in chkconfig" >>p3
		echo "no" >>p4
		echo "IZ.1.5.9.28" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
done
else
		echo "Network Settings" >>p1
		echo "Ensure xinetd is not enabled" >>p2
		echo "Xinetd package is not installed" >>p3
		echo "yes" >>p4
		echo "IZ.1.5.9.28" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
fi

#IZ.1.5.9.3
if [[ "$(rpm -q rusers-server)" != "package rusers-server is not installed" ]]
then
	systemctl is-enabled rstatd
	if [ $? -eq 0 ]
	then
		echo "Network Settings" >>p1
		echo "RSTATD" >>p2
		echo "RSTATD service is enabled" >>p3
		echo "no" >>p4
		echo "IZ.1.5.9.3" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Network Settings" >>p1
		echo "RSTATD" >>p2
		echo "RSTATD service is not enabled" >>p3
		echo "yes" >>p4
		echo "IZ.1.5.9.3" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
		echo "Network Settings" >>p1
		echo "RSTATD" >>p2
		echo "rusers-server package is not installed" >>p3
		echo "yes" >>p4
		echo "IZ.1.5.9.3" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
fi

#IZ.1.5.9.4
if [[ "$(rpm -q tftp-server)" != "package tftp-server is not installed" ]]
then
	systemctl is-enabled tftp.socket
	if [ $? -eq 0 ]
	then
		echo "Network Settings" >>p1
		echo "TFTP" >>p2
		echo "tftp.socket is enabled" >>p3
		echo "no" >>p4
		echo "IZ.1.5.9.4" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Network Settings" >>p1
		echo "TFTP" >>p2
		echo "tftp.socket is not enabled" >>p3
		echo "yes" >>p4
		echo "IZ.1.5.9.4" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
		echo "Network Settings" >>p1
		echo "TFTP" >>p2
		echo "tftp-server package is not installed" >>p3
		echo "yes" >>p4
		echo "IZ.1.5.9.4" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
fi

#IZ.1.5.9.6
if [[ "$(rpm -q rusers-server)" != "package rusers-server is not installed" ]]
then
	systemctl is-enabled rusersd
	if [ $? -eq 0 ]
	then
		echo "Network Settings" >>p1
		echo "RUSERSD" >>p2
		echo "rusersd service is enabled" >>p3
		echo "no" >>p4
		echo "IZ.1.5.9.6" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Network Settings" >>p1
		echo "RUSERSD" >>p2
		echo "rusersd service is not enabled" >>p3
		echo "yes" >>p4
		echo "IZ.1.5.9.6" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
		echo "Network Settings" >>p1
		echo "RUSERSD" >>p2
		echo "rusers-server package is not installed" >>p3
		echo "yes" >>p4
		echo "IZ.1.5.9.6" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
fi

#IZ.1.5.9.10
if [[ "$(rpm -q finger-server)" != "package finger-server is not installed" ]]
then
	systemctl is-enabled finger
	if [ $? -eq 0 ]
	then
		echo "Network Settings" >>p1
		echo "FINGER" >>p2
		echo "finger service is enabled" >>p3
		echo "no" >>p4
		echo "IZ.1.5.9.10" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Network Settings" >>p1
		echo "FINGER" >>p2
		echo "finger service is not enabled" >>p3
		echo "yes" >>p4
		echo "IZ.1.5.9.10" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
		echo "Network Settings" >>p1
		echo "FINGER" >>p2
		echo "finger-server-server package is not installed" >>p3
		echo "yes" >>p4
		echo "IZ.1.5.9.10" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
fi

#IZ.1.5.9.11
if [[ "$(rpm -q tcpspray)" != "package tcpspray is not installed" ]]
then
		echo "Network Settings" >>p1
		echo "SPRAYD" >>p2
		echo "tcpspray package is installed" >>p3
		echo "no" >>p4
		echo "IZ.1.5.9.11" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
else
		echo "Network Settings" >>p1
		echo "SPRAYD" >>p2
		echo "tcpspray package is not installed" >>p3
		echo "yes" >>p4
		echo "IZ.1.5.9.11" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
fi

#IZ.1.5.9.12
if [[ "$(rpm -q pcfnsd)" != "package pcfnsd is not installed" ]]
then
		echo "Network Settings" >>p1
		echo "PCNFSD" >>p2
		echo "pcfnsd package is installed" >>p3
		echo "no" >>p4
		echo "IZ.1.5.9.12" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
else
		echo "Network Settings" >>p1
		echo "PCNFSD" >>p2
		echo "pcfnsd package is not installed" >>p3
		echo "yes" >>p4
		echo "IZ.1.5.9.12" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
fi

#IZ.1.5.9.14
if [[ "$(rpm -q rwho)" != "package rwho is not installed" ]]
then
	systemctl is-enabled rwhod
	if [ $? -eq 0 ]
	then
		echo "Network Settings" >>p1
		echo "RWHO" >>p2
		echo "rwhod service is enabled" >>p3
		echo "no" >>p4
		echo "IZ.1.5.9.14" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Network Settings" >>p1
		echo "RWHO" >>p2
		echo "rwhod service is not enabled" >>p3
		echo "yes" >>p4
		echo "IZ.1.5.9.14" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
		echo "Network Settings" >>p1
		echo "RWHO" >>p2
		echo "rwho package is not installed" >>p3
		echo "yes" >>p4
		echo "IZ.1.5.9.14" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
fi


#IZ.1.5.9.29 - updated
systemctl is-enabled avahi-daemon
if [ $? -ne 0 ] ; then
	echo "Network Settings" >>p1
	echo "avahi service" >>p2
	echo "avahi service is not running" >>p3
	echo "IZ.1.5.9.29">>p12
	echo "yes" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
			echo "$timestamp" >>en4
else
	echo "Network Settings" >>p1
	echo "avahi service" >>p2
	echo "avahi service is running" >>p3
	echo "IZ.1.5.9.29">>p12
	echo "no" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
			echo "$timestamp" >>en4
fi

#IZ.1.5.9.30
systemctl is-enabled slapd
if [ $? -ne 0 ]
then
        echo "Network Settings" >>p1
        echo "Ensure LDAP server is not enabled" >>p2
        echo "LDAP server daemon slapd is disabled" >>p3
        echo "yes" >>p4
        echo "$c" >>p5
        echo "$z" >>p6
        echo "IZ.1.5.9.30" >>p12
else
        echo "Network Settings" >>p1
        echo "Ensure LDAP server is not enabled" >>p2
        echo "LDAP server daemon slapd is enabled" >>p3
        echo "No" >>p4
        echo "$c" >>p5
        echo "$z" >>p6
        echo "IZ.1.5.9.30" >>p12
fi


#IZ.1.5.9.35 - updated
systemctl is-enabled cups
if [ $? -ne 0 ] ; then
	echo "Network Settings" >>p1
	echo "cups service" >>p2
	echo "cups service is not running" >>p3
	echo "IZ.1.5.9.35">>p12
	echo "yes" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
			echo "$timestamp" >>en4
else
	echo "Network Settings" >>p1
	echo "cups service" >>p2
	echo "cups service is running" >>p3
	echo "IZ.1.5.9.35">>p12
	echo "no" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
			echo "$timestamp" >>en4
fi


#IZ.1.8.3.2.1
str=`ls -ld /usr |awk '{print $1}' |cut -c9`
if [ "$str" == "w" ]
then
		echo "Protecting Resources - OSRs" >>p1
		echo "/usr-dir-permission" >>p2
		echo "/usr-dir-is-writtable-by-others" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.8.3.2.1" >>p12
else
		echo "Protecting Resources - OSRs" >>p1
		echo "/usr-dir-permission" >>p2
		echo "/usr-dir-permission-is-correctly-set" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.8.3.2.1" >>p12
fi

#IZ.1.8.4.2.1
str=$(stat -c "%a %n" /etc/shadow |awk '{print $1}')
if [ "$str" == "0" ] || [ "$str" == "600" ]
then
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/shadow permission" >>p2
		echo "/etc/shadow permission-is-correctly-set as $str" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.8.4.2.1" >>p12
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/shadow permission" >>p2
		echo "/etc/shadow permission-is-incorrectly set as $str" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.8.4.2.1" >>p12
fi

#IZ.1.8.4.2.3
str=$(stat -c "%a %n" /etc/shadow- |awk '{print $1}')
if [ "$str" == "0" ]
then
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/shadow- permission" >>p2
		echo "/etc/shadow- permission-is-correctly-set as $str" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.8.4.2.3" >>p12
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/shadow- permission" >>p2
		echo "/etc/shadow- permission-is-incorrectly set as $str" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.8.4.2.3" >>p12
fi

#IZ.1.8.4.2.2
str=$(stat -c "%a %n" /etc/gshadow |awk '{print $1}')
if [ "$str" == "0" ]
then
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/gshadow permission" >>p2
		echo "/etc/gshadow permission-is-correctly-set as $str" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.8.4.2.2" >>p12
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/gshadow permission" >>p2
		echo "/etc/gshadow permission-is-incorrectly set as $str" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.8.4.2.2" >>p12
fi

#IZ.1.8.4.2.4
str=$(stat -c "%a %n" /etc/gshadow- |awk '{print $1}')
if [ "$str" == "0" ]
then
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/gshadow- permission" >>p2
		echo "/etc/gshadow- permission-is-correctly-set as $str" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.8.4.2.4" >>p12
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/gshadow- permission" >>p2
		echo "/etc/gshadow- permission-is-incorrectly set as $str" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.8.4.2.4" >>p12
fi

#IZ.1.8.18.3
find /etc/rc.d/ -type f -perm /g+w \! -perm -1000 >>world-writable-test
find /etc/rc.d/ -type d -perm /g+w \! -perm -1000 >>world-writable-test

fc=`cat world-writable-test |wc -l`

if [ $fc == 0 ] 
then
	echo "Protecting Resources - OSRs" >>p1
	echo "/etc/rc.d File-Directory-write-permissions-for-groups" >>p2
	echo "No files or directory found deviation" >> p3
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
	echo IZ.1.8.18.3>>p12
else
	for i in `cat world-writable-test`
	do
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/rc.d File-Directory-write-permissions-for-groups" >>p2
		echo "$i" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo IZ.1.8.18.3>>p12
	done
fi
rm -rf world-writable-test


#IZ.1.8.20.3
find /etc/cron.d/ -type f -perm /g+w \! -perm -1000 >>world-writable-test
find /etc/cron.d/ -type d -perm /g+w \! -perm -1000 >>world-writable-test

fc=`cat world-writable-test |wc -l`

if [ $fc == 0 ] 
then
	echo "Protecting Resources - OSRs" >>p1
	echo "/etc/cron.d File-Directory-write-permissions-for-groups" >>p2
	echo "No files found deviation $i" >> p3
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
	echo IZ.1.8.20.3>>p12
else
	for i in `cat world-writable-test`
	do
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/cron.d File-Directory-write-permissions-for-groups" >>p2
		echo "Group has write permission for $i" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo IZ.1.8.20.3>>p12
	done
fi
rm -rf world-writable-test

#IZ.2.0.1.1 - updated (06-05-2021)
rpm -qa | grep '^gdm-'
if [ $? -eq 0 ] ; then
	if [ -f /etc/dconf/profile/gdm ] ; then
	sk=`egrep '^user-db:|^system-db:|^file-db:' /etc/dconf/profile/gdm|wc -l`
		if [ $sk -gt 0 ] ; then 
		ss=`egrep '^\[org/gnome/login-screen\]|^banner-message-enable|^banner-message-text' /etc/dconf/db/gdm.d/* 2>/dev/null | LC_ALL=C sort -V|wc -l`
			if [ $ss -gt 0 ] ; then
				echo "Business Use Notice" >>p1
				echo "Business Use Notice exists in Gnome" >>p2
				echo "GDM package is installed.The GNOME setting is correct" >> p3
				echo "yes" >>p4
				echo "IZ.2.0.1.1" >>p12
			else 
				echo "Business Use Notice" >>p1
				echo "Business Use Notice exists in Gnome" >>p2
				echo "GDM package is installed.But The GNOME setting is incorrect" >> p3
				echo "no" >>p4
				echo "$c" >> p5
				echo "$z" >>p6
				echo "IZ.2.0.1.1" >>p12
			fi
		else
			echo "Business Use Notice" >>p1
			echo "Business Use Notice exists in Gnome" >>p2
			echo "user-db:|system-db:|file-db: are not configured" >> p3
			echo "no" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
			echo "IZ.2.0.1.1" >>p12
		fi
	else 
		echo "Business Use Notice" >>p1
		echo "Business Use Notice exists in Gnome" >>p2
		echo "/etc/dconf/profile/gdm this file does not exist" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "IZ.2.0.1.1" >>p12
	fi
else
		echo "Business Use Notice" >>p1
		echo "Business Use Notice exists in Gnome" >>p2
		echo "The gdm package not installed" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "IZ.2.0.1.1" >>p12
fi

#IZ.2.1.2
if [ "$(rpm -q coreutils)" == "package coreutils is not installed" ] || [ "$(rpm -q openssl)" == "package coreutils is not installed" ]
then
	echo "Encryption" >>p1
	echo "File/Database Storage / Checksum" >>p2
	echo "Either coreutils or openssl package not installed" >>p3
	echo "no" >> p4
	echo "IZ.2.1.2" >>p12
	echo "$c" >> p5
	echo "$z" >>p6	
else
	echo "Encryption" >>p1
	echo "File/Database Storage / Checksum" >>p2
	echo "Either coreutils or openssl package installed" >>p3
	echo "yes" >> p4
	echo "IZ.2.1.2" >>p12
	echo "$c" >> p5
	echo "$z" >>p6
fi


#IZ.1.8.4.3.1
str=$(stat -c "%a %n" /etc/crontab |awk '{print $1}')
str1=$(ls -ld /etc/crontab |awk '{print $3}')
str2=$(ls -ld /etc/crontab |awk '{print $4}')
if [ "$str" == "600" ] && [ "$str1" == "root" ] && [ "$str2" == "root" ]
then
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/crontab-permission" >>p2
		echo "/etc/crontab-permission-is-correctly set as $str and $str1:$str2" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.8.4.3.1" >>p12
else
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/crontab-permission" >>p2
		echo "/etc/crontab-permission-is-incorrectly set as $str and $str1:$str2" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.8.4.3.1" >>p12
fi

#IZ.1.8.4.3.2
str=$(stat -c "%a %n" /etc/cron.hourly |awk '{print $1}')
str1=$(ls -ld /etc/cron.hourly |awk '{print $3}')
str2=$(ls -ld /etc/cron.hourly |awk '{print $4}')
if [[ "$str" == "700" || "$str" == "600" ]] && [ "$str1" == "root" ] && [ "$str2" == "root" ]
then
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/cron.hourly-permission" >>p2
		echo "/etc/cron.hourly-permission-is-correctly set as $str and $str1:$str2" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.8.4.3.2" >>p12
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/cron.hourly-permission" >>p2
		echo "/etc/cron.hourly-permission-is-incorrectly set as $str and $str1:$str2" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.8.4.3.2" >>p12
fi

#IZ.1.8.4.3.3
str=$(stat -c "%a %n" /etc/cron.daily |awk '{print $1}')
str1=$(ls -ld /etc/cron.daily |awk '{print $3}')
str2=$(ls -ld /etc/cron.daily |awk '{print $4}')
if [[ "$str" == "700" || "$str" == "600" ]] && [ "$str1" == "root" ] && [ "$str2" == "root" ]
then
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/cron.daily-permission" >>p2
		echo "/etc/cron.daily-permission-is-correctly set as $str and $str1:$str2" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.8.4.3.3" >>p12
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/cron.daily-permission" >>p2
		echo "/etc/cron.daily-permission-is-incorrectly set as $str and $str1:$str2" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.8.4.3.3" >>p12
fi

#IZ.1.8.4.3.4:Crontab.weekly
str=$(stat -c "%a %n" /etc/cron.weekly |awk '{print $1}')
str1=$(ls -ld /etc/cron.weekly |awk '{print $3}')
str2=$(ls -ld /etc/cron.weekly |awk '{print $4}')
if [[ "$str" == "700" || "$str" == "600" ]] && [ "$str1" == "root" ] && [ "$str2" == "root" ]
then
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/cron.weekly-permission" >>p2
		echo "/etc/cron.weekly-permission-is-correctly set as $str and $str1:$str2" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.8.4.3.4" >>p12
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/cron.weekly-permission" >>p2
		echo "/etc/cron.weekly-permission-is-incorrectly set as $str and $str1:$str2" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.8.4.3.4" >>p12
fi

#IZ.1.8.4.3.5:Crontab.monthly
str=$(stat -c "%a %n" /etc/cron.monthly |awk '{print $1}')
str1=$(ls -ld /etc/cron.monthly |awk '{print $3}')
str2=$(ls -ld /etc/cron.monthly |awk '{print $4}')
if [[ "$str" == "700" || "$str" == "600" ]] && [ "$str1" == "root" ] && [ "$str2" == "root" ]
then
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/cron.monthly-permission" >>p2
		echo "/etc/cron.monthly-permission-is-correctly set as $str and $str1:$str2" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.8.4.3.5" >>p12
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/cron.monthly-permission" >>p2
		echo "/etc/cron.monthly-permission-is-incorrectly set as $str and $str1:$str2" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.8.4.3.5" >>p12
fi

#IZ.1.8.4.3.6
str=$(stat -c "%a %n" /etc/cron.d |awk '{print $1}')
str1=$(ls -ld /etc/cron.d |awk '{print $3}')
str2=$(ls -ld /etc/cron.d |awk '{print $4}')
if [[ "$str" == "700" || "$str" == "600" ]] && [ "$str1" == "root" ] && [ "$str2" == "root" ]
then
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/cron.d-permission" >>p2
		echo "/etc/cron.d-permission-is-correctly set as $str and $str1:$str2" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.8.4.3.6" >>p12
else
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/cron.d-permission" >>p2
		echo "/etc/cron.d-permission-is-incorrectly set as $str and $str1:$str2" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.8.4.3.6" >>p12
fi



#IZ.1.8.12.8:gpgcheck
sk=`cat /etc/yum.conf |grep gpgcheck |awk -F"=" '{print $2}'`
if [ "$sk" == "1" ]
then
		echo "Protecting Resources - OSRs" >>p1
		echo "Gpgcheck" >>p2
		echo "IZ.1.8.12.8" >>p12
		echo "Gpgcheck is set correctly" >> p3
		echo "Yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
else
		echo "Protecting Resources - OSRs" >>p1
		echo "Gpgcheck" >>p2
		echo "IZ.1.8.12.8" >>p12
		echo "Gpgcheck is not set as 1" >> p3
		echo "No" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
fi

#IZ.1.8.3.5:Grub2-Permission
str=$(stat -c "%a %n" /boot/grub2 |awk '{print $1}')
if [ "$str" == "700" ]
then
		echo "Protecting Resources - OSRs" >>p1
		echo "/boot/grub2-permission" >>p2
		echo "/boot/grub2-permission-is-correctly-set" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.8.3.5" >>p12
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "/boot/grub2-permission" >>p2
		echo "/boot/grub2-permission-is-incorrect" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.8.3.5" >>p12
fi

#IZ.1.8.3.4:boot-permission&owner
str=$(stat -c "%a %n" /boot |awk '{print $1}')
str1=`ls -ld /boot |awk '{print $3}'`
if [ "$str" == 555 ] && [ "$str1" == root ]
       
then
		echo "Protecting Resources - OSRs" >>p1
		echo "/boot-permission and owner" >>p2
		echo "/boot-permission-is-correctly-set" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.8.3.4" >>p12
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "/boot-permission and owner" >>p2
		echo "/boot-permission and owner-is-incorrect" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.8.3.4" >>p12
fi



#IZ.1.5.9.40:rsh package
str=`rpm -qa | grep -i ^rsh | wc -l`
if [ $str -gt 0 ]
then
		echo "Network Settings" >>p1
		echo "RSH" >>p2
		echo "RSH package is installed" >>p3
		echo "No" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.5.9.40" >>p12
	else
		echo "Network Settings" >>p1
		echo "RSH" >>p2
		echo "RSH package is not installed" >>p3
		echo "Yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.5.9.40" >>p12
fi

#IZ.1.5.11.3
if [[ "$(rpm -q rsh-server)" != "package rsh-server is not installed" ]]
then
	systemctl is-enabled rexec
	if [ $? -eq 0 ]
	then
		echo "Network Settings" >>p1
		echo "rexec" >>p2
		echo "rexec service is enabled" >>p3
		echo "no" >>p4
		echo "IZ.1.5.11.3" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Network Settings" >>p1
		echo "rexec" >>p2
		echo "rexec service is not enabled" >>p3
		echo "yes" >>p4
		echo "IZ.1.5.11.3" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
		echo "Network Settings" >>p1
		echo "rexec" >>p2
		echo "rsh-server package is not installed" >>p3
		echo "yes" >>p4
		echo "IZ.1.5.11.3" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
fi



#IZ.1.5.13.1
res=`sysctl fs.suid_dumpable|awk -F= '{print $2}'`
if [ $res == 0 ] ; then
	echo "Network Settings" >>p1
	echo "core dumps" >>p2
	echo "core dumps are restricted" >>p3
	echo "IZ.1.5.13.1">>p12
	echo "$fqdn" >>e1
	echo "$ipAddress" >>e2
	echo "$osName" >>e3
	echo "$z" >>e4
	echo "$c" >>e5
	echo "$timestamp" >>e6
	echo "yes" >>p4
else
	echo "Network Settings" >>p1
	echo "core dumps" >>p2
	echo "core dumps are not restricted" >>p3
	echo "IZ.1.5.13.1">>p12
	echo "$fqdn" >>e1
	echo "$ipAddress" >>e2
	echo "$osName" >>e3
	echo "$z" >>e4
	echo "$c" >>e5
	echo "$timestamp" >>e6
	echo "no" >>p4
fi

#IZ.1.5.13.2
if [[ "$(sysctl kernel.randomize_va_space)" == "kernel.randomize_va_space = 2" ]];then
	echo "Network Settings" >>p1
	echo "ASLR" >>p2
	echo "ASLR is enabled" >>p3
	echo "IZ.1.5.13.2">>p12
	echo "Yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6

else
	echo "Network Settings" >>p1
	echo "ASLR" >>p2
	echo "ASLR is disabled" >>p3
	echo "IZ.1.5.13.2">>p12
	echo "No" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
fi
#IZ.1.8.3.2.2:/usr

echo "Protecting Resources - OSRs" >>p1
echo "/usr Exceptions to OSR" >>p2
echo "/usr Exceptions to OSR" >>p3
echo "Yes" >>p4
echo "$c" >>p5
echo "$z" >>p6
echo "IZ.1.8.3.2.2" >>p12

#IZ.1.5.9.39 - updated
systemctl is-enabled smb

if [ $? != 0 ] ; then
	echo "Network Settings" >>p1
	echo "samba service" >>p2
	echo "samba service is not running" >>p3
	echo "IZ.1.5.9.39">>p12
	echo "yes" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
			echo "$timestamp" >>en4
else
	echo "Network Settings" >>p1
	echo "samba service" >>p2
	echo "samba service is running" >>p3
	echo "IZ.1.5.9.39">>p12
	echo "no" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
			echo "$timestamp" >>en4
fi

#IZ.1.5.12.4 
str=$(rpm -qa | grep -i postfix| wc -l)
str1=$(rpm -qa | grep -i sendmail| wc -l)
if [ $str -eq 0 ] && [ $str1 -eq 0 ]
#if [ $? -eq 0 ]
then
		echo "Network Settings" >>p1
		echo "Postfix or Sendmail" >>p2
		echo "Postfix or Sendmail is not installed " >>p3
		echo "Yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.5.12.4" >>p12
	else
		echo "Network Settings" >>p1
		echo "Postfix or Sendmail" >>p2
		echo "Postfix or Sendmail is installed, Manual_Check_Required" >>p3
		echo "No" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.5.12.4" >>p12
fi


#IZ.1.5.9.39 
rpm -qa | grep -i smb| wc -l
if [ $? -eq 0 ]
then
		echo "Network Settings" >>p1
		echo "Samba" >>p2
		echo "Samba is not installed " >>p3
		echo "Yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.5.9.39" >>p12
	else
		echo "Network Settings" >>p1
		echo "Samba" >>p2
		echo "Samba is installed, Manual_Check_Required" >>p3
		echo "No" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.5.9.39" >>p12
fi





#IZ.1.5.12.4 
str=$(rpm -qa | grep -i postfix| wc -l)
str1=$(rpm -qa | grep -i sendmail| wc -l)
if [ $str -eq 0 ] && [ $str1 -eq 0 ]
then
		echo "Network Settings" >>p1
		echo "Postfix or Sendmail" >>p2
		echo "Postfix or Sendmail is not installed " >>p3
		echo "Yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.5.12.4" >>p12
	else
		echo "Network Settings" >>p1
		echo "Postfix or Sendmail" >>p2
		echo "Postfix or Sendmail is installed, Manual_Check_Required" >>p3
		echo "No" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.5.12.4" >>p12
fi





#IZ.1.5.9.32
str=$(rpm -qa | grep -i squid | wc -l)
if [ $str -eq 0 ]
then
		echo "Network Settings" >>p1
		echo "HTTP Proxy" >>p2
		echo "HTTP proxy is Disabled " >>p3
		echo "Yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.5.9.32" >>p12
	else
		echo "Network Settings" >>p1
		echo "HTTP Proxy" >>p2
		echo "HTTP proxy is enable, Manual_Check_Required" >>p3
		echo "No" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.5.9.32" >>p12
fi

#IZ.1.5.9.36 - updated
systemctl is-enabled dhcpd
if [ $? -ne 0 ] ; then
	echo "Network Settings" >>p1
	echo "dhcp service" >>p2
	echo "dhcp service is not running" >>p3
	echo "IZ.1.5.9.36">>p12
	echo "yes" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
			echo "$timestamp" >>en4
else
	echo "Network Settings" >>p1
	echo "dhcp service" >>p2
	echo "dhcp service is running" >>p3
	echo "IZ.1.5.9.36">>p12
	echo "no" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
			echo "$timestamp" >>en4
fi




#IZ.1.5.9.31
systemctl is-enabled dovecot
if [ $? -ne 0 ]
then
		echo "Network Settings" >>p1
		echo "Ensure IMAP and POP3 server is not enabled" >>p2
		echo "IMAP and POP3 Service is Disabled " >>p3
		echo "Yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.5.9.31" >>p12
	else
		echo "Network Settings" >>p1
		echo "IMAP and POP" >>p2
		echo "IMAP and POP3 Service is enabled" >>p3
		echo "No" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.5.9.31" >>p12
fi


#IZ.1.5.9.32
systemctl is-enabled squid
if [ $? -ne 0 ]
then
		echo "Network Settings" >>p1
		echo "HTTP Proxy" >>p2
		echo "HTTP proxy is Disabled " >>p3
		echo "Yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.5.9.32" >>p12
	else
		echo "Network Settings" >>p1
		echo "HTTP Proxy" >>p2
		echo "HTTP proxy is enabled" >>p3
		echo "No" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.5.9.32" >>p12
fi

#IZ.1.5.9.33
systemctl is-enabled ntalk
if [ $? -ne 0 ]
then
		echo "Network Settings" >>p1
		echo "Ensure talk server is not enabled" >>p2
		echo "ntalk server is disabled " >>p3
		echo "Yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.5.9.33" >>p12
	else
		echo "Network Settings" >>p1
		echo "Ensure talk server is not enabled" >>p2
		echo "ntalk server is enabled" >>p3
		echo "No" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.5.9.33" >>p12
fi

#IZ.1.5.9.34:Rsync Service
systemctl is-enabled rsyncd
if [ $? -eq 0 ]
then
		echo "Network Settings" >>p1
		echo "Rsync" >>p2
		echo "Rsync is Enabled" >>p3
		echo "No" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.5.9.34" >>p12
	else
		echo "Network Settings" >>p1
		echo "Rsync" >>p2
		echo "Rsync-is Disabled" >>p3
		echo "Yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.5.9.34" >>p12
fi

#IZ.1.5.9.38
systemctl is-enabled httpd
if [ $? -ne 0 ]
then
		echo "Network Settings" >>p1
		echo "HTTP" >>p2
		echo "HTTP service is not running " >>p3
		echo "Yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.5.9.38" >>p12
	else
		echo "Network Settings" >>p1
		echo "HTTP" >>p2
		echo "HTTP service is running, Manual_Check_Required" >>p3
		echo "No" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.5.9.38" >>p12
fi

#IZ.1.5.9.41
rpm -q talk
if [ $? -ne 0 ]
then
		echo "Network Settings" >>p1
		echo "Talk" >>p2
		echo "Talk Package is not installed " >>p3
		echo "Yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.5.9.41" >>p12
	else
		echo "Network Settings" >>p1
		echo "Talk" >>p2
		echo "Talk Package is installed, Manual_Check_Required" >>p3
		echo "No" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "IZ.1.5.9.41" >>p12
fi



#IZ.1.8.23.1 
find / -xdev -type d -perm /o+w \! -perm -1000 2>/dev/null >world-writable-test

fc=`cat world-writable-test|wc -l`

if [ $fc == 0 ] 
then
	echo "Protecting Resources - mixed" >>p1
	echo "Ensure sticky bit is set on all world-writable directories on local file systems" >>p2
	echo "No deviation found for world writable dir has stickybit set" >> p3
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
	echo "IZ.1.8.23.1" >>p12
else

for i in `cat world-writable-test`
do
	echo "Protecting Resources - mixed" >>p1
	echo "Ensure sticky bit is set on all world-writable directories on local file systems" >>p2
	echo "$i dir is set as writable for others and has no sticky bit set" >> p3
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
	echo "IZ.1.8.23.1" >>p12
done
fi
rm -rf world-writable-test

#IZ.1.5.9.37 - updated
systemctl is-enabled named
if [ $? -ne 0 ] ; then
	echo "Network Settings" >>p1
	echo "dns service" >>p2
	echo "dns service is not running" >>p3
	echo "IZ.1.5.9.37">>p12
	echo "yes" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
			echo "$timestamp" >>en4
else
	echo "Network Settings" >>p1
	echo "dns service" >>p2
	echo "dns service is running" >>p3
	echo "IZ.1.5.9.37">>p12
	echo "no" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
    		echo "$fqdn" >>en1
    		echo "$ipAddress" >>en2
    		echo "$osName" >>en3
			echo "$timestamp" >>en4
fi

#IZ.1.1.8.3.2
flag=0
for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do
  grep -q -P "^.*?:[^:]*:$i:" /etc/group 
  if [ $? -ne 0 ]; then 
  	flag=1
	echo "Password Requirements" >>p1
	echo "Ensure all groups in /etc/passwd exist in /etc/group" >>p2
	echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group" >>p3
	echo "no" >>p4
	echo "IZ.1.1.8.3.2" >>p12	
  fi 
done
if [ $flag == 0 ] ; then
	echo "Password Requirements" >>p1
	echo "Ensure all groups in /etc/passwd exist in /etc/group" >>p2
	echo "All groups in /etc/passwd exist in /etc/group" >>p3
	echo "yes" >>p4
	echo "IZ.1.1.8.3.2" >>p12	
fi





#IZ.1.4.3.3.1:Audit Daemon
systemctl is-enabled auditd
if [ $? -eq 0 ]
then
		echo "System Settings" >>p1
		echo "Audit Daemon" >>p2
		echo "IZ.1.4.3.3.1" >>p12
		echo "Audit Daemon is enabled"  >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
else
		echo "System Settings" >>p1
		echo "Audit Daemon" >>p2
		echo "IZ.1.4.3.3.1" >>p12
		echo "Audit Daemon is disabled" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
fi

#IZ.1.2.1.4.3
sk=`grep '^[^#]*\$umask' /etc/rsyslog.conf /etc/rsyslog.d/*.conf | LC_ALL=C sort -V |wc -l`
if [ $sk -eq 0 ] ; then
	echo "Logging" >>p1
        echo "Login success or failure, logs created secure by default" >>p2
        echo "Permission is correctly set for files to be created by rsyslog " >> p3
        echo "IZ.1.2.1.4.3">>p12
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
else
sl1=$(cat /etc/rsyslog.conf |grep '$umask'|awk '{print $2}')
sl2=$(grep -A1 '^[^#]*\$umask' /etc/rsyslog.conf |tail -1 |grep '$FileCreateMode'|awk '{print $2}')
if [ "$sl1" == "0077" ] && [ "$sl2" == "0600" ]
then
	echo "Logging" >>p1
        echo "Login success or failure, logs created secure by default" >>p2
        echo "umask value is set as 0077 and FileCreateMode value is set as 0600 in /etc/rsyslog.conf" >> p3
        echo "IZ.1.2.1.4.3">>p12
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6     
else
	echo "Logging" >>p1
        echo "Login success or failure, logs created secure by default" >>p2
        echo "umask value and FileCreateMode value is not set correct in /etc/rsyslog.conf.Check Techspec" >> p3        
	echo "IZ.1.2.1.4.3">>p12
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
       
fi
fi


#IZ.1.1.4.5
if [ $(egrep -v '^\s*#' /etc/pam.d/password-auth | egrep 'auth.*pam_unix.so.*nullok' |wc -l) -gt 0 ] || [ $(egrep -v '^\s*#' /etc/pam.d/system-auth | egrep 'auth.*pam_unix.so.*nullok' |wc -l) -gt 0 ]
then
	echo "Password Requirementss" >>p1
        echo "Do not accept null passwords" >>p2
        echo "Nullok is allowed in /etc/pam.d/password-auth or /etc/pam.d/system-auth" >> p3
        echo "IZ.1.1.4.5">>p12
	echo "no" >>p4
        echo "$c" >> p5
        echo "$z" >>p6
        
else
	echo "Password Requirementss" >>p1
        echo "Null Password is allowed" >>p2
        echo "Nullok is not allowed in /etc/pam.d/password-auth or /etc/pam.d/system-auth" >> p3
        echo "IZ.1.1.4.5">>p12
	echo "yes" >>p4
        echo "$c" >> p5
        echo "$z" >>p6
        
fi


#IZ.1.1.1.3
epoch=$(($(date --date "$1" +%s)/86400))
sk=`cat /etc/shadow | awk -F: -v epoch="$epoch" '($3 > epoch ) { print $1 " has a future date password change: " $3 " : today epoch is "epoch }' |wc -l`
if [ $sk -gt 0 ]
then
cat /etc/shadow | awk -F: -v epoch="$epoch" '($3 > epoch ) { print $1 " has a future date password change: " $3 " : today epoch is "epoch }' >user
while IFS= read -r line
do
	echo "Password Requirements" >>p1
	echo "last password change date in /etc/shadow" >>p2
	echo "$line" >>p3
	echo "no" >>p4
	echo "IZ.1.1.1.3" >>p12
	echo "$c" >> p5
	echo "$z" >>p6
done <user
else
	echo "Password Requirements" >>p1
	echo "last password change date in /etc/shadow" >>p2
	echo "No user has last password change date in future" >>p3
	echo "yes" >>p4
	echo "IZ.1.1.1.3" >>p12
	echo "$c" >> p5
	echo "$z" >>p6
fi
rm -rf user


#################################################################################################

######### SSH HC Script ####################

#################################################################################################
#AV.1.7.6
sk=`sshd -T |grep -i HostbasedAuthentication |awk '{print $2}'`
if [ "$sk" == "no" ]
then
	echo "Identify and Authenticate Users" >>p1
	echo "HostbasedAuthentication" >>p2
	echo "HostbasedAuthentication is set as \"$sk\" in /etc/ssh/sshd_config" >>p3
	echo "yes" >>p4
	echo "$c" >>p5
	echo "$z" >>p6
	echo "AV.1.7.6" >>p12
else
	echo "Identify and Authenticate Users" >>p1
	echo "HostbasedAuthentication" >>p2
	echo "HostbasedAuthentication is set as \"$sk\" in /etc/ssh/sshd_config" >>p3
	echo "no" >>p4
	echo "$c" >>p5
	echo "$z" >>p6
	echo "AV.1.7.6" >>p12
fi

#AV.1.2.1.2.1
sk=`sshd -T |grep -i ^LogLevel |awk '{print $2}'`
if [ "$sk" == "INFO" ]
then
	echo "Logging" >>p1
	echo "Ensure SSH LogLevel is set to INFO" >>p2
	echo "LogLevel is set as \"$sk\" in /etc/ssh/sshd_config" >>p3
	echo "yes" >>p4
	echo "$c" >>p5
	echo "$z" >>p6
	echo "AV.1.2.1.2.1" >>p12
else
	echo "Logging" >>p1
	echo "Ensure SSH LogLevel is set to INFO" >>p2
	echo "LogLevel is set as \"$sk\" in /etc/ssh/sshd_config" >>p3
	echo "no" >>p4
	echo "$c" >>p5
	echo "$z" >>p6
	echo "AV.1.2.1.2.1" >>p12
fi


#AV.1.7.2.1
cat /etc/passwd | egrep -v "/sbin/nologin|sync|shutdown|halt|/bin/false"|awk -F":" '{print $6}' >temp_home
for i in `cat temp_home` ; do
	if [ -f $i/.ssh/authorized_keys ]
	then
		sk=`grep '!!' $i/.ssh/authorized_keys |wc -l`
		if [ $sk -gt 0 ] ; then
			echo "Identify and Authenticate Users" >>p1
			echo "Public Key Authentication Key Label for Private Key Ownership Identification" >>p2
			echo "Public Key Authentication Key Label exists in $i/.ssh/authorized_keys" >> p3
			echo "Yes" >>p4
			echo "AV.1.7.2.1" >>p12
			echo "$c" >> p5
			echo "$z" >>p6
		else
			echo "Identify and Authenticate Users" >>p1
			echo "Public Key Authentication Key Label for Private Key Ownership Identification" >>p2
			echo "Public Key Authentication Key Label not exists in $i/.ssh/authorized_keys" >> p3
			echo "No" >>p4
			echo "AV.1.7.2.1" >>p12
			echo "$c" >> p5
			echo "$z" >>p6
		fi
	else
			echo "Identify and Authenticate Users" >>p1
			echo "Public Key Authentication Key Label for Private Key Ownership Identification" >>p2
			echo "authorized_keys file not exist in user home directory $i/.ssh/authorized_keys" >> p3
			echo "Yes" >>p4
			echo "AV.1.7.2.1" >>p12
			echo "$c" >> p5
			echo "$z" >>p6
	fi
done

#AV.1.2.1.3
sk=`sshd -T |grep -i ^LogLevel |awk '{print $2}'`
if [ "$sk" == "INFO" ] || [ "$sk" == "DEBUG" ] || [ "$sk" == "VERBOSE" ]
then
	echo "Logging" >>p1
       	echo "LogLevel" >>p2
	echo "LogLevel-set-as \"$sk\" in /etc/ssh/sshd_config" >> p3
	echo "yes" >>p4
       	echo "$c" >> p5
        echo "$z" >>p6
	echo "AV.1.2.1.3" >>p12
else
	echo "Logging" >>p1
       	echo "LogLevel" >>p2
	echo "LogLevel-should-be-set-as-DEBUG" >> p3
        echo "no" >>p4
        echo "$c" >> p5
        echo "$z" >>p6
	echo "AV.1.2.1.3" >>p12
fi

#AV.1.4.1
sz=`rpm -qa |grep -i ssh |grep -i openssh-[0-9].[0-9] | cut -c1,2,3,4,5,6,7,8,9,10,11`
szk=`echo $sz | awk -F"-" '{print $2}'`
BC=`which bc`
if (( $($BC <<< "$szk<=3.7") > 0 ))
then
	sk=`cat /etc/ssh/sshd_config | grep -i "^KeepAlive" | awk '{print $2}' |uniq |wc -l`
	if [ $sk -gt 0 ]
	then
	szl=`cat /etc/ssh/sshd_config | grep -i "^KeepAlive" | awk '{print $2}' |uniq`
	if [ "$szl" == "yes" ]
	then
		echo "SystemSettings" >>p1
		echo "KeepAlive" >>p3
		echo "KeepAlive_$szl" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.1" >>p12
	else
		echo "SystemSettings" >>p1
		echo "KeepAlive" >>p2
		echo "KeepAlive_$szl" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.1" >>p12
	fi
	else
		echo "SystemSettings" >>p1
		echo "KeepAlive" >>p2
		echo "KeepAlive value is set" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.1" >>p12
	fi
else
		echo "SystemSettings" >>p1
		echo "KeepAlive" >>p2
		echo "Applicable-only-for-openssh-versions-3.7-or-less" >>p3
		echo "Not_Applicable" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.1" >>p12
fi

#AV.1.9.1
sz=`rpm -qa |grep -i ssh |grep -i openssh-[0-9].[0-9] | cut -c1,2,3,4,5,6,7,8,9,10,11`
szk=`echo $sz | awk -F"-" '{print $2}'`
BC=`which bc`
if (( $($BC <<< "$szk>=3.5") > 0 ))
then
   sk=`cat /etc/ssh/sshd_config | grep -i "^PermitUserEnvironment" |uniq |wc -l`
   if [ $sk -gt 0 ]
   then
	szl=`cat /etc/ssh/sshd_config | grep -i "^PermitUserEnvironment" | awk '{print $2}' |uniq`
	if [ "$szl" == "$PERMITUSERENVIRONMENT" ]
	then
		echo "Protecting Resources - User Resources" >>p1
		echo "PermitUserEnvironment" >>p2
		echo "PermitUserEnvironment is set as \"$szl\" in /etc/ssh/sshd_config" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.9.1" >>p12
	else
		echo "Protecting Resources - User Resources" >>p1
		echo "PermitUserEnvironment" >>p2
		echo "PermitUserEnvironment is not set in /etc/ssh/sshd_config" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.9.1" >>p12
	fi

    else
	szl=`cat /etc/ssh/sshd_config | grep -i "^#PermitUserEnvironment" | awk '{print $2}' |uniq`
	if [ "$szl" == "$PERMITUSERENVIRONMENT" ]
	then
		echo "Protecting Resources - User Resources" >>p1
		echo "PermitUserEnvironment" >>p2
		echo "PermitUserEnvironment is set as \"$szl\" in /etc/ssh/sshd_config" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.9.1" >>p12
	else
		echo "Protecting Resources - User Resources" >>p1
		echo "PermitUserEnvironment" >>p2
		echo "PermitUserEnvironment is not set in /etc/ssh/sshd_config" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.9.1" >>p12
	fi
    fi
else
		echo "Protecting Resources - User Resources" >>p1
		echo "PermitUserEnvironment" >>p2
		echo "Applicable-only-for-openssh-version-3.5-and-higher" >>p3
		echo "Not_Applicable" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.9.1" >>p12
fi


#AV.1.9.3
sz=`rpm -qa |grep -i ssh |grep -i openssh-[0-9].[0-9] | cut -c1,2,3,4,5,6,7,8,9,10,11`
szk=`echo $sz | awk -F"-" '{print $2}'`
if (( $(bc <<< "$szk>=3.9") > 0 ))
then
	szl=`cat /etc/ssh/sshd_config | grep -i "^AcceptEnv" | egrep 'TERM|PATH|HOME| MAIL| SHELL| LOGNAME| USER| USERNAME| _RLD*| DYLD_*| LD_*| LDR_*| LIBPATH| SHLIB_PATH'`
	if [ $? -eq 0 ]
	then
		echo "Protecting Resources - User Resources" >>p1
		echo "User Environment variables are not correctly set" >>p3
		echo "AcceptEnv" >>p2
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.9.3" >>p12
	else
		echo "Protecting Resources - User Resources" >>p1
		echo "User Environment variables are correctly set" >>p3
		echo "AcceptEnv" >>p2
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.9.3" >>p12
	fi
else
		echo "Protecting Resources - User Resources" >>p1
		echo "AcceptEnv" >>p2
		echo "Applicable-only-for-openssh-version-3.9-and-higher" >>p3
		echo "Not_Applicable" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.9.3" >>p12
fi

#AV.1.4.2
sz=`rpm -qa |grep -i ssh |grep -i openssh-[0-9].[0-9] | cut -c1,2,3,4,5,6,7,8,9,10,11`
szk=`echo $sz | awk -F"-" '{print $2}'`
BC=`which bc`
if (( $($BC <<< "$szk>=3.8") > 0 ))
then
   sk=`cat /etc/ssh/sshd_config | grep -i "^TCPKeepAlive" |uniq |wc -l`
   if [ $sk -gt 0 ]
   then
	szl=`cat /etc/ssh/sshd_config | grep -i "^TCPKeepAlive" | awk '{print $2}' |uniq`
	if [ "$szl" == "$TCPKEEPALIVE" ]
	then
		echo "System Settings" >>p1
		echo "TCPKeepAlive" >>p2
		echo "Value is set as \"$szl\" in /etc/ssh/sshd_config" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.2" >>p12
	else
		echo "System Settings" >>p1
		echo "TCPKeepAlive" >>p2
		echo "TCPKeepAlive Value-is-not-set in /etc/ssh/sshd_config" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.2" >>p12
	fi
   else
	szl=`cat /etc/ssh/sshd_config | grep -i "^#TCPKeepAlive" | awk '{print $2}' |uniq`
	if [ "$szl" == "$TCPKEEPALIVE" ]
	then
		echo "System Settings" >>p1
		echo "TCPKeepAlive" >>p2
		echo "Value is set as \"$szl\" in /etc/ssh/sshd_config" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.2" >>p12
	else
		echo "System Settings" >>p1
		echo "TCPKeepAlive" >>p2
		echo "TCPKeepAlive Value-is-not-set in /etc/ssh/sshd_config" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.2" >>p12
	fi
    fi
else
		echo "SystemSettings" >>p1
		echo "TCPKeepAlive" >>p2
		echo "Applicable-only-for-openssh-versions-3.8-and-greater" >>p3
		echo "Not_Applicable" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.2" >>p12
fi


#AV.1.4.4
sz=`rpm -qa |grep -i ssh |grep -i openssh-[0-9].[0-9] | cut -c1,2,3,4,5,6,7`
if [ "$sz" != "openssh" ]
then
	sk=`cat /etc/ssh/sshd_config | grep -i "^MaxConnections" |uniq |wc -l`
	if [ $sk -gt 0 ]
	then
	szl=`cat /etc/ssh/sshd_config | grep -i "^MaxConnections" | awk '{print $2}' |uniq | awk 'FNR  == 1'`
	if [ "$szl" <= "100" ]
	then
		echo "System Settings" >>p1
		echo "MaxConnections" >>p2
		echo "$szl" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.4" >>p12
	else
		echo "System Settings" >>p1
		echo "MaxConnections" >>p2
		echo "Value-is-not-set" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.4" >>p12
	fi
	else
		echo "System Settings" >>p1
		echo "MaxConnections" >>p2
		echo "Value-is-set" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.4" >>p12
	fi
else
		echo "System Settings" >>p1
		echo "MaxConnections" >>p2
		echo "Not Applicable-for-OpenSSH" >>p3
		echo "Not_Applicable" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.4" >>p12
fi


#AV.1.4.5
sk=`cat /etc/ssh/sshd_config | grep -i "^MaxStartups" |uniq |wc -l`
if [ $sk -gt 0 ]
then
	szl=`cat /etc/ssh/sshd_config | grep -i "^MaxStartups" | awk '{print $2}' |uniq`
	if [ $szl  -le "$MAXSTARTUPS" ] || [ "$szl" == "10:30:100" ]
	then
		echo "System Settings" >>p1
		echo "MaxStartups" >>p2
		echo "Value is set as \"$szl\" in /etc/ssh/sshd_config" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.5" >>p12
	else
		echo "System Settings" >>p1
		echo "MaxStartups" >>p2
		echo "Value-is-not-set in /etc/ssh/sshd_config" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.5" >>p12
	fi
else
	szl=`cat /etc/ssh/sshd_config | grep -i "^#MaxStartups" | awk '{print $2}' |uniq`
	if [ "$szl"  -le "$MAXSTARTUPS" ] || [ "$szl" == "10:30:100" ]
	then
		echo "System Settings" >>p1
		echo "MaxStartups" >>p2
		echo "Value is set as \"$szl\" in /etc/ssh/sshd_config" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.5" >>p12
	else
		echo "System Settings" >>p1
		echo "MaxStartups" >>p2
		echo "Value-is-not-set in /etc/ssh/sshd_config" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.5" >>p12
	fi
fi

#AV.1.4.8
sz=`rpm -qa |grep -i ssh |grep -i openssh-[0-9].[0-9] | cut -c1,2,3,4,5,6,7,8,9,10,11`
szk=`echo $sz | awk -F"-" '{print $2}'`
BC=`which bc`
if (( $($BC <<< "$szk>3.9") > 0 ))
then
  sk=`cat /etc/ssh/sshd_config | grep -i "^MaxAuthTries" |uniq |wc -l`
  if [ $sk -gt 0 ]
  then
	szl=`cat /etc/ssh/sshd_config | grep -i "^MaxAuthTries" | awk '{print $2}' |uniq`
	if [ $szl -le $MAXAUTHTRIES ]
	then
		echo "System Settings" >>p1
		echo "MaxAuthTries" >>p2
		echo "Value is set as \"$szl\" in /etc/ssh/sshd_config" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.8" >>p12
	else
		echo "System Settings" >>p1
		echo "MaxAuthTries" >>p2
		echo "Value-is-not-set in /etc/ssh/sshd_config" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.8" >>p12
	fi
  else
	szl=`cat /etc/ssh/sshd_config | grep -i "^#MaxAuthTries" | awk '{print $2}' |uniq`
	if [ $szl -le $MAXAUTHTRIES ]
	then
		echo "System Settings" >>p1
		echo "MaxAuthTries" >>p2
		echo "Value is set as \"$szl\" in /etc/ssh/sshd_config" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.8" >>p12
	else
		echo "System Settings" >>p1
		echo "MaxAuthTries" >>p2
		echo "Value-is-not-set in /etc/ssh/sshd_config" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.8" >>p12
	fi
  fi
else
		echo "System Settings" >>p1
		echo "MaxAuthTries" >>p2
		echo "Applicable-for-only-openssh3.9-and-greater" >>p3
		echo "Not_Applicable" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.8" >>p12
fi

#AV.1.4.14

sz=`rpm -qa |grep -i ssh |grep -i openssh-[0-9].[0-9] | cut -c1,2,3,4,5,6,7`
if [ "$sz" != "openssh" ]
then
	szl=`cat /etc/ssh/sshd_config | grep -i "^AuthKbdInt.Retries" | awk '{print $2}' |uniq`
	if [ "$szl" <= "5" ]
	then
		echo "System Settings" >>p1
		echo "AuthKbdInt.Retries" >>p2
		echo "Value is set as \"$szl\" in /etc/ssh/sshd_config" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.14" >>p12
	else
		echo "System Settings" >>p1
		echo "AuthKbdInt.Retries" >>p2
		echo "Value-is-not-set" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.14" >>p12
	fi
else
		echo "System Settings" >>p1
		echo "AuthKbdInt.Retries" >>p2
		echo "Not Applicable for OpenSSH" >>p3
		echo "Not_Applicable" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.14" >>p12
fi


#AV.1.4.3
sk=`cat /etc/ssh/sshd_config | grep -i "^LoginGraceTime" |uniq |wc -l`
if [ $sk -gt 0 ]
then
	szl=`cat /etc/ssh/sshd_config | grep -i "^LoginGraceTime" | awk '{print $2}' |uniq`
	if [ "$szl" -le "$LOGINGRACETIME" ] || [ "$szl" == "2m" ]
	then
		echo "System Settings" >>p1
		echo "LoginGraceTime" >>p2
		echo "Value is set as \"$szl\" in /etc/ssh/sshd_config" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.3" >>p12
	else
		echo "System Settings" >>p1
		echo "LoginGraceTime" >>p2
		echo "Value-is-not-set in /etc/ssh/sshd_config" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.3" >>p12
	fi
else
	szl=`cat /etc/ssh/sshd_config | grep -i "^#LoginGraceTime" | awk '{print $2}' |uniq`
	if [ "$szl" -le "$LOGINGRACETIME" ] || [ "$szl" == 2m ]
	then
		echo "System Settings" >>p1
		echo "LoginGraceTime" >>p2
		echo "Value is set as \"$szl\" in /etc/ssh/sshd_config" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.3" >>p12
	else
		echo "System Settings" >>p1
		echo "LoginGraceTime" >>p2
		echo "Value-is-not-set in /etc/ssh/sshd_config" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.3" >>p12
	fi
fi

#AV.1.5.1
sk=`cat /etc/ssh/sshd_config | grep -i "^KeyRegenerationInterval" |uniq |wc -l`
if [ $sk -gt 0 ]
then
	szl=`cat /etc/ssh/sshd_config | grep -i "^KeyRegenerationInterval" | awk '{print $2}' |uniq`
	if [ "$szl" -le "$KEYREGENERATIONINTERVAL" ] || [ "$szl" == "1h" ]
	then
		echo "System Settings" >>p1
		echo "KeyRegenerationInterval" >>p2
		echo "Value is set as \"$szl\" in /etc/ssh/sshd_config" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.5.1" >>p12
	else
		echo "System Settings" >>p1
		echo "KeyRegenerationInterval" >>p2
		echo "Value-is-not-set in /etc/ssh/sshd_config" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.5.1" >>p12
	fi
else
	szl=`cat /etc/ssh/sshd_config | grep -i "^#KeyRegenerationInterval" | awk '{print $2}' |uniq`
	if [ "$szl" -le "$KEYREGENERATIONINTERVAL" ] || [ "$szl" == "1h" ]
	then
		echo "System Settings" >>p1
		echo "KeyRegenerationInterval" >>p2
		echo "Value is set as \"$szl\" in /etc/ssh/sshd_config" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.5.1" >>p12
	else
		echo "System Settings" >>p1
		echo "KeyRegenerationInterval" >>p2
		echo "Value-is-not-set in /etc/ssh/sshd_config" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.5.1" >>p12
	fi
fi

#AV.1.5.2
sk=`cat /etc/ssh/sshd_config | grep -i "^protocol" |uniq |wc -l`
if [ $sk -gt 0 ]
then
	sz=`grep -i ^protocol /etc/ssh/sshd_config | awk 'FNR == 1 {print $2}'` 
	if [ "$sz" == "2" ] || [ "$sz" == "1,2" ] || [ "$sz" == "2,1" ] 
	then
		echo "Network Settingss" >>p1
		echo "SSH-protocol" >>p2
		echo "Value is set as $sz in /etc/ssh/sshd_config" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.5.2" >>p12
	else
		echo "Network Settingss" >>p1
		echo "SSH-protocol" >>p2
		echo "value-should-be-2(or)1,2(or)2,1 in /etc/ssh/sshd_config" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.5.2" >>p12
	fi
else
	sz=`grep -i ^#protocol /etc/ssh/sshd_config | awk 'FNR == 1 {print $2}'` 
	if [ "$sz" == "2" ] || [ "$sz" == "1,2" ] || [ "$sz" == "2,1" ] 
	then
		echo "Network Settingss" >>p1
		echo "SSH-protocol" >>p2
		echo "Value is set as $sz in /etc/ssh/sshd_config" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.5.2" >>p12
	else
		echo "Network Settingss" >>p1
		echo "SSH-protocol" >>p2
		echo "Protocol is not set in /etc/ssh/sshd_config" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.5.2" >>p12
	fi
fi


#AV.2.1.1.1
sk=`cat /etc/ssh/sshd_config | grep -i "^Protocol" |uniq |wc -l`
if [ $sk -gt 0 ]
then
  sz=`grep -i ^Protocol /etc/ssh/sshd_config | awk 'FNR == 1 {print $2}'` 
  if [ "$sz" == "1" ] || [ "$sz" == "1,2" ] || [ "$sz" == "2,1" ] 
  then
	szl=`cat /etc/ssh/sshd_config | grep -i "^ServerKeyBits" | awk '{print $2}'`
	if [ $szl -ge 1024 ]
	then	
		echo "Encryption" >>p1
		echo "Data Transmission" >>p2
		echo "ServerKeyBits-value-is set as \"$szl\" in /etc/ssh/sshd_config" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.2.1.1.1" >>p12
	else
		echo "Encryption" >>p1
		echo "Data Transmission" >>p2
		echo "ServerKeyBits value must be greater than or equal to 1024" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.2.1.1.1" >>p12
	fi
  else

		echo "Encryption" >>p1
		echo "Data Transmission" >>p2
		echo "Not applicable as the SSH protocol version 1 is not enabled" >>p3
		echo "Not_Applicable" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.2.1.1.1" >>p12
  fi		
else
  sz=`grep -i ^#protocol /etc/ssh/sshd_config | awk 'FNR == 1 {print $2}'` 
  if [ "$sz" == "1" ] || [ "$sz" == "1,2" ] || [ "$sz" == "2,1" ] 
  then
	szl=`cat /etc/ssh/sshd_config | grep -i "^ServerKeyBits" | awk '{print $2}'`
	if [ $szl -ge 1024 ]
	then	
		echo "Encryption" >>p1
		echo "Data Transmission" >>p2
		echo "ServerKeyBits-value-is set as \"$szl\" in /etc/ssh/sshd_config" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.2.1.1.1" >>p12
	else
		echo "Encryption" >>p1
		echo "Data Transmission" >>p2
		echo "ServerKeyBits value must be greater than or equal to 1024" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.2.1.1.1" >>p12
	fi
  else

		echo "Encryption" >>p1
		echo "Data Transmission" >>p2
		echo "Not applicable as the SSH protocol version 1 is not enabled" >>p3
		echo "Not_Applicable" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.2.1.1.1" >>p12
  fi		

fi

#AV.1.1.1
sk=`cat /etc/ssh/sshd_config | grep -i "^PermitEmptyPasswords" |uniq |wc -l`
if [ $sk -gt 0 ]
then
  sz=`cat /etc/ssh/sshd_config | grep -i "^PermitEmptyPasswords" | awk '{print $2}' |uniq`
  if [ "$sz" == "$PERMITEMPTYPASSWORDS" ]
  then
		echo "Password Requirementss" >>p1
        	echo "PermitEmptyPasswords" >>p2
		echo "PermitEmptyPasswords is set as \"$sz\" in /etc/ssh/sshd_config" >> p3
		echo "yes" >>p4
         	echo "$c" >> p5
                echo "$z" >>p6
		echo "AV.1.1.1" >>p12
  else
		echo "Password Requirementss" >>p1
        	echo "PermitEmptyPasswords" >>p2
		echo "Value-is-not-set" >> p3
                echo "no" >>p4
                echo "$c" >> p5
                echo "$z" >>p6
		echo "AV.1.1.1" >>p12
  fi
else
  sz=`cat /etc/ssh/sshd_config | grep -i "^#PermitEmptyPasswords" | awk '{print $2}' |uniq`
  if [ "$sz" == "$PERMITEMPTYPASSWORDS" ]
  then
		echo "Password Requirementss" >>p1
        	echo "PermitEmptyPasswords" >>p2
		echo "PermitEmptyPasswords is set as \"$sz\" in /etc/ssh/sshd_config" >> p3
		echo "yes" >>p4
         	echo "$c" >> p5
                echo "$z" >>p6
		echo "AV.1.1.1" >>p12
  else
		echo "Password Requirementss" >>p1
        	echo "PermitEmptyPasswords" >>p2
		echo "Value-is-not-set" >> p3
                echo "no" >>p4
                echo "$c" >> p5
                echo "$z" >>p6
		echo "AV.1.1.1" >>p12
  fi
fi

#AV.1.7.1.1
sz=`cat /etc/ssh/sshd_config | grep -i "^PermitRootLogin" | awk '{print $2}' |uniq`
if [ "$sz" == "$PERMITROOTLOGIN" ]
then
		echo "IdentifyandAuthenticateUsers" >>p1
        	echo "PermitRootLogin" >>p2
		echo "PermitRootLogin is set as \"$sz\" in /etc/ssh/sshd_config" >> p3
		echo "yes" >>p4
         	echo "$c" >> p5
                echo "$z" >>p6
		echo "AV.1.7.1.1" >>p12
else
		echo "Password Requirementss" >>p1
        	echo "PermitRootLogin" >>p2
		echo "PermitRootLogin is incorrectly set as \"$sz\" in /etc/ssh/sshd_config" >> p3
                echo "no" >>p4
                echo "$c" >> p5
                echo "$z" >>p6
		echo "AV.1.7.1.1" >>p12
fi

#AV.1.2.1.2,AV.1.2.1.3
sk=`cat /etc/ssh/sshd_config | grep -i "^LogLevel" |uniq |wc -l`
if [ $sk -gt 0 ]
then
  sk=`cat /etc/ssh/sshd_config | grep -i "^LogLevel" | awk '{print $2}' |uniq`
  if [ "$sk" == "INFO" ] || [ "$sk" == "DEBUG" ]
  then
		echo "Logging" >>p1
        	echo "LogLevel" >>p2
		echo "LogLevel-set-as \"$sk\" in /etc/ssh/sshd_config" >> p3
		echo "yes" >>p4
         	echo "$c" >> p5
                echo "$z" >>p6
		echo "AV.1.2.1.2;AV.1.2.1.3" >>p12
  else
		echo "Logging" >>p1
        	echo "LogLevel" >>p2
		echo "LogLevel-should-be-set-as-INFO or DEBUG" >> p3
                echo "no" >>p4
                echo "$c" >> p5
                echo "$z" >>p6
		echo "AV.1.2.1.2;AV.1.2.1.3" >>p12
  fi
else
  sk=`cat /etc/ssh/sshd_config | grep -i "^#LogLevel" | awk '{print $2}' |uniq`
  if [ "$sk" == "INFO" ] || [ "$sk" == "DEBUG" ]
  then
		echo "Logging" >>p1
        	echo "LogLevel" >>p2
		echo "LogLevel-set-as \"$sk\" in /etc/ssh/sshd_config" >> p3
		echo "yes" >>p4
         	echo "$c" >> p5
                echo "$z" >>p6
		echo "AV.1.2.1.2;AV.1.2.1.3" >>p12
  else
		echo "Logging" >>p1
        	echo "LogLevel" >>p2
		echo "LogLevel-should-be-set-as-INFO or DEBUG" >> p3
                echo "no" >>p4
                echo "$c" >> p5
                echo "$z" >>p6
		echo "AV.1.2.1.2;AV.1.2.1.3" >>p12
  fi
fi

#AV.1.5.5
sk=`cat /etc/ssh/sshd_config | grep -i "^GatewayPorts" |uniq |wc -l`
if [ $sk -gt 0 ]
then
	sz=`cat /etc/ssh/sshd_config | grep -i "^GatewayPorts" | awk '{print $2}' |uniq`
	if [ "$sz" == "$GATEWAYPORTS" ]
	then
			echo "Network Settingss" >>p1
			echo "GatewayPorts" >>p2
			echo "GatewayPorts is set as \"$sz\" in /etc/ssh/sshd_config" >>p3
			echo "yes" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "AV.1.5.5" >>p12
	else
			echo "Network Settingss" >>p1
			echo "GatewayPorts" >>p2
			echo "Value-is-not-set in /etc/ssh/sshd_config" >>p3
			echo "no" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "AV.1.5.5" >>p12
	fi
else
	sz=`cat /etc/ssh/sshd_config | grep -i "^#GatewayPorts" | awk '{print $2}' |uniq`
	if [ "$sz" == "$GATEWAYPORTS" ]
	then
			echo "Network Settingss" >>p1
			echo "GatewayPorts" >>p2
			echo "GatewayPorts is set as \"$sz\" in /etc/ssh/sshd_config" >>p3
			echo "yes" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "AV.1.5.5" >>p12
	else
			echo "Network Settingss" >>p1
			echo "GatewayPorts" >>p2
			echo "Value-is-not-set in /etc/ssh/sshd_config" >>p3
			echo "no" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "AV.1.5.5" >>p12
	fi
fi


#AV.1.7.3.2
if [ -f /etc/hosts.equiv ]
then
	sk=`cat /etc/hosts.equiv |wc -l`
	if [ $sk -gt 0 ]
	then
		echo "IdentifyandAuthenticateUsers" >>p1
        	echo "Host-Based Authentication" >>p2
		echo "File /etc/hosts.equiv-exist and entries found. Please check the entry  in file and remediate it as per techspec" >> p3
		echo "no" >>p4
         	echo "$c" >> p5
                echo "$z" >>p6
		echo "AV.1.7.3.2" >>p12
	else
		echo "IdentifyandAuthenticateUsers" >>p1
        	echo "Host-Based Authentication" >>p2
		echo "File /etc/hosts.equiv-exist and but no entry found" >> p3
		echo "yes" >>p4
         	echo "$c" >> p5
                echo "$z" >>p6
		echo "AV.1.7.3.2" >>p12
	fi
else
		echo "IdentifyandAuthenticateUsers" >>p1
        	echo "Host-Based Authentication" >>p2
		echo "File /etc/hosts.equiv not exist" >> p3
		echo "yes" >>p4
         	echo "$c" >> p5
                echo "$z" >>p6
		echo "AV.1.7.3.2" >>p12
fi

#AV.1.7.3.3
if [ -f /etc/hosts.equiv ]
then
	if [ -f /etc/shosts.equiv ]
	then
		echo "IdentifyandAuthenticateUsers" >>p1
        	echo "Host-Based Authentication" >>p2
		echo "File /etc/shosts.equiv-exist" >> p3
		echo "yes" >>p4
         	echo "$c" >> p5
                echo "$z" >>p6
		echo "AV.1.7.3.3" >>p12
	else
		echo "IdentifyandAuthenticateUsers" >>p1
        	echo "Host-Based Authentication" >>p2
		echo "File /etc/shosts.equiv must exist as file /etc/hosts.equiv is in use" >> p3
		echo "no" >>p4
         	echo "$c" >> p5
                echo "$z" >>p6
		echo "AV.1.7.3.3" >>p12
	fi
else
		echo "IdentifyandAuthenticateUsers" >>p1
        	echo "Host-Based Authentication" >>p2
		echo "Host based authentication is disabled" >> p3
		echo "yes" >>p4
         	echo "$c" >> p5
                echo "$z" >>p6
		echo "AV.1.7.3.3" >>p12
fi

#AV.1.9.2
sk=`cat /etc/ssh/sshd_config | grep -i "^StrictModes" |uniq |wc -l`
if [ $sk -gt 0 ]
then
	szk=`cat /etc/ssh/sshd_config | grep "^StrictModes" | awk '{print $2}' |uniq`
	if [ "$szk" == "$STRICTMODES" ]
	then
		echo "IdentifyandAuthenticateUsers" >>p1
		echo "StrictModes" >>p2
		echo "StrictModes is set as \"$szk\" in /etc/ssh/sshd_config" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AV.1.9.2" >>p12
	else
		echo "IdentifyandAuthenticateUsers" >>p1
		echo "StrictModes" >>p2
		echo "Value-is-not-set in /etc/ssh/sshd_config" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AV.1.9.2" >>p12
	fi
else
	szk=`cat /etc/ssh/sshd_config | grep "^#StrictModes" | awk '{print $2}' |uniq`
	if [ "$szk" == "$STRICTMODES" ]
	then
		echo "IdentifyandAuthenticateUsers" >>p1
		echo "StrictModes" >>p2
		echo "StrictModes is set as \"$szk\" in /etc/ssh/sshd_config" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AV.1.9.2" >>p12
	else
		echo "IdentifyandAuthenticateUsers" >>p1
		echo "StrictModes" >>p2
		echo "Value-is-not-set in /etc/ssh/sshd_config" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AV.1.9.2" >>p12
	fi
fi

#AV.2.0.1.1
sk=`cat /etc/ssh/sshd_config | grep -i "^PrintMotd" |uniq |wc -l`
if [ $sk -gt 0 ]
then
	szk=`cat /etc/ssh/sshd_config | grep "^PrintMotd" | awk '{print $2}' |uniq`
	if [ "$szk" == "$PRINTMOTD" ]
	then
		echo "Business Use Notice " >>p1
		echo "PrintMotd" >>p2
		echo "PrintMotd is set as \"$szk\" in /etc/ssh/sshd_config" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AV.2.0.1.1" >>p12
	else
		echo "Business Use Notice " >>p1
		echo "PrintMotd" >>p2
		echo "Value-is-not-set in /etc/ssh/sshd_config" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AV.2.0.1.1" >>p12
	fi
else
	szk=`cat /etc/ssh/sshd_config | grep "^#PrintMotd" | awk '{print $2}' |uniq`
	if [ "$szk" == "$PRINTMOTD" ]
	then
		echo "Business Use Notice " >>p1
		echo "PrintMotd" >>p2
		echo "PrintMotd is set as No requirement  in /etc/ssh/sshd_config" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AV.2.0.1.1" >>p12
	else
		echo "Business Use Notice " >>p1
		echo "PrintMotd" >>p2
		echo "Value-is-not-set in /etc/ssh/sshd_config" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AV.2.0.1.1" >>p12
	fi
fi

#AV.1.8.2.1,AV.1.8.2.2,AV.1.8.2.3,AV.1.8.6.1,AV.1.8.2.4,AV.1.8.2.5,AV.1.8.2.6,AV.1.8.2.7,AV.1.8.2.8,AV.1.8.2.9,AV.1.8.2.10,AV.1.8.2.11,AV.1.8.2.12,AV.1.8.2.13,AV.1.8.2.14,AV.1.8.2.15,AV.1.8.2.16,AV.1.8.2.17,AV.1.8.2.18,AV.1.8.2.19,AV.1.8.2.20,AV.1.8.2.21,AV.1.8.2.22,AV.1.8.2.23,AV.1.8.2.24,AV.1.8.2.25,AV.1.8.2.26,AV.1.8.2.27,AV.1.8.2.28,AV.1.8.2.29,AV.1.8.2.30,AV.1.8.2.31,AV.1.8.2.32,AV.1.8.2.33,AV.1.8.2.34,AV.1.8.2.35,AV.1.8.2.36,AV.1.8.2.37,AV.1.8.2.38,AV.1.8.2.39,AV.1.8.2.40,AV.1.8.2.41,AV.1.8.2.42,AV.1.8.2.43,AV.1.8.2.44,AV.1.8.2.45,AV.1.8.2.46,AV.1.8.2.47,AV.1.8.2.49,AV.1.8.2.50,AV.1.8.3.1,AV.1.8.3.2,AV.1.8.3.3,AV.1.8.3.4,AV.1.8.3.5,AV.1.8.3.6,AV.1.8.3.7,AV.1.8.3.8,AV.1.8.3.9,AV.1.8.3.10

echo "/usr/bin/openssl,/usr/bin/scp,/usr/bin/scp2,/usr/bin/sftp,/usr/bin/sftp2,/usr/bin/sftp-server,/usr/bin/sftp-server2,/usr/bin/slogin,/usr/bin/ssh,/usr/bin/ssh2,/usr/bin/ssh-add,/usr/bin/ssh-add2,/usr/bin/ssh-agent,/usr/bin/ssh-agent2,/usr/bin/ssh-askpass,/usr/bin/ssh-askpass2,/usr/bin/ssh-certenroll2,/usr/bin/ssh-chrootmgr,/usr/bin/ssh-dummy-shell,/usr/bin/ssh-keygen,/usr/bin/ssh-keygen2,/usr/bin/ssh-keyscan,/usr/bin/ssh-pam-client,/usr/bin/ssh-probe,/usr/bin/ssh-probe2,/usr/bin/ssh-pubkeymgr,/usr/bin/ssh-signer,/usr/bin/ssh-signer2,/lib/libcrypto.a,/lib/libssh.a,/lib/libssl.a,/lib/libz.a,/lib-exec/openssh/sftp-server,/lib-exec/openssh/ssh-keysign,/lib-exec/openssh/ssh-askpass,/lib-exec/sftp-server,/lib-exec/ssh-keysign,/lib-exec/ssh-rand-helper,/libexec/openssh/sftp-server,/libexec/openssh/ssh-keysign,/libexec/openssh/ssh-askpass,/libexec/sftp-server,/libexec/ssh-keysign,/libexec/ssh-rand-helper,/usr/bin/sshd,/usr/bin/sshd2,/usr/bin/sshd-check-conf,/lib/svc/method/sshd,/usr/lib/ssh/sshd,/etc/openssh/sshd_config,/etc/ssh/sshd_config,/etc/ssh/sshd2_config,/etc/ssh2/sshd_config,/etc/ssh2/sshd2_config,/etc/sshd_config,/etc/sshd2_config,/usr/local/etc/sshd_config,/usr/local/etc/sshd2_config,/usr/lib/ssh/ssh-keysign" > temp
tr "," "\n" < temp > temp1
for i in `cat temp1`
do
	if [ -f $i ]
        then
	sz=`cat /etc/redhat-release |awk '{print $7}'`
	RELEASE=`cat /etc/redhat-release |awk '{print $1}'`
	if [ "$RELEASE" == "Red" ]
	then
	sj=`ls -ld $i |awk '{print $3}'`
	sk=`ls -ld $i |awk '{print $4}'`
	sl=`id -u $sj`
	sm=`getent group $sk |awk -F: '{print $3}'`
		if [ $sl -le 99 ] || [[ $sl -ge 101 && $sl -le 499 ]]
		then
			echo "Protecting Resources - OSRs" >>p1
			echo "OSR Executable and Libraries" >>p2
			echo "The file $i is owned by $sj - Permission is Valid" >>p3
			echo "yes" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "AV.1.8.2.1,AV.1.8.2.2,AV.1.8.2.3,AV.1.8.6.1,AV.1.8.2.4,AV.1.8.2.5,AV.1.8.2.6,AV.1.8.2.7,AV.1.8.2.8,AV.1.8.2.9,AV.1.8.2.10,AV.1.8.2.11,AV.1.8.2.12,AV.1.8.2.13,AV.1.8.2.14,AV.1.8.2.15,AV.1.8.2.16,AV.1.8.2.17,AV.1.8.2.18,AV.1.8.2.19,AV.1.8.2.20,AV.1.8.2.21,AV.1.8.2.22,AV.1.8.2.23,AV.1.8.2.24,AV.1.8.2.25,AV.1.8.2.26,AV.1.8.2.27,AV.1.8.2.28,AV.1.8.2.29,AV.1.8.2.30,AV.1.8.2.31,AV.1.8.2.32,AV.1.8.2.33,AV.1.8.2.34,AV.1.8.2.35,AV.1.8.2.36,AV.1.8.2.37,AV.1.8.2.38,AV.1.8.2.39,AV.1.8.2.40,AV.1.8.2.41,AV.1.8.2.42,AV.1.8.2.43,AV.1.8.2.44,AV.1.8.2.45,AV.1.8.2.46,AV.1.8.2.47,AV.1.8.2.49,AV.1.8.2.50,AV.1.8.3.1,AV.1.8.3.2,AV.1.8.3.3,AV.1.8.3.4,AV.1.8.3.5,AV.1.8.3.6,AV.1.8.3.7,AV.1.8.3.8,AV.1.8.3.9,AV.1.8.3.10" >>p12
		else
			echo "Protecting Resources - OSRs" >>p1
			echo "OSR Executable and Libraries" >>p2
			echo "The file $i is owned by $sj - Permission is invalid" >>p3
			echo "no" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "AV.1.8.2.1,AV.1.8.2.2,AV.1.8.2.3,AV.1.8.6.1,AV.1.8.2.4,AV.1.8.2.5,AV.1.8.2.6,AV.1.8.2.7,AV.1.8.2.8,AV.1.8.2.9,AV.1.8.2.10,AV.1.8.2.11,AV.1.8.2.12,AV.1.8.2.13,AV.1.8.2.14,AV.1.8.2.15,AV.1.8.2.16,AV.1.8.2.17,AV.1.8.2.18,AV.1.8.2.19,AV.1.8.2.20,AV.1.8.2.21,AV.1.8.2.22,AV.1.8.2.23,AV.1.8.2.24,AV.1.8.2.25,AV.1.8.2.26,AV.1.8.2.27,AV.1.8.2.28,AV.1.8.2.29,AV.1.8.2.30,AV.1.8.2.31,AV.1.8.2.32,AV.1.8.2.33,AV.1.8.2.34,AV.1.8.2.35,AV.1.8.2.36,AV.1.8.2.37,AV.1.8.2.38,AV.1.8.2.39,AV.1.8.2.40,AV.1.8.2.41,AV.1.8.2.42,AV.1.8.2.43,AV.1.8.2.44,AV.1.8.2.45,AV.1.8.2.46,AV.1.8.2.47,AV.1.8.2.49,AV.1.8.2.50,AV.1.8.3.1,AV.1.8.3.2,AV.1.8.3.3,AV.1.8.3.4,AV.1.8.3.5,AV.1.8.3.6,AV.1.8.3.7,AV.1.8.3.8,AV.1.8.3.9,AV.1.8.3.10" >>p12
		fi
		if [ $sm -le 99 ] || [[ $sm -ge 101 && $sm -le 999 ]]
		then
			echo "Protecting Resources - OSRs" >>p1
			echo "OSR Executable and Libraries" >>p2
			echo "Group owner of file $i is $sk - Permission is Valid" >>p3
			echo "yes" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "AV.1.8.2.1,AV.1.8.2.2,AV.1.8.2.3,AV.1.8.6.1,AV.1.8.2.4,AV.1.8.2.5,AV.1.8.2.6,AV.1.8.2.7,AV.1.8.2.8,AV.1.8.2.9,AV.1.8.2.10,AV.1.8.2.11,AV.1.8.2.12,AV.1.8.2.13,AV.1.8.2.14,AV.1.8.2.15,AV.1.8.2.16,AV.1.8.2.17,AV.1.8.2.18,AV.1.8.2.19,AV.1.8.2.20,AV.1.8.2.21,AV.1.8.2.22,AV.1.8.2.23,AV.1.8.2.24,AV.1.8.2.25,AV.1.8.2.26,AV.1.8.2.27,AV.1.8.2.28,AV.1.8.2.29,AV.1.8.2.30,AV.1.8.2.31,AV.1.8.2.32,AV.1.8.2.33,AV.1.8.2.34,AV.1.8.2.35,AV.1.8.2.36,AV.1.8.2.37,AV.1.8.2.38,AV.1.8.2.39,AV.1.8.2.40,AV.1.8.2.41,AV.1.8.2.42,AV.1.8.2.43,AV.1.8.2.44,AV.1.8.2.45,AV.1.8.2.46,AV.1.8.2.47,AV.1.8.2.49,AV.1.8.2.50,AV.1.8.3.1,AV.1.8.3.2,AV.1.8.3.3,AV.1.8.3.4,AV.1.8.3.5,AV.1.8.3.6,AV.1.8.3.7,AV.1.8.3.8,AV.1.8.3.9,AV.1.8.3.10" >>p12
		else
			echo "Protecting Resources - OSRs" >>p1
			echo "OSR Executable and Libraries" >>p2
			echo "Group owner of file $i is $sk - Permission is invalid" >>p3
			echo "no" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "AV.1.8.2.1,AV.1.8.2.2,AV.1.8.2.3,AV.1.8.6.1,AV.1.8.2.4,AV.1.8.2.5,AV.1.8.2.6,AV.1.8.2.7,AV.1.8.2.8,AV.1.8.2.9,AV.1.8.2.10,AV.1.8.2.11,AV.1.8.2.12,AV.1.8.2.13,AV.1.8.2.14,AV.1.8.2.15,AV.1.8.2.16,AV.1.8.2.17,AV.1.8.2.18,AV.1.8.2.19,AV.1.8.2.20,AV.1.8.2.21,AV.1.8.2.22,AV.1.8.2.23,AV.1.8.2.24,AV.1.8.2.25,AV.1.8.2.26,AV.1.8.2.27,AV.1.8.2.28,AV.1.8.2.29,AV.1.8.2.30,AV.1.8.2.31,AV.1.8.2.32,AV.1.8.2.33,AV.1.8.2.34,AV.1.8.2.35,AV.1.8.2.36,AV.1.8.2.37,AV.1.8.2.38,AV.1.8.2.39,AV.1.8.2.40,AV.1.8.2.41,AV.1.8.2.42,AV.1.8.2.43,AV.1.8.2.44,AV.1.8.2.45,AV.1.8.2.46,AV.1.8.2.47,AV.1.8.2.49,AV.1.8.2.50,AV.1.8.3.1,AV.1.8.3.2,AV.1.8.3.3,AV.1.8.3.4,AV.1.8.3.5,AV.1.8.3.6,AV.1.8.3.7,AV.1.8.3.8,AV.1.8.3.9,AV.1.8.3.10" >>p12
		fi
	else
	sz=`cat /etc/redhat-release |awk '{print $7}'`
	RELEASE=`cat /etc/redhat-release |awk '{print $1}'`
	if [ "$RELEASE" == "Red" ] 
	then
	sj=`ls -ld $i |awk '{print $3}'`
	sk=`ls -ld $i |awk '{print $4}'`
	sl=`id -u $sj`
	sm=`getent group $sk |awk -F: '{print $3}'`
		if [ $sl -le 99 ] || [[ $sl -ge 101 && $sl -le 499 ]]
		then
			echo "Protecting Resources - OSRs" >>p1
			echo "OSR Executable and Libraries" >>p2
			echo "The file $i is owned by $sj - Permission is Valid" >>p3
			echo "yes" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "AV.1.8.2.1,AV.1.8.2.2,AV.1.8.2.3,AV.1.8.6.1,AV.1.8.2.4,AV.1.8.2.5,AV.1.8.2.6,AV.1.8.2.7,AV.1.8.2.8,AV.1.8.2.9,AV.1.8.2.10,AV.1.8.2.11,AV.1.8.2.12,AV.1.8.2.13,AV.1.8.2.14,AV.1.8.2.15,AV.1.8.2.16,AV.1.8.2.17,AV.1.8.2.18,AV.1.8.2.19,AV.1.8.2.20,AV.1.8.2.21,AV.1.8.2.22,AV.1.8.2.23,AV.1.8.2.24,AV.1.8.2.25,AV.1.8.2.26,AV.1.8.2.27,AV.1.8.2.28,AV.1.8.2.29,AV.1.8.2.30,AV.1.8.2.31,AV.1.8.2.32,AV.1.8.2.33,AV.1.8.2.34,AV.1.8.2.35,AV.1.8.2.36,AV.1.8.2.37,AV.1.8.2.38,AV.1.8.2.39,AV.1.8.2.40,AV.1.8.2.41,AV.1.8.2.42,AV.1.8.2.43,AV.1.8.2.44,AV.1.8.2.45,AV.1.8.2.46,AV.1.8.2.47,AV.1.8.2.49,AV.1.8.2.50,AV.1.8.3.1,AV.1.8.3.2,AV.1.8.3.3,AV.1.8.3.4,AV.1.8.3.5,AV.1.8.3.6,AV.1.8.3.7,AV.1.8.3.8,AV.1.8.3.9,AV.1.8.3.10" >>p12
		else
			echo "Protecting Resources - OSRs" >>p1
			echo "OSR Executable and Libraries" >>p2
			echo "The file $i is owned by $sj - Permission is invalid" >>p3
			echo "no" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "AV.1.8.2.1,AV.1.8.2.2,AV.1.8.2.3,AV.1.8.6.1,AV.1.8.2.4,AV.1.8.2.5,AV.1.8.2.6,AV.1.8.2.7,AV.1.8.2.8,AV.1.8.2.9,AV.1.8.2.10,AV.1.8.2.11,AV.1.8.2.12,AV.1.8.2.13,AV.1.8.2.14,AV.1.8.2.15,AV.1.8.2.16,AV.1.8.2.17,AV.1.8.2.18,AV.1.8.2.19,AV.1.8.2.20,AV.1.8.2.21,AV.1.8.2.22,AV.1.8.2.23,AV.1.8.2.24,AV.1.8.2.25,AV.1.8.2.26,AV.1.8.2.27,AV.1.8.2.28,AV.1.8.2.29,AV.1.8.2.30,AV.1.8.2.31,AV.1.8.2.32,AV.1.8.2.33,AV.1.8.2.34,AV.1.8.2.35,AV.1.8.2.36,AV.1.8.2.37,AV.1.8.2.38,AV.1.8.2.39,AV.1.8.2.40,AV.1.8.2.41,AV.1.8.2.42,AV.1.8.2.43,AV.1.8.2.44,AV.1.8.2.45,AV.1.8.2.46,AV.1.8.2.47,AV.1.8.2.49,AV.1.8.2.50,AV.1.8.3.1,AV.1.8.3.2,AV.1.8.3.3,AV.1.8.3.4,AV.1.8.3.5,AV.1.8.3.6,AV.1.8.3.7,AV.1.8.3.8,AV.1.8.3.9,AV.1.8.3.10" >>p12
		fi
		if [ $sm -le 99 ] || [[ $sm -ge 101 && $sm -le 499 ]]
		then
			echo "Protecting Resources - OSRs" >>p1
			echo "OSR Executable and Libraries" >>p2
			echo "Group owner of file $i is $sk - Permission is Valid" >>p3
			echo "yes" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "AV.1.8.2.1,AV.1.8.2.2,AV.1.8.2.3,AV.1.8.6.1,AV.1.8.2.4,AV.1.8.2.5,AV.1.8.2.6,AV.1.8.2.7,AV.1.8.2.8,AV.1.8.2.9,AV.1.8.2.10,AV.1.8.2.11,AV.1.8.2.12,AV.1.8.2.13,AV.1.8.2.14,AV.1.8.2.15,AV.1.8.2.16,AV.1.8.2.17,AV.1.8.2.18,AV.1.8.2.19,AV.1.8.2.20,AV.1.8.2.21,AV.1.8.2.22,AV.1.8.2.23,AV.1.8.2.24,AV.1.8.2.25,AV.1.8.2.26,AV.1.8.2.27,AV.1.8.2.28,AV.1.8.2.29,AV.1.8.2.30,AV.1.8.2.31,AV.1.8.2.32,AV.1.8.2.33,AV.1.8.2.34,AV.1.8.2.35,AV.1.8.2.36,AV.1.8.2.37,AV.1.8.2.38,AV.1.8.2.39,AV.1.8.2.40,AV.1.8.2.41,AV.1.8.2.42,AV.1.8.2.43,AV.1.8.2.44,AV.1.8.2.45,AV.1.8.2.46,AV.1.8.2.47,AV.1.8.2.49,AV.1.8.2.50,AV.1.8.3.1,AV.1.8.3.2,AV.1.8.3.3,AV.1.8.3.4,AV.1.8.3.5,AV.1.8.3.6,AV.1.8.3.7,AV.1.8.3.8,AV.1.8.3.9,AV.1.8.3.10" >>p12
		else
			echo "Protecting Resources - OSRs" >>p1
			echo "OSR Executable and Libraries" >>p2
			echo "Group owner of file $i is $sk - Permission is invalid" >>p3
			echo "no" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "AV.1.8.2.1,AV.1.8.2.2,AV.1.8.2.3,AV.1.8.6.1,AV.1.8.2.4,AV.1.8.2.5,AV.1.8.2.6,AV.1.8.2.7,AV.1.8.2.8,AV.1.8.2.9,AV.1.8.2.10,AV.1.8.2.11,AV.1.8.2.12,AV.1.8.2.13,AV.1.8.2.14,AV.1.8.2.15,AV.1.8.2.16,AV.1.8.2.17,AV.1.8.2.18,AV.1.8.2.19,AV.1.8.2.20,AV.1.8.2.21,AV.1.8.2.22,AV.1.8.2.23,AV.1.8.2.24,AV.1.8.2.25,AV.1.8.2.26,AV.1.8.2.27,AV.1.8.2.28,AV.1.8.2.29,AV.1.8.2.30,AV.1.8.2.31,AV.1.8.2.32,AV.1.8.2.33,AV.1.8.2.34,AV.1.8.2.35,AV.1.8.2.36,AV.1.8.2.37,AV.1.8.2.38,AV.1.8.2.39,AV.1.8.2.40,AV.1.8.2.41,AV.1.8.2.42,AV.1.8.2.43,AV.1.8.2.44,AV.1.8.2.45,AV.1.8.2.46,AV.1.8.2.47,AV.1.8.2.49,AV.1.8.2.50,AV.1.8.3.1,AV.1.8.3.2,AV.1.8.3.3,AV.1.8.3.4,AV.1.8.3.5,AV.1.8.3.6,AV.1.8.3.7,AV.1.8.3.8,AV.1.8.3.9,AV.1.8.3.10" >>p12
		fi
	else
			echo "Protecting Resources - OSRs" >>p1
			echo "OSR Executable and Libraries" >>p2
			echo "Not applicable as it is not for RHEL6 or RHEL7" >>p3
			echo "Not_Applicable" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "AV.1.8.2.1,AV.1.8.2.2,AV.1.8.2.3,AV.1.8.6.1,AV.1.8.2.4,AV.1.8.2.5,AV.1.8.2.6,AV.1.8.2.7,AV.1.8.2.8,AV.1.8.2.9,AV.1.8.2.10,AV.1.8.2.11,AV.1.8.2.12,AV.1.8.2.13,AV.1.8.2.14,AV.1.8.2.15,AV.1.8.2.16,AV.1.8.2.17,AV.1.8.2.18,AV.1.8.2.19,AV.1.8.2.20,AV.1.8.2.21,AV.1.8.2.22,AV.1.8.2.23,AV.1.8.2.24,AV.1.8.2.25,AV.1.8.2.26,AV.1.8.2.27,AV.1.8.2.28,AV.1.8.2.29,AV.1.8.2.30,AV.1.8.2.31,AV.1.8.2.32,AV.1.8.2.33,AV.1.8.2.34,AV.1.8.2.35,AV.1.8.2.36,AV.1.8.2.37,AV.1.8.2.38,AV.1.8.2.39,AV.1.8.2.40,AV.1.8.2.41,AV.1.8.2.42,AV.1.8.2.43,AV.1.8.2.44,AV.1.8.2.45,AV.1.8.2.46,AV.1.8.2.47,AV.1.8.2.49,AV.1.8.2.50,AV.1.8.3.1,AV.1.8.3.2,AV.1.8.3.3,AV.1.8.3.4,AV.1.8.3.5,AV.1.8.3.6,AV.1.8.3.7,AV.1.8.3.8,AV.1.8.3.9,AV.1.8.3.10" >>p12
	fi
	fi
else
			echo "Protecting Resources - OSRs" >>p1
			echo "OSR Executable and Libraries" >>p2
			echo "Not applicable as file $i not exist" >>p3
			echo "Not_Applicable" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "AV.1.8.2.1,AV.1.8.2.2,AV.1.8.2.3,AV.1.8.6.1,AV.1.8.2.4,AV.1.8.2.5,AV.1.8.2.6,AV.1.8.2.7,AV.1.8.2.8,AV.1.8.2.9,AV.1.8.2.10,AV.1.8.2.11,AV.1.8.2.12,AV.1.8.2.13,AV.1.8.2.14,AV.1.8.2.15,AV.1.8.2.16,AV.1.8.2.17,AV.1.8.2.18,AV.1.8.2.19,AV.1.8.2.20,AV.1.8.2.21,AV.1.8.2.22,AV.1.8.2.23,AV.1.8.2.24,AV.1.8.2.25,AV.1.8.2.26,AV.1.8.2.27,AV.1.8.2.28,AV.1.8.2.29,AV.1.8.2.30,AV.1.8.2.31,AV.1.8.2.32,AV.1.8.2.33,AV.1.8.2.34,AV.1.8.2.35,AV.1.8.2.36,AV.1.8.2.37,AV.1.8.2.38,AV.1.8.2.39,AV.1.8.2.40,AV.1.8.2.41,AV.1.8.2.42,AV.1.8.2.43,AV.1.8.2.44,AV.1.8.2.45,AV.1.8.2.46,AV.1.8.2.47,AV.1.8.2.49,AV.1.8.2.50,AV.1.8.3.1,AV.1.8.3.2,AV.1.8.3.3,AV.1.8.3.4,AV.1.8.3.5,AV.1.8.3.6,AV.1.8.3.7,AV.1.8.3.8,AV.1.8.3.9,AV.1.8.3.10" >>p12
fi
done
rm -rf temp temp1


#AV.1.1.5
echo "Password Requirements" >>p1
echo "Private Key Passphrases" >>p2
echo "No value to be set as per techspec guidelines" >>p3
echo "Not_Applicable" >>p4
echo "$c" >>p5
echo "$z" >>p6
echo "AV.1.1.5" >>p12

#AV.1.1.4
cat /etc/passwd | egrep -v "/sbin/nologin|sync|shutdown|halt|/bin/false"|awk -F":" '{print $6}'>temp_home
for i in `cat temp_home`
do
if [ -f $i/.ssh/id_rsa ]
then
	ssh-keygen -y -P '' -f $i/.ssh/id_rsa
	if [ $? -eq 0 ]
	then
	      	echo "Password Requirements" >>p1
	       	echo "Private Key Passphrase Requirement" >>p2
		echo "SSH Private Key has no passphrase set in user home dir $i/.ssh/id_rsa" >> p3
		echo "No" >>p4
		echo "AV.1.1.4" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
		echo "$fqdn" >>en1
		echo "$ipAddress" >>en2
		echo "$osName" >>en3
		echo "$timestamp" >>en4
	else
		echo "Password Requirements" >>p1
	       	echo "Private Key Passphrase Requirement" >>p2
		echo "SSH Private Key has passphrase set in user home dir $i/.ssh/id_rsa" >> p3
		echo "Yes" >>p4
		echo "AV.1.1.4" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
		echo "$fqdn" >>en1
		echo "$ipAddress" >>en2
		echo "$osName" >>en3
		echo "$timestamp" >>en4
	fi
else
		echo "Password Requirements" >>p1
	       	echo "Private Key Passphrase Requirement" >>p2
		echo "SSH Private Key doesn't exist in user home dir $i/.ssh/id_rsa" >> p3
		echo "Yes" >>p4
		echo "AV.1.1.4" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
		echo "$fqdn" >>en1
		echo "$ipAddress" >>en2
		echo "$osName" >>en3
		echo "$timestamp" >>en4
fi
done


#AV.1.7.1.2
echo "Identify and Authenticate Users" >>p1
echo "Maintain Individual Accountability" >>p2
echo "No value to be set as per techspec" >>p3
echo "$c" >>p5
echo "$z" >>p6
echo "Not_Applicable" >>p4
echo "AV.1.7.1.2" >>p12
		
#AV.1.2.2
sz=`rpm -qa |grep -i ssh |grep -i openssh-[0-9].[0-9] | cut -c1,2,3,4,5,6,7`
if [ "$sz" == "openssh" ]
then
		echo "Logging" >>p1
		echo "QuietMode" >>p2
		echo "Not applicable for OpenSSH" >>p3
		echo "Not_Applicable" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.2.2" >>p12
else
	szl=`cat /etc/ssh/sshd_config | grep -i "^QuietMode" | awk '{print $2}' |uniq`
	if [ "$szl" == "no" ]
	then
		echo "Logging" >>p1
		echo "QuietMode" >>p2
		echo "$szl" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.2.2" >>p12
	else
		echo "Logging" >>p1
		echo "QuietMode" >>p2
		echo "Value-is-not-set" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.2.2" >>p12
	fi
		
fi

#AV.1.1.7
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
				echo "$c" >>p5
				echo "$z" >>p6
				echo "AV.1.1.7" >>p12

			
		else
			if [ "$B" == "$sl" ] 
			then
			
				echo "Password Requirements" >>p1
				echo "Private Key Passphrases - system-to-system authentication" >>p2
				echo "ownership-for-/home/$i/.ssh/authorized_keys is $sk:$sl" >>p3
				echo "yes" >>p4
				echo "$c" >>p5
				echo "$z" >>p6
				echo "AV.1.1.7" >>p12
			fi
		fi
	else
				echo "Password Requirements" >>p1
				echo "Private Key Passphrases - system-to-system authentication" >>p2
				echo "/home/$i/.ssh/authorized_keys doesnt exist" >>p3
				echo "yes" >>p4
				echo "$c" >>p5
				echo "$z" >>p6
				echo "AV.1.1.7" >>p12
	fi
done
rm -rf 	temp_id	

#AV.1.1.6
cat /etc/passwd | awk -F":" '{print $1}' > temp_id
for i in `cat temp_id`
do
	if [ -f /home/$i/.ssh/authorized_keys ]
	then
		sk=`cat /home/$i/.ssh/authorized_keys |grep "from=" |wc -l`
		if [ $sk -gt 0 ]
		then
				echo "Password Requirements" >>p1
				echo "Public Key must restrict access only from authorized hosts" >>p2
				echo "The entry "from=" exists in /home/$i/.ssh/authorized_keys for user $i" >>p3
				echo "yes" >>p4
				echo "$c" >>p5
				echo "$z" >>p6
				echo "AV.1.1.6" >>p12
			
		else
	
				echo "Password Requirements" >>p1
				echo "Public Key must restrict access only from authorized hosts" >>p2
				echo "The entry "from=" not exists in /home/$i/.ssh/authorized_keys for user $i" >>p3
				echo "no" >>p4
				echo "$c" >>p5
				echo "$z" >>p6
				echo "AV.1.1.6" >>p12
		fi
	else
				echo "Password Requirements" >>p1
				echo "Public Key must restrict access only from authorized hosts" >>p2
				echo "/home/$i/.ssh/authorized_keys-doesnt-exist" >>p3
				echo "yes" >>p4
				echo "$c" >>p5
				echo "$z" >>p6
				echo "AV.1.1.6" >>p12
	fi
done
rm -rf 	temp_id	

#AV.1.1.2;AV.1.1.3;AV.1.2.3.1;AV.1.2.3.2 ;AV.1.2.3.3;AV.1.2.3.4 ;AV.1.2.3.5;AV.1.2.3.6;AV.1.2.4.1;AV.1.2.4.2;AV.1.2.4.3;AV.1.2.4.4;AV.1.4.6;AV.1.4.7;AV.1.4.9 ;AV.1.4.10;AV.1.4.11;AV.1.4.12;AV.1.4.13;AV.1.4.15 ;AV.1.4.16;AV.1.4.17;AV.1.4.18;AV.1.5.3;AV.1.5.4;AV.1.5.6;AV.1.5.7;AV.1.8.4.1;AV.1.8.4.2;AV.1.8.4.3;AV.1.8.4.4;AV.1.8.4.5;AV.1.8.4.6;AV.1.8.4.7;AV.1.8.5.1;AV.1.8.5.2;AV.1.8.5.3;AV.1.8.5.4;AV.1.8.5.5;AV.1.8.5.6;AV.1.8.5.7;AV.1.8.5.8;AV.1.8.5.10;AV.1.8.5.11;AV.1.8.5.12;AV.1.8.5.13;AV.1.8.5.14;AV.2.0.1.2;AV.2.0.1.3;AV.2.0.1.4;AV.2.1.1.5;AV.2.1.1.6;AV.2.1.1.7;AV.2.2.1.1;AV.2.2.1.2;AV.2.2.1.3;AV.2.2.1.4
	echo "Windows SSH Requirements" >>p1
	echo "SSH Parameter-Windows" >>p2
	echo "These parameters are for Windows" >>p3
	echo "Not_Applicable" >>p4
	echo "AV.1.1.2:AV.1.1.3:AV.1.2.3.1:AV.1.2.3.2:AV.1.2.3.3:AV.1.2.3.4:AV.1.2.3.5:AV.1.2.3.6:AV.1.2.4.1:AV.1.2.4.2:AV.1.2.4.3:AV.1.2.4.4:AV.1.4.6:AV.1.4.7:AV.1.4.9:AV.1.4.10:AV.1.4.11:AV.1.4.12:AV.1.4.13:AV.1.4.15:AV.1.4.16:AV.1.4.17:AV.1.4.18:AV.1.5.3:AV.1.5.4:AV.1.5.6:AV.1.5.7:AV.1.8.4.1:AV.1.8.4.2:AV.1.8.4.3:AV.1.8.4.4:AV.1.8.4.5:AV.1.8.4.6:AV.1.8.4.7:AV.1.8.5.1:AV.1.8.5.2:AV.1.8.5.3:AV.1.8.5.4:AV.1.8.5.5:AV.1.8.5.6:AV.1.8.5.7:AV.1.8.5.8:AV.1.8.5.10:AV.1.8.5.11:AV.1.8.5.12:AV.1.8.5.13:AV.1.8.5.14:AV.2.0.1.2:AV.2.0.1.3:AV.2.0.1.4:AV.2.1.1.5:AV.2.1.1.6:AV.2.1.1.7:AV.2.2.1.1:AV.2.2.1.2:AV.2.2.1.3:AV.2.2.1.4" >>p12


#################################################################################################

######### SUDO HC Script ####################

#################################################################################################

#ZY.1.2.4;AV.1.2.4
sl=`sed -n '/# rotate.log*/,/#.*keep*/p' /etc/logrotate.conf |grep -v '#' |egrep 'monthly|weekly'`
sn=`cat /etc/logrotate.conf |grep -v '#' |grep ^rotate |uniq  |awk '{print $2}'`

if [[ "$sl" == "weekly" && "$sn" -ge "$LOG_ROTATE_WEEK" ]] || [[ "$sl" == "monthly" && "$sn" -ge "$LOG_ROTATE_MONTH" ]]
then
cat /etc/logrotate.conf |grep "^include.*/etc/logrotate.d"
if [ $? -eq 0 ]
then
  sp=`cat /etc/logrotate.d/syslog |grep '^/var/log/secure' |wc -l`
  if [ $sp -gt 0 ]
  then
	sed -n '/\/var\/log\/secure.*{/,/}/p' /etc/logrotate.d/syslog |grep -v '#' > log_file1
	sk=`cat log_file1 |wc -l`
	if [ $sk -gt 0 ]
	then
		sj1=`cat log_file1 |grep rotate |awk '{print $2}'`
		sj2=`cat log_file1 |grep weekly |wc -c`
		sj3=`cat log_file1 |grep monthly |wc -c`
		if [[ $sj1 -ge $LOG_ROTATE_WEEK  &&  $sj2 -gt 1 ]] || [[ $sj1 -ge $LOG_ROTATE_MONTH  &&  $sj3 -gt 1 ]]
		then
			echo "Logging" >>p1
		        echo "Retain Log Files" >>p2
			echo "Logrotate-is-set-as correct for /var/log/secure in-/etc/logrotate.d/syslog" >>p3
			echo "ZY.1.2.4;AV.1.2.4">>p12
			echo "yes" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
		else
			echo "Logging" >>p1
		        echo "Retain Log Files" >>p2
			echo "Logrotate-is-set-as incorrect for /var/log/secure in-/etc/logrotate.d/syslog" >>p3
			echo "ZY.1.2.4;AV.1.2.4">>p12
			echo "no" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
		fi
	else
		echo "Logging" >>p1
                echo "Retain Log Files" >>p2
		echo "Logrotate for /var/log/secure is-set-as correct in /etc/logrotate.d/syslog" >>p3
		echo "ZY.1.2.4;AV.1.2.4">>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	fi
  else
		echo "Logging" >>p1
                echo "Retain Log Files" >>p2
		echo "Logrotate for /var/log/secure is not set correct in /etc/logrotate.d/syslog" >>p3
		echo "ZY.1.2.4;AV.1.2.4">>p12
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
  fi
else
		echo "Logging" >>p1
                echo "Retain Log Files" >>p2
		echo "'include /etc/logrotate.d' entry not found in /etc/logrotate.conf. Please check logrotate policy manually" >>p3
		echo "ZY.1.2.4;AV.1.2.4">>p12
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
fi
else
cat /etc/logrotate.conf |grep "^include.*/etc/logrotate.d"
if [ $? -eq 0 ]
then
  sp=`cat /etc/logrotate.d/syslog |grep '^/var/log/secure' |wc -l`
  if [ $sp -gt 0 ]
  then
	sed -n '/\/var\/log\/secure.*{/,/}/p' /etc/logrotate.d/syslog |grep -v '#' > log_file1
	sk=`cat log_file1 |wc -l`
	if [ $sk -gt 0 ]
	then
		sj1=`cat log_file1 |grep rotate |awk '{print $2}'`
		sj2=`cat log_file1 |grep weekly |wc -c`
		sj3=`cat log_file1 |grep monthly |wc -c`
		if [[ $sj1 -ge $LOG_ROTATE_WEEK  &&  $sj2 -gt 1 ]] || [[ $sj1 -ge $LOG_ROTATE_MONTH  &&  $sj3 -gt 1 ]]
		then
			echo "Logging" >>p1
		        echo "Retain Log Files" >>p2
			echo "Logrotate-is-set-as correct for /var/log/secure in-/etc/logrotate.d/syslog" >>p3
			echo "ZY.1.2.4;AV.1.2.4">>p12
			echo "yes" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
		else
			echo "Logging" >>p1
		        echo "Retain Log Files" >>p2
			echo "Logrotate-is-set-as incorrect for /var/log/secure in-/etc/logrotate.d/syslog" >>p3
			echo "ZY.1.2.4;AV.1.2.4">>p12
			echo "no" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
		fi
	else
		echo "Logging" >>p1
                echo "Retain Log Files" >>p2
		echo "Logrotate for /var/log/secure is-set-as correct in /etc/logrotate.d/syslog" >>p3
		echo "ZY.1.2.4;AV.1.2.4">>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	fi
  else
		echo "Logging" >>p1
                echo "Retain Log Files" >>p2
		echo "Logrotate for /var/log/secure is not set correct in /etc/logrotate.d/syslog" >>p3
		echo "ZY.1.2.4;AV.1.2.4">>p12
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
  fi
else
		echo "Logging" >>p1
                echo "Retain Log Files" >>p2
		echo "'include /etc/logrotate.d' entry not found in /etc/logrotate.conf. Please check logrotate policy manually" >>p3
		echo "ZY.1.2.4;AV.1.2.4">>p12
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
fi
fi
rm -rf log_file1


#ZY.1.4.2.0;#ZY.1.4.2.1
cat /etc/sudoers |grep SHELLESCAPE
if [ $? -eq 0 ]
then
cat /etc/sudoers | grep -i "noexec"
if [ $? -eq 0 ]
then
		echo "System Settings" >>p1
		echo "Commands which allow shell escape" >>p2
		echo "SHELLESCAPE and noexec is enabled in /etc/sudoers" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "ZY.1.4.2.1" >>p12
else
		echo "System Settings" >>p1
		echo "Commands which allow shell escape" >>p2
		echo "SHELLESCAPE is enabled but noexec-is-not-enabled in /etc/sudoers" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "ZY.1.4.2.1" >>p12
fi
else
		echo "System Settings" >>p1
		echo "Commands which allow shell escape" >>p2
		echo "SHELLESCAPE-is-not-enabled in /etc/sudoers" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "ZY.1.4.2.1" >>p12
fi

#ZY.1.4.2.3
Release=`cat /etc/redhat-release |awk '{print $1}'`
if [ "$Release" != "Red" ]
then
cat /etc/sudoers | grep "Defaults env_file=/etc/sudo.env"
	if [ $? -eq 0 ]
	then
		if [ -f /etc/sudo.env ]
		then
			cat /etc/sudo.env | egrep "^SMIT_SHELL=n|^SMIT_SEMI_COLON=n|^SMIT_QUOTE=n"
			if [ $? -eq 0 ]
			then
				echo "System Settings" >>p1
				echo "Commands which allow shell escape" >>p2
				echo "SMIT-values-found" >>p3
				echo "missing-values-SMIT_SHELL=n|^SMIT_SEMI_COLON=n|^SMIT_QUOTE=n" >>p2
				echo "yes" >>p4
				echo "$c" >>p5
				echo "$z" >>p6
				echo "ZY.1.4.2.3" >>p12
			
			else
				echo "missing-values-SMIT_SHELL=n|^SMIT_SEMI_COLON=n|^SMIT_QUOTE=n" >>p3
				echo "System Settings" >>p1
				echo "Commands which allow shell escape" >>p2
				echo "yes" >>p4
				echo "$c" >>p5
				echo "$z" >>p6
				echo "ZY.1.4.2.3" >>p12
			fi
		else
			echo "System Settings" >>p1
			echo "Commands which allow shell escape" >>p2
			echo "/etc/sudo.env-file-not-found" >>p3
			echo "no" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "ZY.1.4.2.3" >>p12
		fi
	fi
else
			echo "System Settings" >>p1
			echo "Commands which allow shell escape" >>p2
			echo "This-is-not-for-Linux" >>p3
			echo "Not_Applicable" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "ZY.1.4.2.3" >>p12

fi

#ZY.1.4.3.3
sl=`cat /etc/sudoers.d/* |grep -w "Cmnd_Alias.*SUDOSUDO.*=.*/usr/local/bin/sudo,.*/usr/bin/sudo,.*/bin/sudo"|wc -l`
sp=`cat /etc/sudoers |grep -w "Cmnd_Alias.*SUDOSUDO" |grep "=.*/usr/local/bin/sudo,.*/usr/bin/sudo,.*/bin/sudo"|wc -l`
sk=`cat /etc/sudoers |grep -v '#' |grep -v '^$' |tail -1`
#cat /etc/sudoers | grep "^ALL ALL=\!SUDOSUDO"
if [ $sl -ne 0 ] || [ $sp -ne 0 ]
then
	if [[ "$sk" == *"ALL ALL=!SUDOSUDO"* ]]
	then
		    
		    echo "System Settings" >>p1
		    echo "Preventing Nested Sudo invocation" >>p2
		    echo "ALL-ALL=!SUDOSUDO-found in /etc/sudoers" >>p3
		    echo "yes" >>p4
		    echo "$c" >>p5
		    echo "$z" >>p6
		    echo "ZY.1.4.3.3" >>p12
	else
		    
		    echo "System Settings" >>p1
		    echo "Preventing Nested Sudo invocation" >>p2
		    echo "ALL-ALL=!SUDOSUDO-not-found in /etc/sudoers" >>p3
		    echo "no" >>p4
		    echo "$c" >>p5
		    echo "$z" >>p6
		    echo "ZY.1.4.3.3" >>p12
	fi
else
 
            
            echo "System Settings" >>p1
            echo "Preventing Nested Sudo invocation" >>p2
            echo "Cmnd_Alias SUDOSUDO-not-found in /etc/sudoers">>p3
            echo "no" >>p4
            echo "$c" >>p5
            echo "$z" >>p6
            echo "ZY.1.4.3.3" >>p12
fi


#ZY.1.2.3,ZY.1.4.4,ZY.1.2.2
sl=`ls -l /var/log/hist/root/ |wc -c`
if [ "$sl" -gt "0" ] && [ -f /etc/profile.d/secondary_logging_IBM.sh ]
then
			echo "Logging" >>p1
			echo "Secondary logging" >>p2
			echo "Secondary login is in place" >>p3
			echo "yes" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "ZY.1.2.3,ZY.1.4.4,ZY.1.2.2" >>p12
else
	sl1=`ls -ltr /root/.history-sudo-* |wc -l`
	if [ $sl1 -gt 0 ]
	then
			echo "Logging" >>p1
			echo "Secondary logging" >>p2
			echo "Secondary login is in place" >>p3
			echo "yes" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "ZY.1.2.3,ZY.1.4.4,ZY.1.2.2" >>p12
	else		
			echo "Logging" >>p1
			echo "Secondary logging" >>p2
			echo "Secondary login is not in place" >>p3
			echo "no" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "ZY.1.2.3,ZY.1.4.4,ZY.1.2.2" >>p12
	fi
fi

#ZY.1.2.1
sk=`cat /etc/sudoers.d/* |grep "\!logfile" |wc -l`
sl=`cat /etc/sudoers |grep "\!logfile" |wc -l`
if [ $sk -gt 0 ] || [ $sl -gt 0 ]
then
			echo "Logging" >>p1
			echo "Sudo Logging must not be disabled" >>p2
			echo "Sudo logging is disabled" >>p3
			echo "no" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "ZY.1.2.1" >>p12
else
			echo "Logging" >>p1
			echo "Sudo Logging must not be disabled" >>p2
			echo "Sudo logging is not disabled" >>p3
			echo "yes" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "ZY.1.2.1" >>p12
fi

#ZY.1.4.3.1,ZY.1.8.2.1,ZY.1.8.1.2,ZY.1.8.1.4
cat /etc/sudoers |egrep "^#include|^#includedir" |awk '{print $2}' >temp1
cat /etc/sudoers.d/* |egrep "^#include|^#includedir" |awk '{print $2}' >>temp1
for i in `cat temp1`
do
sk=`echo $i |cut -c1`
if [ "$sk" == "/" ]
then
	echo "System Settings" >>p1
	echo "Specific commands/programs executed via sudo:" >>p2
	echo "Full path specified for command \"$i\" in sudoers config file having include or includedir statements" >>p3
	echo "yes" >>p4
	echo "$c" >>p5
	echo "$z" >>p6
	echo "ZY.1.4.3.1,ZY.1.8.2.1,ZY.1.8.1.2,ZY.1.8.1.4" >>p12
else
	echo "System Settings" >>p1
	echo "Specific commands/programs executed via sudo:" >>p2
	echo "Full path not specified for command \"$i\" in sudoers config file having include or includedir statements" >>p3
	echo "no" >>p4
	echo "$c" >>p5
	echo "$z" >>p6
	echo "ZY.1.4.3.1,ZY.1.8.2.1,ZY.1.8.1.2,ZY.1.8.1.4" >>p12
fi
done
rm -rf temp1

#ZY.1.8.1.0
ls -l /etc/sudoers
if [ $? -eq 0 ]
then
	sz=`ls -lrt /etc/sudoers | awk '{print $1}' | cut -c9`
	sz1=`ls -lrt /etc/sudoers | awk '{print $3}'`
	if [ "$sz1" == "root" ] && [ "$sz" != "w" ]
	then
				echo "Protecting Resources - OSRs" >>p1
                echo "/etc/sudoers permission" >>p2
				echo "Permission of /etc/sudoers is valid" >>p3
                echo "yes" >>p4
                echo "$c" >>p5
                echo "$z" >>p6
                echo "ZY.1.8.1.0" >>p12
	else
				echo "Protecting Resources - OSRs" >>p1
                echo "/etc/sudoers permission" >>p2
				echo "Permission of /etc/sudoers is invalid" >>p3
                echo "no" >>p4
                echo "$c" >>p5
                echo "$z" >>p6
                echo "ZY.1.8.1.0" >>p12
	fi
else
				echo "Protecting Resources - OSRs" >>p1
                echo "/etc/sudoers permission" >>p2
				echo "File /etc/sudoers not exist" >>p3
                echo "no" >>p4
                echo "$c" >>p5
                echo "$z" >>p6
                echo "ZY.1.8.1.0" >>p12
fi

#ZY.1.4.5
sk=`cat /etc/sudoers |egrep "/bin/vi|/bin/tvi|/bin/vim|/bin/rvim|/bin/gvim|/bin/evim|/bin/emacs|/bin/ed|/usr/bin/vi|/usr/bin/tvi|/usr/bin/nano|/usr/bin/vim|/usr/bin/rvim|/usr/bin/gvim|/usr/bin/evim|/usr/bin/emacs|/usr/bin/ed|/bin/view|/usr/bin/view|/bin/rvi|/usr/bin/rvi" |wc -l`
sk1=`cat /etc/sudoers.d/* |egrep "/bin/vi|/bin/tvi|/bin/vim|/bin/rvim|/bin/gvim|/bin/evim|/bin/emacs|/bin/ed|/usr/bin/vi|/usr/bin/tvi|/usr/bin/nano|/usr/bin/vim|/usr/bin/rvim|/usr/bin/gvim|/usr/bin/evim|/usr/bin/emacs|/usr/bin/ed|/bin/view|/usr/bin/view|/bin/rvi|/usr/bin/rvi" |wc -l`
if [ $sk -gt 0 ] ||  [ $sk1 -gt 0 ]
then
          echo "System Settings" >>p1
           echo "Editors used with sudo privileges" >>p2
    echo "The sudoedit program is not used when edit privileges are required" >> p3
    echo "No" >>p4
    echo "$c" >> p5
    echo "$z" >>p6
        echo "ZY.1.4.5" >>p12
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
    echo "$timestamp" >>en4
else
           echo "System Settings" >>p1
           echo "Editors used with sudo privileges" >>p2
    echo "The sudoedit program is used when edit privileges are required" >> p3
    echo "Yes" >>p4
    echo "$c" >> p5
    echo "$z" >>p6
        echo "ZY.1.4.5" >>p12
    echo "$fqdn" >>en1
    echo "$ipAddress" >>en2
    echo "$osName" >>en3
    echo "$timestamp" >>en4
fi

#ZY.1.8.1.6
cat /etc/sudoers |grep env_file
if [ $? -eq 0 ]
then
	sk=`cat /etc/sudoers |grep "^[^#;]" | grep  env_file | awk -F"=" '{print $2}' | sed 's/\#.*//' | sed -e 's/ //g'`
	str1=$(ls -ld $sk |awk '{print $3}')
	str2=$(ls -ld $sk |awk '{print $4}')
	if [ "$str1" == "root" ] && [ "$str2" == "root" ]
	then
		echo "Protecting Resources - OSRs" >>p1
		echo "Any file referenced by a  “env_file” directive in the /etc/sudoers" >>p2
		echo "File permission is valid for $sk" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "ZY.1.8.1.6" >>p12
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "Any file referenced by a  “env_file” directive in the /etc/sudoers" >>p2
		echo "File permission is invalid for $sk" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "ZY.1.8.1.6" >>p12
	fi
else
		echo "Protecting Resources - OSRs" >>p1
		echo "Any file referenced by a  “env_file” directive in the /etc/sudoers" >>p2
		echo "env_file not exists in /etc/sudoers" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "ZY.1.8.1.6" >>p12
fi


#ZY.1.8.1.1,ZY.1.8.1.3,ZY.1.8.1.5,ZY.1.8.2.2,ZY.1.8.2.3
sl=`ls -ltr /etc/sudoers.d |wc -l`
file1=`ls -ld /etc/sudoers.d |wc -l`
if [ $file1 -gt 0 ] && [ $sl -gt 1 ]
then
cat /etc/sudoers |egrep "^#include|^#includedir" |awk '{print $2}' >temp1
cat /etc/sudoers.d/* |egrep "^#include|^#includedir" |awk '{print $2}' >>temp1
	sn=`cat temp1 |wc -l`
	if [ $sn -gt 0 ]
	then
	for i in `cat temp1`
	do
		sz=`ls -ld $i | awk '{print $1}' | cut -c9`
		sk=`ls -ld $i | awk '{print $3}'`
		sp=`ls -ld $i | awk '{print $4}'`
		if [ "$sk" == "root" ] && [ "$sz" != "w" ] && [ "$sp" == "root" ]
		then
			echo "Protecting Resources - OSRs" >>p1
		        echo "File permission in /etc/sudoers.d and /etc/sudoers" >>p2
			echo "File permission is valid for $i" >>p3
		        echo "yes" >>p4
		        echo "$c" >>p5
		        echo "$z" >>p6
		        echo "ZY.1.8.1.1,ZY.1.8.1.3,ZY.1.8.1.5,ZY.1.8.2.2,ZY.1.8.2.3" >>p12
		else
			echo "Protecting Resources - OSRs" >>p1
		        echo "File permission in /etc/sudoers.d and /etc/sudoers" >>p2
			echo "File permission is invalid for $i" >>p3
		        echo "no" >>p4
		        echo "$c" >>p5
		        echo "$z" >>p6
		        echo "ZY.1.8.1.1,ZY.1.8.1.3,ZY.1.8.1.5,ZY.1.8.2.2,ZY.1.8.2.3" >>p12
		fi
	done
	else
		echo "Protecting Resources - OSRs" >>p1
                echo "File permission in /etc/sudoers.d and /etc/sudoers" >>p2
		echo "SUDO template not implemented" >>p3
                echo "no" >>p4
                echo "$c" >>p5
                echo "$z" >>p6
                echo "ZY.1.8.1.1,ZY.1.8.1.3,ZY.1.8.1.5,ZY.1.8.2.2,ZY.1.8.2.3" >>p12
	fi

else
		echo "Protecting Resources - OSRs" >>p1
                echo "File permission in /etc/sudoers.d and /etc/sudoers" >>p2
		echo "SUDO template not implemented" >>p3
                echo "no" >>p4
                echo "$c" >>p5
                echo "$z" >>p6
                echo "ZY.1.8.1.1,ZY.1.8.1.3,ZY.1.8.1.5,ZY.1.8.2.2,ZY.1.8.2.3" >>p12
fi
rm -rf temp1


######## Privilege Monitoring Parameters Code ############

#IZ.20.1.2.1
if [ -f /etc/rsyslog.conf ]
then
	sk=`cat /etc/rsyslog.conf |grep -v '^#' |grep "'*.info;mail.none.*@$SYSLOG_IP" |wc -l`
	sl=`cat /etc/rsyslog.conf |grep -v '^#' |grep "'*.info;mail.none.*@@$SYSLOG_IP" |wc -l`
	
	if [ $sk -gt 0 ] || [ $sl -gt 0 ]
	then
		echo "Logging" >>p1
		echo "Login Success or Failure" >>p2
		echo "/etc/rsyslog.conf contain correct parameters along with syslog collector IP" >> p3
		echo "yes" >>p4
		echo "IZ.20.1.2.1" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
	else
		echo "Logging" >>p1
		echo "Login Success or Failure" >>p2
		echo "/etc/rsyslog.conf doesn't contain correct parameters along with syslog collector IP" >> p3
		echo "no" >>p4
		echo "IZ.20.1.2.1" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
	fi
else
		echo "Logging" >>p1
		echo "Login Success or Failure" >>p2
		echo "/etc/rsyslog.conf file not exist" >> p3
		echo "no" >>p4
		echo "IZ.20.1.2.1" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
fi


#IZ.20.1.2.2.1:file-check
if [ -f /var/log/audit/audit.log ]
then
	str6=$(stat -c "%a %n" /var/log/audit/audit.log |awk '{print $1}')
	if [ "$str6" == "600" ]
	then
		echo "Logging" >>p1
		echo "/var/log/audit/audit.log" >>p2
		echo "/var/log/audit/audit.log exist and file permission is set as $str6" >> p3
		echo "yes" >>p4
		echo "IZ.20.1.2.2.1" >>p12
		echo "$c" >> p5
		echo "$z" >>p6	
	
	else
		echo "Logging" >>p1
		echo "/var/log/audit/audit.log" >>p2
		echo "/var/log/audit/audit.log exist but wrong file permission set as $str6" >> p3
		echo "no" >>p4
		echo "IZ.20.1.2.2.1" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
	fi
else
		echo "Logging" >>p1
		echo "/var/log/audit/audit.log" >>p2
		echo "/var/log/audit/audit.log file doesn't exist" >> p3
		echo "no" >>p4
		echo "IZ.20.1.2.2.1" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
fi


#IZ.20.1.2.3.1:file-check

systemctl status auditd |grep 'active (running)'

if [ $? = 0 ] ;then


sk=` cat /etc/audit/audit.rules|awk '{if($1=="-a" && $2=="exit,always" && $3=="-F" && $4=="path=/usr" && $5=="-F" && $6=="perm=a") {print $0}'} `

  if [ "$sk" == "" ];then
   
	echo "Logging" >>p1
	echo "/etc/audit/audit.rules" >>p2
	echo "-a_exit-always -F path=/usr -F perm=a_ doesnot exist" >>p3
	echo "no" >>p4
	echo "IZ.20.1.2.3.1" >>p12
else
	echo "Logging" >>p1
	echo "/etc/audit/audit.rules" >>p2
	echo "-a_exit-always -F path=/usr -F perm=a_exist"  >>p3
	echo "yes"  >>p4
	echo "IZ.20.1.2.3.1"  >>p12
fi


  else 

        echo "Logging" >>p1
        echo "/etc/audit/audit.rules" >>p2
        echo "Auditd service is not running.First this service should run and then check the rules" >>p3
        echo "no" >>p4
        echo "IZ.20.1.2.3.1" >>p12
fi


#IZ.20.1.2.3.2	/etc/audit/audit.rules		-a_exit-always -F path=/etc -F perm=a_does_not_exist
#IZ.20.1.2.3.2	/etc/audit/audit.rules		-a_exit-always -F path=/etc -F perm=a_does_not_exist

#IZ.20.1.2.3.2:file-check

systemctl status auditd |grep 'active (running)'


  if [ $? = 0 ] ;then


sk=` cat /etc/audit/audit.rules|awk '{if($1=="-a" && $2=="exit,always" && $3=="-F" && $4=="path=/etc" && $5=="-F" && $6=="perm=a") {print $0}'} `

  if [ "$sk" == "" ];then
   
	echo "Logging" >>p1
	echo "/etc/audit/audit.rules" >>p2
	echo "-a_exit-always -F path=/etc -F perm=a_ doesnot exist" >>p3
	echo "no" >>p4
	echo "IZ.20.1.2.3.2" >>p12
else
	echo "Logging" >>p1
	echo "/etc/audit/audit.rules" >>p2
	echo "-a_exit-always -F path=/etc -F perm=a_exist"  >>p3
	echo "yes"  >>p4
	echo "IZ.20.1.2.3.2"  >>p12
fi


  else 

        echo "Logging" >>p1
        echo "/etc/audit/audit.rules" >>p2
        echo "Auditd service is not running.First this service should run and then check the rules" >>p3
        echo "no" >>p4
        echo "IZ.20.1.2.3.2" >>p12
fi





#IZ.20.1.2.3.3	/etc/audit/audit.rules		-a_exit-always -F path=/var/log -F perm=a_not_exist
#IZ.20.1.2.3.3	/var/log/audit/audit.rules		-a_exit-always -F path=/var/log -F perm=a_does_not_exist

#IZ.20.1.2.3.3:file-check

systemctl status auditd |grep 'active (running)'


  if [ $? = 0 ] ;then


sk=` cat /etc/audit/audit.rules|awk '{if($1=="-a" && $2=="exit,always" && $3=="-F" && $4=="path=/var/log" && $5=="-F" && $6=="perm=a") {print $0}'} `

  if [ "$sk" == "" ];then
   
	echo "Logging" >>p1
	echo "/var/log/audit/audit.rules" >>p2
	echo "-a_exit-always -F path=/var/log -F perm=a_ doesnot exist" >>p3
	echo "no" >>p4
	echo "IZ.20.1.2.3.3" >>p12
else
	echo "Logging" >>p1
	echo "/var/log/audit/audit.rules" >>p2
	echo "-a_exit-always -F path=/var/log -F perm=a_exist"  >>p3
	echo "yes"  >>p4
	echo "IZ.20.1.2.3.3"  >>p12
fi


  else 

        echo "Logging" >>p1
        echo "/var/log/audit/audit.rules" >>p2
        echo "Auditd service is not running.First this service should run and then check the rules" >>p3
        echo "no" >>p4
        echo "IZ.20.1.2.3.3" >>p12
fi

#IZ.20.1.2.3.4	/etc/audit/audit.rules		-a_exit-always -F path=/tmp -F perm=a_not_exist

#IZ.20.1.2.3.4	/tmp/audit/audit.rules		-a_exit-always -F path=/tmp -F perm=a_does_not_exist

#IZ.20.1.2.3.4:file-check

systemctl status auditd |grep 'active (running)'


  if [ $? = 0 ] ;then


sk=` cat /etc/audit/audit.rules|awk '{if($1=="-a" && $2=="exit,always" && $3=="-F" && $4=="path=/tmp" && $5=="-F" && $6=="perm=a") {print $0}'} `

  if [ "$sk" == "" ];then
   
	echo "Logging" >>p1
	echo "/tmp/audit/audit.rules" >>p2
	echo "-a_exit-always -F path=/tmp -F perm=a_ doesnot exist" >>p3
	echo "no" >>p4
	echo "IZ.20.1.2.3.4" >>p12
else
	echo "Logging" >>p1
	echo "/tmp/audit/audit.rules" >>p2
	echo "-a_exit-always -F path=/tmp -F perm=a_exist"  >>p3
	echo "yes"  >>p4
	echo "IZ.20.1.2.3.4"  >>p12
fi


  else 

        echo "Logging" >>p1
        echo "/tmp/audit/audit.rules" >>p2
        echo "Auditd service is not running.First this service should run and then check the rules" >>p3
        echo "no" >>p4
        echo "IZ.20.1.2.3.4" >>p12
fi




#IZ.20.1.2.3.6	/etc/audit/audit.rules		-a_exit-always -F path=/var/log/messages -F perm=a_not_exist
#IZ.20.1.2.3.6	/var/log/messages/audit/audit.rules		-a_exit-always -F path=/var/log/messages -F perm=a_does_not_exist

#IZ.20.1.2.3.6:file-check

systemctl status auditd |grep 'active (running)'


  if [ $? = 0 ] ;then


sk=` cat /etc/audit/audit.rules|awk '{if($1=="-a" && $2=="exit,always" && $3=="-F" && $4=="path=/var/log/messages" && $5=="-F" && $6=="perm=a") {print $0}'} `

  if [ "$sk" == "" ];then
   
	echo "Logging" >>p1
	echo "/var/log/messages/audit/audit.rules" >>p2
	echo "-a_exit-always -F path=/var/log/messages -F perm=a_ doesnot exist" >>p3
	echo "no" >>p4
	echo "IZ.20.1.2.3.6" >>p12
else
	echo "Logging" >>p1
	echo "/var/log/messages/audit/audit.rules" >>p2
	echo "-a_exit-always -F path=/var/log/messages -F perm=a_exist"  >>p3
	echo "yes"  >>p4
	echo "IZ.20.1.2.3.6"  >>p12
fi


  else 

        echo "Logging" >>p1
        echo "/var/log/messages/audit/audit.rules" >>p2
        echo "Auditd service is not running.First this service should run and then check the rules" >>p3
        echo "no" >>p4
        echo "IZ.20.1.2.3.6" >>p12
fi


#IZ.20.1.2.3.7	/etc/audit/audit.rules		-a_exit-always -F path=/var/log/wtmp -F perm=a_not_exist
#IZ.20.1.2.3.7	/var/log/wtmp/audit/audit.rules		-a_exit-always -F path=/var/log/wtmp -F perm=a_does_not_exist

#IZ.20.1.2.3.7:file-check

systemctl status auditd |grep 'active (running)'


  if [ $? = 0 ] ;then


sk=` cat /etc/audit/audit.rules|awk '{if($1=="-a" && $2=="exit,always" && $3=="-F" && $4=="path=/var/log/wtmp" && $5=="-F" && $6=="perm=a") {print $0}'} `

  if [ "$sk" == "" ];then
   
	echo "Logging" >>p1
	echo "/var/log/wtmp/audit/audit.rules" >>p2
	echo "-a_exit-always -F path=/var/log/wtmp -F perm=a_ doesnot exist" >>p3
	echo "no" >>p4
	echo "IZ.20.1.2.3.7" >>p12
else
	echo "Logging" >>p1
	echo "/var/log/wtmp/audit/audit.rules" >>p2
	echo "-a_exit-always -F path=/var/log/wtmp -F perm=a_exist"  >>p3
	echo "yes"  >>p4
	echo "IZ.20.1.2.3.7"  >>p12
fi


  else 

        echo "Logging" >>p1
        echo "/var/log/wtmp/audit/audit.rules" >>p2
        echo "Auditd service is not running.First this service should run and then check the rules" >>p3
        echo "no" >>p4
        echo "IZ.20.1.2.3.7" >>p12
fi


#IZ.20.1.2.3.8	/etc/audit/audit.rules		-a_exit-always -F path=/var/log/secure -F perm=a_not_exist
#IZ.20.1.2.3.8	/var/log/secure/audit/audit.rules		-a_exit-always -F path=/var/log/secure -F perm=a_does_not_exist

#IZ.20.1.2.3.8:file-check

systemctl status auditd |grep 'active (running)'


  if [ $? = 0 ] ;then


sk=` cat /etc/audit/audit.rules|awk '{if($1=="-a" && $2=="exit,always" && $3=="-F" && $4=="path=/var/log/secure" && $5=="-F" && $6=="perm=a") {print $0}'} `

  if [ "$sk" == "" ];then
   
	echo "Logging" >>p1
	echo "/var/log/secure/audit/audit.rules" >>p2
	echo "-a_exit-always -F path=/var/log/secure -F perm=a_ doesnot exist" >>p3
	echo "no" >>p4
	echo "IZ.20.1.2.3.8" >>p12
else
	echo "Logging" >>p1
	echo "/var/log/secure/audit/audit.rules" >>p2
	echo "-a_exit-always -F path=/var/log/secure -F perm=a_exist"  >>p3
	echo "yes"  >>p4
	echo "IZ.20.1.2.3.8"  >>p12
fi


  else 

        echo "Logging" >>p1
        echo "/var/log/secure/audit/audit.rules" >>p2
        echo "Auditd service is not running.First this service should run and then check the rules" >>p3
        echo "no" >>p4
        echo "IZ.20.1.2.3.8" >>p12
fi


#IZ.20.1.2.3.9	/etc/audit/audit.rules		-a_exit-always -F path=/etc/ssh/sshd_config -F perm=wa_not_exist
#IZ.20.1.2.3.9	/etc/ssh/sshd_config/audit/audit.rules		-a_exit-always -F path=/etc/ssh/sshd_config -F perm=a_does_not_exist

#IZ.20.1.2.3.9:file-check

systemctl status auditd |grep 'active (running)'


  if [ $? = 0 ] ;then


sk=` cat /etc/audit/audit.rules|awk '{if($1=="-a" && $2=="exit,always" && $3=="-F" && $4=="path=/etc/ssh/sshd_config" && $5=="-F" && $6=="perm=wa") {print $0}'} `

  if [ "$sk" == "" ];then
   
	echo "Logging" >>p1
	echo "/etc/ssh/sshd_config/audit/audit.rules" >>p2
	echo "-a_exit-always -F path=/etc/ssh/sshd_config -F perm=wa_ doesnot exist" >>p3
	echo "no" >>p4
	echo "IZ.20.1.2.3.9" >>p12
else
	echo "Logging" >>p1
	echo "/etc/ssh/sshd_config/audit/audit.rules" >>p2
	echo "-a_exit-always -F path=/etc/ssh/sshd_config -F perm=wa_exist"  >>p3
	echo "yes"  >>p4
	echo "IZ.20.1.2.3.9"  >>p12
fi


  else 

        echo "Logging" >>p1
        echo "/etc/ssh/sshd_config/audit/audit.rules" >>p2
        echo "Auditd service is not running.First this service should run and then check the rules" >>p3
        echo "no" >>p4
        echo "IZ.20.1.2.3.9" >>p12
fi


#IZ.20.1.2.3.10	/etc/audit/audit.rules		Rule is set for this path /etc/default
#IZ.20.1.2.3.10	/etc/default/audit/audit.rules		-a_exit-always -F path=/etc/default -F perm=wa_does_not_exist

#IZ.20.1.2.3.10:file-check

systemctl status auditd |grep 'active (running)'


  if [ $? = 0 ] ;then


sk=` cat /etc/audit/audit.rules|awk '{if($1=="-a" && $2=="exit,always" && $3=="-F" && $4=="path=/etc/default" && $5=="-F" && $6=="perm=wa") {print $0}'} `

  if [ "$sk" == "" ];then
   
	echo "Logging" >>p1
	echo "/etc/default/audit/audit.rules" >>p2
	echo "-a_exit-always -F path=/etc/default -F perm=wa_ doesnot exist" >>p3
	echo "no" >>p4
	echo "IZ.20.1.2.3.10" >>p12
else
	echo "Logging" >>p1
	echo "/etc/default/audit/audit.rules" >>p2
	echo "-a_exit-always -F path=/etc/default -F perm=wa_exist"  >>p3
	echo "yes"  >>p4
	echo "IZ.20.1.2.3.10"  >>p12
fi


  else 

        echo "Logging" >>p1
        echo "/etc/default/audit/audit.rules" >>p2
        echo "Auditd service is not running.First this service should run and then check the rules" >>p3
        echo "no" >>p4
        echo "IZ.20.1.2.3.10" >>p12
fi

#IZ.20.1.2.3.11	/etc/audit/audit.rules		Rule is set for this path /var/log/audit/audit.log
#IZ.20.1.2.3.11	/var/log/audit/audit.log/audit/audit.rules		-a_exit-always -F path=/var/log/audit/audit.log -F perm=a_does_not_exist

#IZ.20.1.2.3.11:file-check

systemctl status auditd |grep 'active (running)'


  if [ $? = 0 ] ;then


sk=` cat /etc/audit/audit.rules|awk '{if($1=="-a" && $2=="exit,always" && $3=="-F" && $4=="path=/var/log/audit/audit.log" && $5=="-F" && $6=="perm=a") {print $0}'} `

  if [ "$sk" == "" ];then
   
	echo "Logging" >>p1
	echo "/var/log/audit/audit.log/audit/audit.rules" >>p2
	echo "-a_exit-always -F path=/var/log/audit/audit.log -F perm=a_ doesnot exist" >>p3
	echo "no" >>p4
	echo "IZ.20.1.2.3.11" >>p12
else
	echo "Logging" >>p1
	echo "/var/log/audit/audit.log/audit/audit.rules" >>p2
	echo "-a_exit-always -F path=/var/log/audit/audit.log -F perm=a_exist"  >>p3
	echo "yes"  >>p4
	echo "IZ.20.1.2.3.11"  >>p12
fi


  else 

        echo "Logging" >>p1
        echo "/var/log/audit/audit.log/audit/audit.rules" >>p2
        echo "Auditd service is not running.First this service should run and then check the rules" >>p3
        echo "no" >>p4
        echo "IZ.20.1.2.3.11" >>p12
fi


#IZ.20.1.2.3.12	/etc/audit/audit.rules		Rule is set for this path /etc/audit/auditd.conf
#IZ.20.1.2.3.12	/etc/audit/auditd.conf/audit/audit.rules		-a_exit-always -F path=/etc/audit/auditd.conf -F perm=wa_does_not_exist

#IZ.20.1.2.3.12:file-check

systemctl status auditd |grep 'active (running)'


  if [ $? = 0 ] ;then


sk=` cat /etc/audit/audit.rules|awk '{if($1=="-a" && $2=="exit,always" && $3=="-F" && $4=="path=/etc/audit/auditd.conf" && $5=="-F" && $6=="perm=wa") {print $0}'} `

  if [ "$sk" == "" ];then
   
	echo "Logging" >>p1
	echo "/etc/audit/auditd.conf/audit/audit.rules" >>p2
	echo "-a_exit-always -F path=/etc/audit/auditd.conf -F perm=wa_ doesnot exist" >>p3
	echo "no" >>p4
	echo "IZ.20.1.2.3.12" >>p12
else
	echo "Logging" >>p1
	echo "/etc/audit/auditd.conf/audit/audit.rules" >>p2
	echo "-a_exit-always -F path=/etc/audit/auditd.conf -F perm=wa_exist"  >>p3
	echo "yes"  >>p4
	echo "IZ.20.1.2.3.12"  >>p12
fi


  else 

        echo "Logging" >>p1
        echo "/etc/audit/auditd.conf/audit/audit.rules" >>p2
        echo "Auditd service is not running.First this service should run and then check the rules" >>p3
        echo "no" >>p4
        echo "IZ.20.1.2.3.12" >>p12
fi

#IZ.20.1.2.3.13	/etc/audit/audit.rules		Rule is set for this path /etc/audit/audit.rules
#IZ.20.1.2.3.13	/etc/audit/audit.rules/audit/audit.rules		-a_exit-always -F path=/etc/audit//etc/audit/audit.rules-F perm=a_does_not_exist

#IZ.20.1.2.3.13:file-check

systemctl status auditd |grep 'active (running)'


  if [ $? = 0 ] ;then


sk=` cat /etc/audit/audit.rules|awk '{if($1=="-a" && $2=="exit,always" && $3=="-F" && $4=="path=/etc/audit/audit.rules" && $5=="-F" && $6=="perm=wa") {print $0}'} `

  if [ "$sk" == "" ];then
   
	echo "Logging" >>p1
	echo "/etc/audit/audit.rules/audit/audit.rules" >>p2
	echo "-a_exit-always -F path=/etc/audit//etc/audit/audit.rules-F perm=wa_ doesnot exist" >>p3
	echo "no" >>p4
	echo "IZ.20.1.2.3.13" >>p12
else
	echo "Logging" >>p1
	echo "/etc/audit/audit.rules/audit/audit.rules" >>p2
	echo "-a_exit-always -F path=/etc/audit//etc/audit/audit.rules-F perm=wa_exist"  >>p3
	echo "yes"  >>p4
	echo "IZ.20.1.2.3.13"  >>p12
fi


  else 

        echo "Logging" >>p1
        echo "/etc/audit/audit.rules/audit/audit.rules" >>p2
        echo "Auditd service is not running.First this service should run and then check the rules" >>p3
        echo "no" >>p4
        echo "IZ.20.1.2.3.13" >>p12
fi

#IZ.20.1.2.3.14	/etc/audit/audit.rules		Rule is set for this path /sbin/auditctl
#IZ.20.1.2.3.14	/sbin/auditctl/audit/audit.rules		-a_exit-always -F path=/sbin/auditctl -F perm=a_does_not_exist

#IZ.20.1.2.3.14:file-check

systemctl status auditd |grep 'active (running)'


  if [ $? = 0 ] ;then


sk=` cat /etc/audit/audit.rules|awk '{if($1=="-a" && $2=="exit,always" && $3=="-F" && $4=="path=/sbin/auditctl" && $5=="-F" && $6=="perm=a") {print $0}'} `

  if [ "$sk" == "" ];then
   
	echo "Logging" >>p1
	echo "/sbin/auditctl/audit/audit.rules" >>p2
	echo "-a_exit-always -F path=/sbin/auditctl -F perm=a_ doesnot exist" >>p3
	echo "no" >>p4
	echo "IZ.20.1.2.3.14" >>p12
else
	echo "Logging" >>p1
	echo "/sbin/auditctl/audit/audit.rules" >>p2
	echo "-a_exit-always -F path=/sbin/auditctl -F perm=a_exist"  >>p3
	echo "yes"  >>p4
	echo "IZ.20.1.2.3.14"  >>p12
fi


  else 

        echo "Logging" >>p1
        echo "/sbin/auditctl/audit/audit.rules" >>p2
        echo "Auditd service is not running.First this service should run and then check the rules" >>p3
        echo "no" >>p4
        echo "IZ.20.1.2.3.14" >>p12
fi

#IZ.20.1.2.3.15	/etc/audit/audit.rules		Rule is set for this path /sbin/auditd
#IZ.20.1.2.3.15	/sbin/auditd/audit/audit.rules		-a_exit-always -F path=/sbin/auditd -F perm=a_does_not_exist

#IZ.20.1.2.3.15:file-check

systemctl status auditd |grep 'active (running)'


  if [ $? = 0 ] ;then


sk=` cat /etc/audit/audit.rules|awk '{if($1=="-a" && $2=="exit,always" && $3=="-F" && $4=="path=/sbin/auditd" && $5=="-F" && $6=="perm=a") {print $0}'} `

  if [ "$sk" == "" ];then
   
	echo "Logging" >>p1
	echo "/sbin/auditd/audit/audit.rules" >>p2
	echo "-a_exit-always -F path=/sbin/auditd -F perm=a_ doesnot exist" >>p3
	echo "no" >>p4
	echo "IZ.20.1.2.3.15" >>p12
else
	echo "Logging" >>p1
	echo "/sbin/auditd/audit/audit.rules" >>p2
	echo "-a_exit-always -F path=/sbin/auditd -F perm=a_exist"  >>p3
	echo "yes"  >>p4
	echo "IZ.20.1.2.3.15"  >>p12
fi


  else 

        echo "Logging" >>p1
        echo "/sbin/auditd/audit/audit.rules" >>p2
        echo "Auditd service is not running.First this service should run and then check the rules" >>p3
        echo "no" >>p4
        echo "IZ.20.1.2.3.15" >>p12
fi

#IZ.20.1.2.3.16	/etc/audit/audit.rules		Rule is set for this path /sbin/ausearch
#IZ.20.1.2.3.16	/sbin/ausearch/audit/audit.rules		-a_exit-always -F path=/sbin/ausearch -F perm=a_does_not_exist

#IZ.20.1.2.3.16:file-check

systemctl status auditd |grep 'active (running)'


  if [ $? = 0 ] ;then


sk=` cat /etc/audit/audit.rules|awk '{if($1=="-a" && $2=="exit,always" && $3=="-F" && $4=="path=/sbin/ausearch" && $5=="-F" && $6=="perm=a") {print $0}'} `

  if [ "$sk" == "" ];then
   
	echo "Logging" >>p1
	echo "/sbin/ausearch/audit/audit.rules" >>p2
	echo "-a_exit-always -F path=/sbin/ausearch -F perm=a_ doesnot exist" >>p3
	echo "no" >>p4
	echo "IZ.20.1.2.3.16" >>p12
else
	echo "Logging" >>p1
	echo "/sbin/ausearch/audit/audit.rules" >>p2
	echo "-a_exit-always -F path=/sbin/ausearch -F perm=a_exist"  >>p3
	echo "yes"  >>p4
	echo "IZ.20.1.2.3.16"  >>p12
fi


  else 

        echo "Logging" >>p1
        echo "/sbin/ausearch/audit/audit.rules" >>p2
        echo "Auditd service is not running.First this service should run and then check the rules" >>p3
        echo "no" >>p4
        echo "IZ.20.1.2.3.16" >>p12
fi


#IZ.20.1.2.3.17	/etc/audit/audit.rules		Rule is set for this path /etc/syslog.conf
#IZ.20.1.2.3.17	/etc/syslog.conf/audit/audit.rules		-a_exit-always -F path=/etc/syslog.conf -F perm=wa_does_not_exist

#IZ.20.1.2.3.17:file-check

systemctl status auditd |grep 'active (running)'


  if [ $? = 0 ] ;then


sk=` cat /etc/audit/audit.rules|awk '{if($1=="-a" && $2=="exit,always" && $3=="-F" && $4=="path=/etc/syslog.conf" && $5=="-F" && $6=="perm=wa") {print $0}'} `

  if [ "$sk" == "" ];then
   
	echo "Logging" >>p1
	echo "/etc/syslog.conf/audit/audit.rules" >>p2
	echo "-a_exit-always -F path=/etc/syslog.conf -F perm=wa_ doesnot exist" >>p3
	echo "no" >>p4
	echo "IZ.20.1.2.3.17" >>p12
else
	echo "Logging" >>p1
	echo "/etc/syslog.conf/audit/audit.rules" >>p2
	echo "-a_exit-always -F path=/etc/syslog.conf -F perm=wa_exist"  >>p3
	echo "yes"  >>p4
	echo "IZ.20.1.2.3.17"  >>p12
fi


  else 

        echo "Logging" >>p1
        echo "/etc/syslog.conf/audit/audit.rules" >>p2
        echo "Auditd service is not running.First this service should run and then check the rules" >>p3
        echo "no" >>p4
        echo "IZ.20.1.2.3.17" >>p12
fi

#IZ.20.1.2.3.18	/etc/audit/audit.rules		Rule is set for this path /etc/syslog.conf
#IZ.20.1.2.3.18	/etc/syslog.conf/audit/audit.rules		-a_exit-always -F path=/etc/syslog.conf -F perm=wa_does_not_exist

#IZ.20.1.2.3.18:file-check

systemctl status auditd |grep 'active (running)'


  if [ $? = 0 ] ;then


sk=` cat /etc/audit/audit.rules|awk '{if($1=="-a" && $2=="exit,always" && $3=="-F" && $4=="path=/etc/syslog.conf" && $5=="-F" && $6=="perm=wa") {print $0}'} `

  if [ "$sk" == "" ];then
   
	echo "Logging" >>p1
	echo "/etc/syslog.conf/audit/audit.rules" >>p2
	echo "-a_exit-always -F path=/etc/syslog.conf -F perm=wa_ doesnot exist" >>p3
	echo "no" >>p4
	echo "IZ.20.1.2.3.18" >>p12
else
	echo "Logging" >>p1
	echo "/etc/syslog.conf/audit/audit.rules" >>p2
	echo "-a_exit-always -F path=/etc/syslog.conf -F perm=wa_exist"  >>p3
	echo "yes"  >>p4
	echo "IZ.20.1.2.3.18"  >>p12
fi


  else 

        echo "Logging" >>p1
        echo "/etc/syslog.conf/audit/audit.rules" >>p2
        echo "Auditd service is not running.First this service should run and then check the rules" >>p3
        echo "no" >>p4
        echo "IZ.20.1.2.3.18" >>p12
fi


#IZ.20.1.2.3.19:file-check

systemctl status auditd |grep 'active (running)'


  if [ $? = 0 ] ;then


sk=`cat /etc/audit/audit.rules|awk '{if($1=="-a" && $2=="exit,always" && $3=="-F" && $4=="path=/etc/snmp/snmpd.conf" && $5=="-F" && $6=="perm=wa") {print $0}'}`

  if [ "$sk" == "" ];then
   
	echo "Logging" >>p1
	echo "/etc/syslog.conf/audit/audit.rules" >>p2
	echo "-a_exit-always -F path=/etc/snmp/snmpd.conf -F perm=wa_ doesnot exist" >>p3
	echo "no" >>p4
	echo "IZ.20.1.2.3.19" >>p12
else
	echo "Logging" >>p1
	echo "/etc/syslog.conf/audit/audit.rules" >>p2
	echo "-a_exit-always -Fpath=/etc/snmp/snmpd.conf -F perm=wa_exist"  >>p3
	echo "yes"  >>p4
	echo "IZ.20.1.2.3.19"  >>p12
fi


  else 

        echo "Logging" >>p1
        echo "/etc/syslog.conf/audit/audit.rules" >>p2
        echo "Auditd service is not running.First this service should run and then check the rules" >>p3
        echo "no" >>p4
        echo "IZ.20.1.2.3.19" >>p12
fi


#IZ.20.1.2.3.20:file-check

systemctl status auditd |grep 'active (running)'


  if [ $? = 0 ] ;then


sk=`cat /etc/audit/audit.rules|awk '{if($1=="-a" && $2=="exit,always" && $3=="-F" && $4=="path=/etc/snmp/snmpd.conf" && $5=="-F" && $6=="perm=wa") {print $0}'}`

  if [ "$sk" == "" ];then
   
	echo "Logging" >>p1
	echo "/etc/syslog.conf/audit/audit.rules" >>p2
	echo "-a_exit-always -F path=/etc/snmp/snmpd.conf -F perm=wa_ doesnot exist" >>p3
	echo "no" >>p4
	echo "IZ.20.1.2.3.20" >>p12
else
	echo "Logging" >>p1
	echo "/etc/syslog.conf/audit/audit.rules" >>p2
	echo "-a_exit-always -F path=/etc/snmp/snmpd.conf -F perm=wa_exist"  >>p3
	echo "yes"  >>p4
	echo "IZ.20.1.2.3.20"  >>p12
fi


  else 

        echo "Logging" >>p1
        echo "/etc/syslog.conf/audit/audit.rules" >>p2
        echo "Auditd service is not running.First this service should run and then check the rules" >>p3
        echo "no" >>p4
        echo "IZ.20.1.2.3.20" >>p12
fi



#IZ.20.1.2.3.21:file-check

systemctl status auditd |grep 'active (running)'


  if [ $? = 0 ] ;then


sk=`cat /etc/audit/audit.rules|awk '{if($1=="-a" && $2=="exit,always" && $3=="-F" && $4=="path=/etc/snmp/snmpd.conf" && $5=="-F" && $6=="perm=wa") {print $0}'}`

  if [ "$sk" == "" ];then
   
	echo "Logging" >>p1
	echo "/etc/syslog.conf/audit/audit.rules" >>p2
	echo "-a_exit-always -F path=/etc/snmp/snmpd.conf -F perm=wa_ doesnot exist" >>p3
	echo "no" >>p4
	echo "IZ.20.1.2.3.21" >>p12
else
	echo "Logging" >>p1
	echo "/etc/syslog.conf/audit/audit.rules" >>p2
	echo "-a_exit-always -F path=/etc/snmp/snmpd.conf -F perm=wa_exist"  >>p3
	echo "yes"  >>p4
	echo "IZ.20.1.2.3.21"  >>p12
fi


  else 

        echo "Logging" >>p1
        echo "/etc/syslog.conf/audit/audit.rules" >>p2
        echo "Auditd service is not running.First this service should run and then check the rules" >>p3
        echo "no" >>p4
        echo "IZ.20.1.2.3.21" >>p12
fi


#IZ.20.1.2.3.22:file-check

systemctl status auditd |grep 'active (running)'


  if [ $? = 0 ] ;then


sk=`cat /etc/audit/audit.rules|awk '{if($1=="-a" && $2=="exit,always" && $3=="-F" && $4=="path=/etc/snmp/snmpd.conf" && $5=="-F" && $6=="perm=wa") {print $0}'}`

  if [ "$sk" == "" ];then
   
	echo "Logging" >>p1
	echo "/etc/syslog.conf/audit/audit.rules" >>p2
	echo "-a_exit-always -F path=/etc/snmp/snmpd.conf -F perm=wa_ doesnot exist" >>p3
	echo "no" >>p4
	echo "IZ.20.1.2.3.22" >>p12
else
	echo "Logging" >>p1
	echo "/etc/syslog.conf/audit/audit.rules" >>p2
	echo "-a_exit-always -F path=/etc/snmp/snmpd.conf -F perm=wa_exist"  >>p3
	echo "yes"  >>p4
	echo "IZ.20.1.2.3.22"  >>p12
fi


  else 

        echo "Logging" >>p1
        echo "/etc/syslog.conf/audit/audit.rules" >>p2
        echo "Auditd service is not running.First this service should run and then check the rules" >>p3
        echo "no" >>p4
        echo "IZ.20.1.2.3.22" >>p12
fi



#IZ.20.1.2.3.23:file-check

systemctl status auditd |grep 'active (running)'
if [ $? = 0 ] ;then

sk=`cat /etc/audit/audit.rules|awk '{if($1=="-a" && $2=="exit,always" && $3=="-F" && $4=="path=/etc/snmp/snmpd.conf" && $5=="-F" && $6=="perm=wa") {print $0}'}`

  if [ "$sk" == "" ];then
   
	echo "Logging" >>p1
	echo "/etc/syslog.conf/audit/audit.rules" >>p2
	echo "-a_exit-always -F path=/etc/snmp/snmpd.conf -F perm=wa_ doesnot exist" >>p3
	echo "no" >>p4
	echo "IZ.20.1.2.3.23" >>p12
else
	echo "Logging" >>p1
	echo "/etc/syslog.conf/audit/audit.rules" >>p2
	echo "-a_exit-always -F path=/etc/snmp/snmpd.conf -F perm=wa_exist"  >>p3
	echo "yes"  >>p4
	echo "IZ.20.1.2.3.23"  >>p12
fi


else 

        echo "Logging" >>p1
        echo "/etc/syslog.conf/audit/audit.rules" >>p2
        echo "Auditd service is not running.First this service should run and then check the rules" >>p3
        echo "no" >>p4
        echo "IZ.20.1.2.3.23" >>p12
fi


#IZ.20.1.2.4
if [ -f /etc/sudoers ]
then
    #p=`grep "ALL=(ALL) NOPASSWD: /sbin/ausearch" /etc/sudoers`
         p=`cat /etc/sudoers |grep ausearch |awk '{print $2}'|grep -w ALL|wc -l`
         q=`cat /etc/sudoers |grep ausearch |awk -F= '{print $2}'|awk -F: '{print $1}' |grep "ALL" |grep -w NOPASSWD|wc -l`
         r=`cat /etc/sudoers |grep ausearch |awk -F= '{print $2}'|awk -F: '{print $2}' |grep -w "/sbin/ausearch"|wc -l`


    if [ $p -ne 0 ] &&  [ $q -ne 0 ]  &&  [ $r -ne 0 ]
    then
        echo "Logging" >>p1
        echo "Ensure /etc/sudoers must contain ALL=(ALL) NOPASSWD: /sbin/ausearch" >>p2
        echo "/etc/sudoers contains ALL=(ALL) NOPASSWD: /sbin/ausearch" >>p3
        echo "yes" >>p4
        echo "IZ.20.1.2.4" >>p12
        echo "$z">>p6
        echo "$c">>p5
        
    else
        echo "Logging" >>p1
        echo "Ensure /etc/sudoers must contain ALL=(ALL) NOPASSWD: /sbin/ausearch" >>p2
        echo "/etc/sudoers does not contain ALL=(ALL) NOPASSWD: /sbin/ausearch" >>p3
        echo "no" >>p4
        echo "IZ.20.1.2.4" >>p12
        echo "$z" >>p6
        echo "$c" >>p5
        
    fi
else
    echo "Logging" >>p1
    echo "Ensure /etc/sudoers must contain ALL=(ALL) NOPASSWD: /sbin/ausearch" >>p2
    echo "File /etc/sudoers not exists" >> p3
    echo "No">>p4
    echo "IZ.20.1.2.4" >>p12
        echo "$z" >> p6
        echo "$c" >> p5
        
fi

###################################################################################################################



##############################################################################################################
echo -e "ACCOUNT:$accountName-$accountID \nTechSpec Version: $techSpecVersion \nCustomisation Date: $customisedDate \nScan Version: $scanVersion\nFQDN:$fqdn \nIP-ADDRESS:$ipAddress \nOS-NAME: $osName \nScan-Date: $c\nTime-Stamp: $timestamp\n*************************************************************************************" > `hostname`_Linux_SSH_SUDO$c_mhc.csv
paste -d "|" p12 p1 p2 p3 p4   >> `hostname`_Linux_SSH_SUDO$c_mhc.csv
chmod 644 `hostname`_Linux_SSH_SUDO$c_mhc.csv
rm -rf temp_shadow temp_shadow1 temp1_shadow temp_shadow2 temp_shadow3 temp-ud psw_temp temp_uid temp_uid1 temp_gid temp_gid1 pasd_temp en1 en2 en3 en4 p5 p4 p3 p2 p1 p6 p12 f1 t1 temp_pam.so world-writable-test log_file1 temp_id file1 ff2 e1 e2 e3 e4 e5 e6 temp_home user
else
echo "Error: The parameter file hc_scan_parameter not found. Please copy the file hc_scan_parameter into same location where HC scan script is available, then run the script again."
fi
