#!/bin/bash
#Author: M.Fevzi Korkutata | Last day of 2017 (New year PARTY script)

function echo_err()
{
  >&2 echo "$1"
}

function usage()
{
  echo_err "$0 <trustStoreFile> <trustStorePassPhrase> <keystoreType> <!-- <thresholdDays> -->"
  echo_err "for Example: $0 /home/user/security/trust.jks mytrustpassword JKS 45"
  exit 1
}

function validateAndReadArgs()
{
    if [ $# -lt 2 ];
    then
        echo_err "[ERROR]: invalid arguments"
        usage
    fi

    if [ -z "$JAVA_HOME" ];
    then
      echo_err "[ERROR]: JAVA_HOME is not set. Please set JAVA_HOME and try again".
      exit 1
    fi

    readArgs "$@"
}

function readArgs()
{
  __keystore="$1"
  __keystorepass="$2"
  __keystoretype="$3"
  __thresholdDay="$4"


    if [ ! -f "$__keystore" ];
    then
        echo_err "[ERROR]: Keystore File $__keystore not found."
        exit 1
    fi

    if [ -z "$__keystoretype" ];
    then
        __keystoretype="$__defaultKeyStoreType"
    fi

    if [ -z "$__thresholdDay" ];
    then
        __thresholdDay="$__defaultThresholdDay"
    fi

    echo "keystore    : $__keystore"
    echo "keystoretype: $__keystoretype"
    echo "thresholdDay: $__thresholdDay"
}

function cleanup()
{
    #create dir for holding messages
    mkdir -p $__scriptPath/msgtemplates
    rm -rf $__scriptPath/msgtemplates/*
}


function validateCerts()
{
    #Flush output values
    echo -n > $__scriptPath/msgtemplates/certificateStatus.txt
    echo -n > $__scriptPath/msgtemplates/certificateExpireWarning.txt
    echo -n > $__scriptPath/msgtemplates/certificateSummary.txt

    rm -rf $__scriptPath/output.txt
    $__keytool -list -v -keystore $__keystore -storetype $__keystoretype -storepass $__keystorepass > $__scriptPath/output.txt

    if [ $? != 0 ];
    then
        errorOutput=$(cat $__scriptPath/output.txt)
        echo_err "[ERROR]: $errorOutput"
        rm -rf $__scriptPath/output.txt
        exit 1
    fi

    rm -rf $__scriptPath/output.txt

    #Fetch certificate "until"  dates
    for i in $($__keytool -list -v -keystore $__keystore -storetype $__keystoretype -storepass $__keystorepass | grep 'Alias name:' | perl -ne 'if(/name: (.*?)\n/) { print "$1\n"; }')
    do
        echo "$i valid until: "$($__keytool -list -v -keystore $__keystore -storepass $__keystorepass -alias "$i" | grep 'Valid from' | head -1 | perl -ne 'if(/until: (.*?)\n/) { print "$1\n"; }') >> $__scriptPath/msgtemplates/certificateStatus.txt
    done

    #Calculate certificate remaining days
    __lc=$(cat $__scriptPath/msgtemplates/certificateStatus.txt | wc -l)
    for (( c=1 ; c<=$__lc ; c++ ))
    do
        __alias=$(awk "NR==$c" $__scriptPath/msgtemplates/certificateStatus.txt | awk '{print $1}')
        __until=$(awk "NR==$c" $__scriptPath/msgtemplates/certificateStatus.txt | perl -ne 'if(/until: (.*?)\n/) { print "$1\n"; }')
        #echo $__until

        __untilSeconds=`date -d "$__until" +%s`
        __remainingDays=$(( ($__untilSeconds -  $(date +%s)) / 60 / 60 / 24 ))

        if [ $__threshold -le $__untilSeconds ]; then
                #printf "[OK]         ===> $__alias <===  Certificate '$__alias' expires on '$__until'! *** $__remainingDays day(s) remaining ***\n\n"
                printf "[OK]         ===> $__alias <===  Certificate '$__alias' expires on '$__until'! *** $__remainingDays day(s) remaining ***\n\n" >> $__scriptPath/msgtemplates/certificateSummary.txt
        elif [ $__remainingDays -le 0 ]; then
            #printf "[CRITICAL]   ===> $__alias <===  !!! Certificate '$__alias' has already expired !!!\n"
            printf "[CRITICAL]   ===> $__alias <===  !!! Certificate '$__alias' has already expired !!!\n" >> $__scriptPath/msgtemplates/certificateSummary.txt

        else
            #printf "[WARNING]    ===> $__alias <===  Certificate '$__alias' expires on '$__until'! *** $__remainingDays day(s) remaining ***\n\n"
            printf "[WARNING]    ===> $__alias <===  Certificate '$__alias' expires on '$__until'! *** $__remainingDays day(s) remaining ***\n\n" >> $__scriptPath/msgtemplates/certificateSummary.txt
            printf "[WARNING]    ===> $__alias <===  Certificate '$__alias' expires on '$__until'! *** $__remainingDays day(s) remaining ***\n\n" >> $__scriptPath/msgtemplates/certificateExpireWarning.txt
        fi
    done
}

#send alerts
function sendAlerts()
{
    __lcCES=$(cat $__scriptPath/msgtemplates/certificateSummary.txt | wc -l)

    if [ $__lcCES == 0 ]; 
    then
        echo_err "!!! [ERROR] Error in reading certification summary. Please ensure that you have provided valid information !!!"
        exit 1
    fi

    __lcCEW=$(cat $__scriptPath/msgtemplates/certificateExpireWarning.txt | wc -l)
    if [ $__lcCEW -gt 0 ]; then
        (echo_err "!!! [WARNING] Check expired certificates !!!")
        (echo_err "$(cat $__scriptPath/msgtemplates/certificateExpireWarning.txt)")
        #Comment out if you want to send as WARNING email.
        #cat $__scriptPath/msgtemplates/certificateExpireWarning.txt $__scriptPath/msgtemplates/certificateSummary.txt | /sbin/sendmail -s "!!! [WARNING] Check expired certificates !!!" $__mailTo

        emailBody=$(cat $__scriptPath/msgtemplates/certificateExpireWarning.txt)

/usr/sbin/sendmail -oi -t << EOF
From:  
To: $__mailTo 
Subject: Certificate Expiry Reminder

$emailBody
EOF
	    exit 1
    else
        echo "Script executed successfully! Certificates are OK!"
        echo " "
        echo "##################################################"
        cat $__scriptPath/msgtemplates/certificateSummary.txt
	    exit 0
    fi
}


#Change environment variables:
__scriptPath=$(dirname $0)

source $__scriptPath/monitor.properties

validateAndReadArgs "$@"

#Static Variables
__keytool="$JAVA_HOME/bin/keytool"
__currentDate=$(date +%s)
__threshold=$(($__currentDate + ($__thresholdDay*24*60*60)))

cleanup
validateCerts
sendAlerts