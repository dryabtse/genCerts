#!/bin/bash

# Initialize variables to some default values or empty strings
keepRoot=false
keepCA=false
keepAll=false

function usage
{
     echo "Usage: `basename $0` [ [--keepRoot] [--keepCA] [--keepAll] ] [--help]"
	 echo "       --keepRoot   preserve the Root CA, regenerate everything else"
	 echo "       --keepCA     preserve the Intermediate CAs, regenerate everything else"
	 echo "       --keepAll    preserve everything but the host certificates"
	 echo "       --help       shows this output"
}

# Parse named arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --keepRoot) keepRoot=true; shift ;; 
        --keepCA) keepCA=true; shift ;;
        --keepAll) keepAll=true; shift ;;
		--help) usage; exit 0;;
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

if [ "$keepCA" = true ]
then
    keepRoot=true
fi

if [ "$keepAll" = true ]
then
    keepRoot=true
    keepCA=true
fi

CONFIG_TEMPLATE_NAME=root-ca.cfg
HOSTNAMES_FILE=hostnames
ROOT_CA_DIR=RootCA

function testFilePattern {
	if compgen -G "$PWD/$1" > /dev/null
	then
	    return 1
	else
	    return 0
	fi
}

function mkRoot {
	echo "Creatng a self signed root cert ..."
	openssl genrsa -out rootCA.key 2048
	openssl req -x509 -new -nodes -key rootCA.key -days 1460 -out rootCA.crt -subj "/C=AU/ST=NSW/L=Sydney/O=MongoDB/OU=TS/CN=dmntest.com"
	mkdir RootCA
	mkdir RootCA/ca.db.certs
	echo "01" >> RootCA/ca.db.serial
	touch RootCA/ca.db.index
	echo $RANDOM >> RootCA/ca.db.rand
	mv root* RootCA/
}

function backup {
	echo "Backing up the prevous setup ..."
	ts=`date +"%Y-%m-%dT%T"`
	backupDir=bak.$ts
	mkdir $backupDir
	if [ "$keepRoot" = false ]
	then
	    backupRoot $backupDir
	fi
	if [ "$keepCA" = false ]
	then
	    backupCAs $backupDir
	fi
	if [ "$keepAll" = false ]
	then
	    backupClient $backupDir
	fi
	backupConfig $backupDir
	backupHosts $backupDir
	# backupElse $backupDir
	echo "Backup saved under $backupDir"
}

function backupRoot {
	backupDir=$1
	echo "   ⌞Backing up the Root CA into $backupDir ..."
	if [ -d "$PWD/$backupDir" ]
	then
	    if [ -d "$PWD/RootCA" ]
		then
            mv RootCA $backupDir
		fi
	else
	    echo "${FUNCNAME[*]} ERROR: Provided backup directory $backupDir does not exist. Exiting ..."
		exit 1
	fi
}

function backupConfig {
	backupDir=$1
	echo "   ⌞Backing up the config file into $backupDir ..."
	if [ -d "$PWD/$backupDir" ]
	then
	    if [ -f "$PWD/$CONFIG_TEMPLATE_NAME" ]
		then
            mv $CONFIG_TEMPLATE_NAME $backupDir
		fi
	else
	    echo "${FUNCNAME[*]} ERROR: Provided backup directory $backupDir does not exist. Exiting ..."
		exit 1
	fi
}

function backupCAs {
	backupDir=$1
	pattern=("SigningCA*" "CA.pem")
	echo "   ⌞Backing up the Intermediate CAs into $backupDir ..."
	if [ -d "$PWD/$backupDir" ]
	then
	    for p in ${pattern[@]}
		do
	        testFilePattern $p
			if [ $? -eq 1 ]
			then
			    mv $p $backupDir
			fi
		done 
	else
	    echo "  ⌞${FUNCNAME[*]} ERROR: Provided backup directory $backupDir does not exist. Exiting ..."
		exit 1
	fi
}

function backupClient {
	backupDir=$1
	pattern="client.*"
	echo "   ⌞Backing up the client material into $backupDir ..."
	if [ -d "$PWD/$backuDir" ]
	then
	    testFilePattern "$pattern"
		if [ $? -eq 1 ]
		then
            mv client.* $backupDir
		else
		    echo "No matching files found"
		fi
	else
	    echo "  ⌞${FUNCNAME[*]} ERROR: Provided backup directory $backupDir does not exist. Exiting ..."
		exit 1
	fi
}

function backupHosts {
	backupDir=$1
	echo "   ⌞Backing up the hosts material into $backupDir ..."
	if [ -d "$PWD/$backupDir" ]
	then
		if [ -f "$HOSTNAMES_FILE" ]
		then
			for i in `cat hostnames | grep -v ^# | awk '{ print $1}'`
			do
			    testFilePattern $i
				if [ $? -eq 1 ]
				then
				    mv $i.* $backupDir
				else
				    echo "No matching files found for the $i hostname"
				fi
			done
		fi
	else
	    echo "  ⌞${FUNCNAME[*]} ERROR: Provided backup directory $backupDir does not exist. Exiting ..."
		exit 1
	fi
}

function backupElse {
	backupDir=$1
	listCmd="ls -1 *.csr *.crt *.pem *.key"
	backupCmd="mv *.csr *.crt *.pem *.key $backupDir"
	echo "   ⌞Backing up everything else into $backupDir ..."
	if [ -d "$PWD/$backupDir" ]
	then
		$listCmd > /dev/null 2>&1
		if [ $? -eq 0 ]
		then
			numFiles=`$listCmd | wc -l`
			if [ $numFiles -gt 0 ]
			then
				$backupCmd
			fi
		fi
	else
	    echo "  ⌞${FUNCNAME[*]} ERROR: Provided backup directory $backupDir does not exist. Exiting ..."
		exit 1
	fi
}

function genConfig {
	echo "Generating a new config template ..."
	cat >> $CONFIG_TEMPLATE_NAME <<EOF
[ RootCA ]
dir		= ./RootCA
certs		= \$dir/ca.db.certs
database	= \$dir/ca.db.index
new_certs_dir	= \$dir/ca.db.certs
certificate	= \$dir/rootCA.crt
serial		= \$dir/ca.db.serial
private_key	= \$dir/rootCA.key
RANDFILE	= \$dir/ca.db.rand
default_md	= sha256
default_days	= 365
default_crl_days= 30
email_in_dn	= no
unique_subject	= no
policy		= policy_match

[ SigningCA1 ]
dir		= ./SigningCA1
certs		= \$dir/ca.db.certs
database	= \$dir/ca.db.index
new_certs_dir	= \$dir/ca.db.certs
certificate	= \$dir/signing-ca-1.crt
serial		= \$dir/ca.db.serial
private_key	= \$dir/signing-ca-1.key
RANDFILE	= \$dir/ca.db.rand
default_md	= sha256
default_days	= 365
default_crl_days= 30
email_in_dn	= no
unique_subject	= no
policy		= policy_match

[ SigningCA2 ]
dir		= ./SigningCA2
certs		= \$dir/ca.db.certs
database	= \$dir/ca.db.index
new_certs_dir	= \$dir/ca.db.certs
certificate	= \$dir/signing-ca-2.crt
serial		= \$dir/ca.db.serial
private_key	= \$dir/signing-ca-2.key
RANDFILE	= \$dir/ca.db.rand
default_md	= sha256
default_days	= 365
default_crl_days= 30
email_in_dn	= no
unique_subject	= no
policy		= policy_match

[ policy_match ]
countryName		= match
stateOrProvinceName	= match
localityName		= match
organizationName	= match
organizationalUnitName	= optional
commonName		= supplied
emailAddress		= optional

[ v3_req_cl ]
basicConstraints	= CA:FALSE
keyUsage		= nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage	= clientAuth

[ v3_ca ]
subjectKeyIdentifier	= hash
authorityKeyIdentifier	= keyid:always,issuer:always
basicConstraints	= CA:true

[ v3_req_srv ]
basicConstraints	= CA:FALSE
keyUsage		= nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage	= serverAuth, clientAuth
EOF
}

function genCAs {
	echo "Generating 2 signing CAs ..."
	index=1
	openssl genrsa -out signing-ca-${index}.key 2048
	openssl req -new -key signing-ca-${index}.key \
		-out signing-ca-${index}.csr -subj "/C=AU/ST=NSW/L=Sydney/O=MongoDB/OU=COE/CN=ClientsCA"
	openssl ca -batch -name RootCA -days 1460 -config $CONFIG_TEMPLATE_NAME -extensions v3_ca \
		-out signing-ca-${index}.crt \
		-infiles signing-ca-${index}.csr

	mkdir SigningCA${index}
	mkdir SigningCA${index}/ca.db.certs
	echo "01" >> SigningCA${index}/ca.db.serial
	touch SigningCA${index}/ca.db.index
	# Should use a better source of random here..
	echo $RANDOM >> SigningCA${index}/ca.db.rand
	mv signing-ca-${index}* SigningCA${index}/
	
	# repeat with...
	index=2
	openssl genrsa -out signing-ca-${index}.key 2048
	openssl req -new -key signing-ca-${index}.key \
		-out signing-ca-${index}.csr -subj "/C=AU/ST=NSW/L=Sydney/O=MongoDB/OU=TS/CN=ServersCA"
	openssl ca -batch -name RootCA -days 1460 -config $CONFIG_TEMPLATE_NAME -extensions v3_ca \
		-out signing-ca-${index}.crt \
		-infiles signing-ca-${index}.csr

	mkdir SigningCA${index}
	mkdir SigningCA${index}/ca.db.certs
	echo "01" >> SigningCA${index}/ca.db.serial
	touch SigningCA${index}/ca.db.index
	# Should use a better source of random here..
	echo $RANDOM >> SigningCA${index}/ca.db.rand
	mv signing-ca-${index}* SigningCA${index}/

	cat RootCA/rootCA.crt SigningCA1/signing-ca-1.crt SigningCA2/signing-ca-2.crt > CA.pem
}

function signServerCerts {
	echo "Signing Server certificates ..."
	if [ -f "$HOSTNAMES_FILE" ]
	then
		while read -r line
		do
			[[ "$line" =~ ^#.*$ ]] && continue
			hostname=`echo $line | awk '{ print $1 }'`
			IP=`echo $line | awk '{ print $2 }'`
			echo $hostname $IP
			openssl genrsa -out $hostname.key 2048
			export SAN=DNS:$hostname,IP:$IP
			echo "subjectAltName=\${ENV::SAN}" >> $CONFIG_TEMPLATE_NAME
			openssl req -new -key $hostname.key -out $hostname.csr \
				-subj "/C=AU/ST=NSW/L=Sydney/O=MongoDB/OU=mongodb/CN=$hostname"
			openssl ca -batch -name SigningCA2 -days 1460 -config $CONFIG_TEMPLATE_NAME -extensions v3_req_srv -out $hostname.crt \
				-infiles $hostname.csr
			# Create the .pem file with the certificate and private key
			cat $hostname.crt $hostname.key >> $hostname.pem
		done < hostnames
	else
	    echo "The $HOSTNAMES_FILE is not present. Skipping this step ..."
	fi
}

function signClientCert {
	echo "Generating client cert ..."
	openssl genrsa -out client.key 2048
	openssl req -new -key client.key -out client.csr \
		-subj "/C=AU/ST=NSW/L=Sydney/O=MongoDB/OU=COE/CN=client"
	openssl ca -batch -name SigningCA1 -days 1460 -config root-ca.cfg -extensions v3_req_cl -out client.crt \
		-infiles client.csr
	# Create the .pem file with the certificate and private key
	cat client.crt client.key >> client.pem
}

backup
if [ "$keepRoot" = false ]
then
    mkRoot
fi
genConfig

if [ "$keepCA" = false ]
then
    genCAs
fi
signServerCerts

if [ "$keepAll" = false ]
then
    signClientCert
fi
