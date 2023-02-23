CONFIG_TEMPLATE_NAME=root-ca.cfg

function mkRoot {
	echo "Creatng a self signed root cert..."
	openssl genrsa -out rootCA.key 2048
	openssl req -x509 -new -nodes -key rootCA.key -days 365 -out rootCA.crt -subj "/C=AU/ST=NSW/L=Sydney/O=MongoDB/OU=TS/CN=dmntest.com"
	mkdir RootCA
	mkdir RootCA/ca.db.certs
	echo "01" >> RootCA/ca.db.serial
	touch RootCA/ca.db.index
	echo $RANDOM >> RootCA/ca.db.rand
	mv root* RootCA/
}

function backup {
	echo "Backing up the prevous setup..."
	ts=`date +"%Y-%m-%dT%T"`
	mkdir bak.$ts
	mv *.csr *.crt *.pem *.key RootCA SigningCA* *root-ca.cfg bak.$ts
	echo "Backup saved under bak.$ts"
}

function genConfig {
	echo "Generating a new config template..."
	cat >> $CONFIG_TEMPLATE_NAME <<EOF
[ RootCA ]
dir             = ./RootCA
certs           = \$dir/ca.db.certs
database        = \$dir/ca.db.index
new_certs_dir   = \$dir/ca.db.certs
certificate     = \$dir/rootCA.crt
serial          = \$dir/ca.db.serial
private_key     = \$dir/rootCA.key
RANDFILE        = \$dir/ca.db.rand
default_md      = sha256
default_days    = 365
default_crl_days= 30
email_in_dn     = no
unique_subject  = no
policy          = policy_match

[ SigningCA1 ]
dir             = ./SigningCA1
certs           = \$dir/ca.db.certs
database        = \$dir/ca.db.index
new_certs_dir   = \$dir/ca.db.certs
certificate     = \$dir/signing-ca-1.crt
serial          = \$dir/ca.db.serial
private_key     = \$dir/signing-ca-1.key
RANDFILE        = \$dir/ca.db.rand
default_md      = sha256
default_days    = 365
default_crl_days= 30
email_in_dn     = no
unique_subject  = no
policy          = policy_match

[ SigningCA2 ]
dir             = ./SigningCA2
certs           = \$dir/ca.db.certs
database        = \$dir/ca.db.index
new_certs_dir   = \$dir/ca.db.certs
certificate     = \$dir/signing-ca-2.crt
serial          = \$dir/ca.db.serial
private_key     = \$dir/signing-ca-2.key
RANDFILE        = \$dir/ca.db.rand
default_md      = sha256
default_days    = 365
default_crl_days= 30
email_in_dn     = no
unique_subject  = no
policy          = policy_match

[ policy_match ]
countryName     = match
stateOrProvinceName = match
localityName            = match
organizationName    = match
organizationalUnitName  = optional
commonName      = supplied
emailAddress        = optional

[ v3_req_cl ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth

[ v3_ca ]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer:always
basicConstraints = CA:true

[ v3_req_srv ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
EOF
}


function genCAs {
	echo "Generating 2 signing CAs..."
	index=1
	openssl genrsa -out signing-ca-${index}.key 2048
	openssl req -new -days 1460 -key signing-ca-${index}.key \
		-out signing-ca-${index}.csr -subj "/C=AU/ST=NSW/L=Sydney/O=MongoDB/OU=TS/CN=ClientsCA"
	openssl ca -batch -name RootCA -config $CONFIG_TEMPLATE_NAME -extensions v3_ca \
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
	openssl req -new -days 1460 -key signing-ca-${index}.key \
		-out signing-ca-${index}.csr -subj "/C=AU/ST=NSW/L=Sydney/O=MongoDB/OU=TS/CN=ServersCA"
	openssl ca -batch -name RootCA -config $CONFIG_TEMPLATE_NAME -extensions v3_ca \
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
	echo "Signing Server certificates..."
	while read -r line
	do
		hostname=`echo $line | awk '{ print $1 }'`
		IP=`echo $line | awk '{ print $2 }'`
		echo $hostname $IP
		openssl genrsa -out $hostname.key 2048
		export SAN=DNS:$hostname,IP:$IP
		echo "subjectAltName=\${ENV::SAN}" >> $CONFIG_TEMPLATE_NAME
		openssl req -new -days 365 -key $hostname.key -out $hostname.csr \
			-subj "/C=AU/ST=NSW/L=Sydney/O=MongoDB/OU=mongodb/CN=$hostname"
		openssl ca -batch -name SigningCA2 -config $CONFIG_TEMPLATE_NAME -extensions v3_req_srv -out $hostname.crt \
			-infiles $hostname.csr
		# Create the .pem file with the certificate and private key
		cat $hostname.crt $hostname.key >> $hostname.pem
	done < hostnames
}

function signClientCert {
	echo "Generating client cert..."
	openssl genrsa -out client.key 2048
	openssl req -new -days 365 -key client.key -out client.csr \
		-subj "/C=AU/ST=NSW/L=Sydney/O=MongoDB/CN=client"
	openssl ca -batch -name SigningCA1 -config root-ca.cfg -extensions v3_req_cl -out client.crt \
		-infiles client.csr
	# Create the .pem file with the certificate and private key
	cat client.crt client.key >> client.pem
}

backup
mkRoot
genConfig
genCAs
signServerCerts
signClientCert
