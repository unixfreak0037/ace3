#!/usr/bin/env bash
#
# ensures all the files and directories that are needed exist
# and waits for the database connection to become available
# this file is sourced from every other startup file
#

cd /opt/ace
source /venv/bin/activate
source load_environment

# do we need to create fake ssl certificates?
if [ ! -f ssl/ace.cert.pem ]
then
    echo "installing self-signed SSL certificates"
    mkdir -p ssl
    openssl req \
        -x509 \
        -newkey rsa:4096 \
        -keyout ssl/ace.key.pem \
        -out ssl/ace.cert.pem \
        -sha256 \
        -days 3650 \
        -nodes \
        -subj "/C=US/ST=Ohio/L=Springfield/O=CompanyName/OU=CompanySectionName/CN=ace.local"

    cp ssl/ace.cert.pem ssl/ca-chain-combined.cert.pem
    cp ssl/ace.cert.pem ssl/ca-chain.cert.pem

    cp ssl/ace.key.pem ssl/mysql.key.pem
    cp ssl/ace.cert.pem ssl/mysql.cert.pem

    # Set proper permissions for SSL files
    chmod 600 ssl/ace.key.pem
    chmod 644 ssl/ace.cert.pem
    chmod 644 ssl/ca-chain-combined.cert.pem
    chmod 644 ssl/ca-chain.cert.pem

    cp ssl/ace.key.pem ssl/mysql.key.pem
    cp ssl/ace.cert.pem ssl/mysql.cert.pem

    chmod 644 ssl/mysql.key.pem
    chmod 644 ssl/mysql.cert.pem
fi

# prepare SQL files

if [ ! -f /docker-entrypoint-initdb.d/done ]
then
    bin/initialize_database.py 
fi

# TOOD
# initialize gitconfig

# TODO
# initialize git repos here?

#
# make sure all these directories and files exist
#

for dir in \
    error_reports \
    logs \
    var \
    scan_failures \
    storage \
    stats/modules/ace \
    archive/email \
    archive/smtp_stream \
    archive/office \
    archive/ole \
    work \
    etc \
    external/analyst-data
do
    if [ ! -d data/$dir ]
    then
        echo "creating directory data/$dir"
        mkdir -p data/$dir
    fi
done

for path in data/etc/site_tags.csv data/etc/ssdeep_hashes
do
	if [ ! -e "${path}" ]; then touch "${path}"; fi
done

bin/initialize_misc.sh

# TODO get rid of these
if [ ! -e data/etc/organization.json ]; then echo '{}' > data/etc/organization.json; fi
if [ ! -e data/etc/local_networks.csv ]; then echo 'Indicator,Indicator_Type' > data/etc/local_networks.csv; fi

# TODO mount this!
#if [ ! -e /home/ace/.vimrc ]; then cp etc/vimrc /home/ace/.vimrc; fi
#if [ ! -e /home/ace/.screenrc ]; then cp etc/screenrc /home/ace/.screenrc; fi
#if [ ! -e /home/ace/.vscode-server/extensions ]; then mkdir -p /home/ace/.vscode-server/extensions; fi
#if [ ! -e /home/ace/.vscode-server/extensionsCache ]; then mkdir -p /home/ace/.vscode-server/extensionsCache; fi

# target integration configuration
#if [ -e etc/saq.integrations.$ACE_TARGET.ini ]
#then
    #cp etc/saq.integrations.$ACE_TARGET.ini data/etc/saq.integrations.ini
#fi

# make sure we've got our SSH creds for github
#if [ ! -e ~/.ssh/id_rsa ]
#then
    #mkdir -p ~/.ssh && tar -C ~/.ssh -zxf mnt/ssh.$ACE_TARGET/ssh.creds.tar.gz && chmod 400 ~/.ssh/id_rsa
#fi

#if [ ! -e ~/.ssh/known_hosts ]
#then
    #cp mnt/ssh.$ACE_TARGET/known_hosts ~/.ssh/known_hosts
#fi