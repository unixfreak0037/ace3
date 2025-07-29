FROM python:3.12-bookworm

# Add metadata labels
LABEL maintainer="ACE Team"
LABEL description="ACE Analysis Engine"
LABEL version="1.0"

# Set environment variables
ENV SAQ_HOME=/opt/ace \
    SAQ_USER=ace \
    SAQ_GROUP=ace \
    TZ=UTC \
    DEBIAN_FRONTEND=noninteractive

# Build arguments
ARG SAQ_USER_ID=${SAQ_USER_ID}
ARG SAQ_GROUP_ID=${SAQ_GROUP_ID}
ARG http_proxy
ARG https_proxy

# Set proxy environment variables if provided
ENV http_proxy=$http_proxy \
    https_proxy=$https_proxy

# Create user and group
RUN groupadd ace -g $SAQ_GROUP_ID && \
    useradd -g ace -m -s /bin/bash -u $SAQ_USER_ID ace

# Update sources and add Microsoft repository
RUN sed -i -e '/^Components: main$/ s/$/ contrib non-free/' /etc/apt/sources.list.d/debian.sources && \
    sed -i -e '/^Suites: bookworm bookworm-updates$/ s/$/ bookworm-backports/' /etc/apt/sources.list.d/debian.sources && \
    wget https://packages.microsoft.com/config/debian/12/packages-microsoft-prod.deb -O /tmp/packages-microsoft-prod.deb && \
    dpkg -i /tmp/packages-microsoft-prod.deb && \
    rm /tmp/packages-microsoft-prod.deb

# Install system dependencies in a single layer
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        apt-utils \
        apt-transport-https \
        automake \
        bison \
        bsdmainutils \
        build-essential \
        ca-certificates \
        curl \
        default-jre \
        default-mysql-client \
        dmg2img \
        dnsutils \
        dirmngr \
        file \
        flex \
        gcc \
        ghostscript \
        git \
        htop \
        less \
        libbz2-dev \
        libffi-dev \
        libfuzzy-dev \
        libgdbm-dev \
        libimage-exiftool-perl \
        libldap2-dev \
        libmagic-dev \
        libncurses5-dev \
        libnss3-dev \
        libreadline-dev \
        libsasl2-dev \
        libsqlite3-dev \
        libssl-dev \
        libtool \
        libxml2-dev \
        libxslt1-dev \
        libyaml-dev \
        locales \
        lsb-release \
        lsof \
        make \
        man \
        net-tools \
        nginx \
        nmap \
        node-esprima \
        openjdk-17-jre \
        p7zip-full \
        p7zip-rar \
        pkg-config \
        poppler-utils \
        rng-tools \
        rsync \
        screen \
        smbclient \
        software-properties-common \
        ssdeep \
        strace \
        tcpdump \
        tshark \
        unace-nonfree \
        unixodbc-dev \
        unrar \
        unzip \
        upx-ucl \
        exiftool \
        libarchive-zip-perl \
        vim \
        wireshark-common \
        zip \
        zlib1g-dev \
        dmg2img \
        dotnet-runtime-9.0 \
        tesseract-ocr \
        libtesseract-dev \
        enchant-2 \
        zbar-tools && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create necessary directories
RUN mkdir -p /opt/signatures /opt/ace /venv /opt/misc && \
    chown -R ace:ace /opt/signatures /opt/ace /venv /opt/misc

# Configure Python and install base packages
RUN python3 -m pip config set global.cert /etc/ssl/certs/ca-certificates.crt && \
    python3 -m pip install --no-cache-dir pip virtualenv --upgrade

# Install YARA with all required features
RUN git clone --depth 1 --branch v4.2.3 https://github.com/VirusTotal/yara.git /tmp/yara && \
    cd /tmp/yara && \
    ./bootstrap.sh && \
    ./configure --enable-magic --enable-dotnet --enable-macho --enable-dex && \
    make -j && \
    make install && \
    ldconfig && \
    rm -rf /tmp/yara

# Install additional tools
COPY packages/unautoit /usr/local/bin/unautoit
RUN chmod a+x /usr/local/bin/unautoit && \
    wget https://github.com/leibnitz27/cfr/releases/download/0.151/cfr-0.151.jar -O /usr/local/bin/cfr.jar && \
    chmod a+x /usr/local/bin/cfr.jar

# Configure locale
RUN sed -i '/en_US.UTF-8 UTF-8/ s/^# //' /etc/locale.gen && \
    locale-gen en_US en_US.UTF-8 && \
    dpkg-reconfigure locales && \
    update-locale LANG=en_US.utf8 && \
    rmdir /opt/signatures && \
    ln -s /opt/ace/etc/yara /opt/signatures

# Install Node.js and deobfuscator
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && \
    npm install --global deobfuscator && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Set up Python virtual environment
USER ace
COPY --chown=ace:ace installer/requirements.txt /venv/python-requirements.txt
COPY --chown=ace:ace installer/requirements-2.7.txt /venv/python-requirements-2.7.txt

RUN python3 -m virtualenv --python=python3 /venv && \
    . /venv/bin/activate && \
    pip config set global.cert /etc/ssl/certs/ca-certificates.crt && \
    pip install --no-cache-dir setuptools pycryptodome && \
    pip install --no-cache-dir -r /venv/python-requirements.txt && \
    pip install --no-cache-dir yara-python yara-scanner~=1.1.9

# Configure bash environment
RUN echo 'source /venv/bin/activate' >> /home/ace/.bashrc && \
    echo 'export PATH="$PATH:/opt/ace/bin:/opt/ace"' >> /home/ace/.bashrc && \
    echo 'if [ -e /opt/ace/load_environment ]; then source /opt/ace/load_environment; fi' >> /home/ace/.bashrc

# Install additional Python packages
RUN . /venv/bin/activate && \
    pip install --no-cache-dir -U \
        https://github.com/DissectMalware/xlrd2/archive/master.zip \
        https://github.com/DissectMalware/pyxlsb2/archive/master.zip \
        https://github.com/DissectMalware/XLMMacroDeobfuscator/archive/master.zip

USER ace
# the olevba library wants to reset the logging levels you set
# so we patch it so that it doesn't do that
#RUN sed -i -e '/# TODO: here it works only/,+1d' /venv/lib/python3.9/site-packages/oletools/olevba.py

RUN mkdir -p /opt/ace/data/logs /opt/ace/data/error_reports /opt/ace/data/external /opt/ace/data/var && \
    rm -rf /opt/ace/etc/yara && \
    mkdir -p /opt/ace/etc/yara && \
    touch /opt/ace/etc/yara/.empty && \
    rm -rf /opt/ace/hunts/site && \
    mkdir -p /opt/ace/hunts/site && \
    touch /opt/ace/hunts/site/.empty && \
    rm -rf /opt/ace/etc/collection/tuning && \
    mkdir -p /opt/ace/etc/collection/tuning && \
    touch /opt/ace/etc/collection/tuning/.empty && \
    rm -f /opt/ace/etc/saq.ini 2> /dev/null && \
    touch /opt/ace/etc/saq.ini && \
    find /opt/ace -type d -name __pycache__ -print0 | xargs -0 rm -rf

# Configure Git for automation
RUN git config --global user.email 'ace@localhost' && \
    git config --global user.name "ACE Automation"

# Clean up proxy settings and configure SSL
USER root
RUN rm -f /etc/apt/apt.conf.d/proxy.conf

# !!! is this needed?
RUN sed -i -e 's/MinProtocol = TLSv1.2/MinProtocol = TLSv1.0/' /etc/ssl/openssl.cnf

RUN mkdir -p /opt/ace/data/logs /opt/ace/data/error_reports /opt/ace/data/external /opt/ace/data/var
COPY --chown=ace:ace ace ace_api.py ace_uwsgi.py analyst_on_ace.png ansistrm.py api_uwsgi.py flask_config.py load_environment pytest.ini /opt/ace/
# NOTE that COPY app /opt/ace does not create /opt/ace/app, it actually copies everything inside of app into /opt/ace
# so we copy each individual thing we need
COPY --chown=ace:ace aceapi /opt/ace/aceapi
COPY --chown=ace:ace app /opt/ace/app
COPY --chown=ace:ace bin /opt/ace/bin
COPY --chown=ace:ace bro /opt/ace/bro
COPY --chown=ace:ace cron /opt/ace/cron
COPY --chown=ace:ace docker /opt/ace/docker
COPY --chown=ace:ace saq /opt/ace/saq
COPY --chown=ace:ace tests /opt/ace/tests
COPY --chown=ace:ace etc /opt/ace/etc
COPY --chown=ace:ace hunts /opt/ace/hunts

# install all available integrations
# note that all integrations are installed even if they are disabled in the config
COPY --chown=ace:ace integrations /opt/ace/integrations
RUN /opt/ace/bin/install_integrations.sh

USER ace
WORKDIR /opt/ace
VOLUME [ "/opt/ace/data", "/opt/ace/etc/yara", "/opt/ace/hunts", "/opt/ace/etc/collection" ]

# Expose necessary ports
EXPOSE 5000
