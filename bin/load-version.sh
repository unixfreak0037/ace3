#
# this is meant to be sourced not executed
#

# get the current version according to what is stored in RELEASE.VERSION
RELEASE_VERSION=$(<RELEASE.VERSION)
# if ACE_VERSION is not already exported then default to the release version
ACE_VERSION=${ACE_VERSION:-$RELEASE_VERSION}

# make sure it's set to something
if [ -z "${ACE_VERSION}" ]
then
    echo "ERROR: ACE_VERSION is not set to anything"
    exit 1
fi

export ACE_VERSION
