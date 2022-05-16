#!/bin/sh
CMD=$(basename $0)
REPO=$(basename `pwd`)
MSG="updating ${REPO}"
STATUS=1
TAG=

# git commit with message
git_add() {
    git add .
}
git_commit(){
    local MSG="'$1'"
    git commit -a -m "'${MSG}'"
}
git_tag(){
    local TAG="$1"
    git tag -a ${TAG} -m "'${TAG}'"
}
# usage
Usage(){
    cat <<EOH
      
      ${CMD} accepts one option - the message text for 'git commit'.
      Without this option, the script will apply a default message: '${MSG}'

      Usage:

        $ ${CMD} [-h | --help] # for this help

        $ ${CMD} [-m <message text> | --message=<message text>] [-t <tag text> | --tag=<tag text>] # for the custom commit message.

EOH
}
while [ $# -ge 1 ]
do
    ARG=$1
    case ${ARG} in
        -h|--help)
            Usage
            exit 0
        ;;
        -m|--message=*)
            if [ ${ARG} == "-m" ]
            then
                # set -x
                # echo "-m version running..."
                shift
                OPT="$*"
                # OPT=$( echo ${ARG} | grep -oe '-\w\s\+\(.*\)' | sed 's/-m//g')
                if [ -z "'${OPT}'" ]
                then
                    cat << EOR

      ERROR: missing parameter (The message text is mandatory for this option!)
    
EOR
                    exit 1
                fi
                # set +x
                MSG=${OPT}
                echo
                echo "Updating remote repository using '${MSG}' message"
                echo
                sed -i "" "s/^##.*/## ${MSG}/" ./README.md
                git_add && git_commit "'${MSG}'" && git push
            else
                echo "--message version running..."
                # echo ${ARG}
                # set -x
                echo
                OPT=$( echo ${ARG} | grep -oe '--\w\+=\(.*\)' | sed 's/--message=//g')
                echo
                if [ -z ${OPT}]
                then
cat << EOR

      ERROR: missing parameter (The message text is mandatory for this option!)
    
EOR
                    exit 1
                fi
                MSG=${OPT}
                echo "Updating remote repository using '${OPT}' message"
                git_add && git_commit ${MSG} && git push
            fi
            exit 0
        ;;
        -t|--tag=*)
            if [ ${ARG} == "-t" ]
            then
                # set -x
                # echo "-m version running..."
                shift
                OPT="$*"
                # OPT=$( echo ${ARG} | grep -oe '-\w\s\+\(.*\)' | sed 's/-m//g')
                if [ -z "'${OPT}'" ]
                then
                    cat << EOR

      ERROR: missing parameter (The message text is mandatory for this option!)
    
EOR
                    exit 1
                fi
                # set +x
                TAG=${OPT}
                echo
                echo "Tagging remote repository using '${TAG}' tag"
                echo
                git status 2>&1 >/dev/null; STATUS=$?
                if [ $STATUS -eq 0 ]
                then
                    echo -n "Add tag ${TAG}..." && git_tag "${TAG}" && echo "done!"
                    git push origin ${TAG}
                else
                    echo "Check git status!!!"
                    TAG=""
                fi
            fi
            exit 0
        ;;
        *)
            Usage
            exit 1
        ;;
    esac
    shift
done
# default behaviour using default message instead custom message
# git commit -a -m "'${MSG}'"
# git push
# git_commit ${MSG} && git push
