#!/bin/bash
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
SRC_DIR=$( cd "$( dirname "${DIR}" )" && pwd )

ANVILL_PYTHON="python3 -m anvill"
ANVILL_DECOMPILE="anvill-decompile-spec"
function Help
{
  echo "Run Anvill on AnghaBech-1K"
  echo ""
  echo "Options:"
  echo "  --python-cmd <cmd>        The anvill Python command to invoke. Default ${ANVILL_PYTHON}"
  echo "  --decompile-cmd <cmd>     The anvill decompile command to invoke. Default ${ANVILL_DECOMPILE}"
  echo "  -h --help                 Print help."
}

function check_test
{
    local input_json=${1}
    #if [[ ! -f $(pwd)/results/${arch}/python/stats.json ]]
    if [[ ! -f ${1} ]]
    then
        echo "[!] Could not find python results for: ${arch}"
        return 1
    fi

    # count number of failures
    fail_msg=$(\
		PYTHONPATH=${SRC_DIR}/libraries/lifting-tools-ci/tool_run_scripts \
		python3 -c "import stats,sys; s=stats.Stats(); s.load_json(sys.stdin); print(s.get_fail_count())" \
        < ${input_json})

    echo "[!] There were [${fail_msg}] failures on ${arch}:"
    PYTHONPATH=${SRC_DIR}/libraries/lifting-tools-ci/tool_run_scripts \
        python3 -c "import stats,sys; s=stats.Stats(); s.load_json(sys.stdin); s.print_fails()" \
        < ${input_json}

    if [[ "${fail_msg}" != "0" ]]
    then
        return 1
    fi

    return 0
}

set -euo pipefail

while [[ $# -gt 0 ]] ; do
    key="$1"

    case $key in

        -h)
            Help
            exit 0
        ;;

        --help)
            Help
            exit 0
        ;;

        # Anvill python cmd
        --python-cmd)
            ANVILL_PYTHON=${2}
            shift # past argument
        ;;

        # How large of a run to get
        --decompile-cmd)
            ANVILL_DECOMPILE=${2}
            shift # past argument
        ;;

        *)
            # unknown option
            echo "[x] Unknown option: ${key}"
            exit 1
        ;;
    esac

    shift # past argument or value
done

if ! PYTHONPATH=${SRC_DIR}/libraries/lifting-tools-ci/tool_run_scripts \
	python3 -c "import stats" &>/dev/null
then
    echo "[!] Could not set PYTHONPATH=${PYTHONPATH} to get stats"
    exit 1
fi

if ! ${ANVILL_PYTHON} --help &>/dev/null;
then   
    echo "[!] Could not execute anvill python cmd: ${ANVILL_PYTHON}"
    exit 1
fi

if ! ${ANVILL_DECOMPILE} --version &>/dev/null;
then   
    echo "[!] Could not execute anvill decompile cmd: ${ANVILL_DECOMPILE}"
    exit 1
fi

# create a working directory
mkdir -p angha-test-1k
pushd angha-test-1k

# fetch the test set: 1K binaries (per arch)
${SRC_DIR}/libraries/lifting-tools-ci/datasets/fetch_anghabench.sh --run-size 1k --binaries
# extract it
for tarfile in *.tar.xz
do
    tar -xJf ${tarfile}
done

FAILED="no"
for arch in $(ls -1 binaries/)
do
    echo "[+] Testing architecture ${arch}"
    ${SRC_DIR}/libraries/lifting-tools-ci/tool_run_scripts/anvill.py \
        --anvill-python "${ANVILL_PYTHON}" \
        --anvill-decompile "${ANVILL_DECOMPILE}" \
        --input-dir "$(pwd)/binaries/${arch}" \
        --output-dir "$(pwd)/results/${arch}" \
        --run-name "anvill-live-ci-${arch}" \
        --test-options "${SRC_DIR}/ci/angha_1k_test_settings.json" \
        --dump-stats


    if ! check_test "$(pwd)/results/${arch}/python/stats.json"
    then
        echo "[!] Failed python spec generation for ${arch}"
        FAILED="yes"
    fi
    if ! check_test "$(pwd)/results/${arch}/decompile/stats.json"
    then
        echo "[!] Failed decompilation from spec for ${arch}"
        FAILED="yes"
    fi

done

if [[ "${FAILED}" = "no" ]]
then
	echo "[+] All tests successful!"
    exit 0
fi

echo "[!] One or more failures encountered during test"
exit 1
