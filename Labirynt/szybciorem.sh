#!/bin/bash

RED="\e[31m"
GREEN="\e[32m"
CYAN="\e[36m"
ENDCOLOR="\e[0m"

if [ $# != 2 ]; then
    echo WRONG NUMBER OF PARAMETERS
    exit 1
fi

if [ ! -x $1 ]; then
    echo WRONG PROGRAM
    exit 1
fi

if [ ! -d $2 ]; then
    echo WRONG DIRECTORY
    exit 1
fi

prog=$(readlink -e $1)
dir=$(readlink -e $2)
count=0

touch result.out
touch error.out
touch temp.out
val="--error-exitcode=123 --leak-check=full --show-leak-kinds=all --errors-for-leak-kinds=all --log-fd=9"

echo -e "${CYAN}---- TESTING ----${ENDCOLOR}"
for input in ${dir}/*.in; do
    echo ==== "$(basename ${input})" ====
    time (${prog} <${input} 1>result.out 2>error.out)
    extcode=$?
    printf "\nResult:\n"
    cat result.out error.out
    echo Program ended with exit code ${extcode}.
    echo
    cat temp.out
    echo

    output=${input%in}
    if (diff error.out ${output}err >/dev/null 2>&1) && (diff result.out ${output}out >/dev/null 2>&1); then
        echo -e "${GREEN}---- SUCCESS ----${ENDCOLOR}"
        printf "Test "$(basename -s .in ${input})" successfully completed!\n"
        count=$((count + 1))
        echo -e "${GREEN}---- SUCCESS ----${ENDCOLOR}"
    else
        echo -e "${RED}---- ERROR ----${ENDCOLOR}"
        echo "Program ended up with different result for test "$(basename ${input})"."
        echo Expected result:
        cat ${output}out ${output}err
        echo Obtained result:
        cat result.out error.out
        echo -e "${RED}---- ERROR ----${ENDCOLOR}"
        break
    fi
done

rm result.out
rm error.out
rm temp.out
echo -e "${CYAN}---- TESTING ENDED ----${ENDCOLOR}"
echo Tests completed successfully: ${count}
