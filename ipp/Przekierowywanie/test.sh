#!/bin/bash

RED="\e[31m"
GREEN="\e[32m"
ENDCOLOR="\e[0m"

declare -a test_names=("empty_struct" "no_forward" "wrong_arguments" "malicious_arguments" "breaking_struct" "long_numbers" "copy_arguments"
  "two_structs" "delete_null" "persistent_results" "forward_overwrite" "remove_forward" "various_ops" "many_ops"
  "very_long" "many_remove" "add_remove" "twelve_digits" "cycle" "sort" "alloc_fail_1" "alloc_fail_2")

counter=0
testing_folder=$1
if [ ! -d "${testing_folder}" ]; then
  exit
fi

val="--error-exitcode=123 --leak-check=full --show-leak-kinds=all --errors-for-leak-kinds=all"

for i in "${test_names[@]}"; do
  echo -e "${RED}------------${counter}------------\n${ENDCOLOR}"
  valgrind ${val} ./"${testing_folder}"/phone_forward_instrumented "${i}"
  echo -e "${GREEN}exit code = $? \n${ENDCOLOR}"
  counter=$((counter + 1))
done
