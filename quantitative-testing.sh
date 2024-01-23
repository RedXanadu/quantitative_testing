#!/bin/bash

# Copyright 2023 Andrew Howe
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.


# CRS Quantitative Testing Script
# v1.1
# Written by Andrew Howe (andrew.howe@owasp.org)
#
# This script takes input from a corpus of natural language and tests it against
# the CRS to see what false positives arise. This is designed to be tested using
# the CRS reference platform in the form of the official CRS Apache container.
#
# Invoke this script with the -h option to print the full usage documentation.

# Future ideas
# - Add option to include the rule severity level, e.g. "CRITICAL"
# - Add options to test other parts of HTTP requests, e.g. cookies, query string
#   parameters
# - Test with languages other than English, e.g. German, French, Arabic
# - A Go rewrite of this script


# Configure strings for colour output
colour_reset="\e[0m"
colour_primary_bold="\e[1;94m"
colour_secondary="\e[96m"
colour_error="\e[1;31m"
colour_warning="\e[1;33m"

# 
# usage
#
# Provide user with documentation on how to use this script
usage() {
	# Print an optional leading error string if one is provided as an
	# argument, e.g. usage "No log file given."
	if [ -n "$1" ]; then
		echo -e "${colour_error}ERROR: "$1"${colour_reset}" >&2
		echo >&2
	fi

	echo "This script should be invoked like so:" >&2
	echo "  ./$(basename $0) [options] path-to-log-file.log < corpus.txt" >&2
	echo >&2
	echo "The log file should be the error log output from your test WAF, in standard ModSecurity log format." >&2
	echo "The corpus file should be a *-sentences.txt corpus file from https://wortschatz.uni-leipzig.de/en/download (i.e. a file of payloads presented in the form <PAYLOAD_NUM><TAB><PAYLOAD><NL>)." >&2
	echo >&2
	echo "Options:" >&2
	echo "  -h          Print this usage documentation and exit" >&2
	echo "  -f          Full log output for each false positive" >&2
	echo "  -l num      Number of lines of input to process before stopping" >&2
	echo "  -x num      Process 1 in every X lines of input ('fast run' mode)" >&2
	echo "  -r id       Rule ID of interest: only show false positives for specified rule ID" >&2
	echo "  -n          No colours / plain text output" >&2
	echo "  -p num      Payload number to exclusively send" >&2
	echo "  -s IP:port  Server to send requests to (default: localhost:80)" >&2
	echo "  -m          Markdown table output mode, e.g. for posting results onto GitHub" >&2
	echo "  -y          sYnc mode: flush the log file after every test (significant (e.g. 4x) slowdown)" >&2
}


# Define the default settings
colour_output=1
server="localhost:80" # The default server is a local CRS container
full_log_output=0
sync_mode=0 # Do not sync/flush the log file for every test by default as this is very slow
declare -i payload_of_interest # Empty default value: default mode is to test all payloads
declare -i num_lines_process # Empty default value: default mode is to test all payloads
declare -i ratio_lines_process # Empty default value: default mode is to test all payloads
declare rule_id_of_interest=0 # Default mode is to show false positives for all rules
declare markdown_output=0 # Default mode is to print a simple, plain text table

# Process any provided command line options
while getopts 'ns:fl:x:r:p:myh' option
do
	case $option in
		n) colour_output=0 ;;
		s) server=$OPTARG ;;
		f) full_log_output=1 ;;
		l) num_lines_process=$OPTARG ;;
		x) ratio_lines_process=$OPTARG ;;
		r) rule_id_of_interest=$OPTARG ;;
		p) payload_of_interest=$OPTARG ;;
		m) markdown_output=1 ;;
		y) sync_mode=1 ;;
		h) usage ; exit ;;
	esac
done
shift $(($OPTIND-1))


# Set up remaining variables
# If a log file was specified at the command line then at this point it is $1
# (which is the case following the above 'shift' which consumes all flag opts)
logfile="$1"
# Declare counting variables
declare -i i=1
declare -i num_lines_processed=0
declare -i payload_found=0

# Prepare a temporary file to store the intermediate results in prior to sorting
tmp_file=$(mktemp)

# Define a cleanup process via a trap: remove the temporary file
trap "rm $tmp_file" QUIT TERM EXIT

# If colour output mode has been disabled then disable it now by emptying the
# colour strings
if [ $colour_output -eq 0 ]; then
	colour_reset=""
	colour_primary_bold=""
	colour_secondary=""
	colour_error=""
	colour_warning=""
fi


# If no log file has been specified at the command line then exit: this script
# cannot meaningfully carry out any testing without a log file to work with
if [ -z "$logfile" ]; then
	usage "No log file given."
	exit 1
fi



# Provide some user indication that the script has started
echo "Starting testing..." >&2

# The main processing loop
while read sentence
do
	# Optional mechanism to limit how many lines of input are processed
	if [ -n "$num_lines_process" ]; then
		# Break out of the loop once the requested number of lines have
		# been processed
		if [ $i -gt $num_lines_process ]; then
			break
		fi
	fi

	# Optional mechanism to limit processing to every 1 in X lines, for
	# fast runs on a large input corpus
	if [ -n "$ratio_lines_process" ]; then
		if [ $(($i % $ratio_lines_process)) -ne 0 ]; then
			# Still need to increment the counting variable
			i=$(($i+1))
			continue
		fi
	fi

	# Optional mechanism to only process one specific payload number, if a
	# number has been provided at the command line
	if [ -n "$payload_of_interest" ]; then
		# If the payload found flag is set then the relevant payload has
		# already been processed. Break out of the processing loop.
		if [ $payload_found -eq 1 ]; then
			break
		fi

		# Silently test if the current line starts with the relevant
		# payload number
		if ! echo $sentence | grep --silent "^${payload_of_interest}\s" - ; then
			# This isn't the payload we're looking for. Skip the
			# remainder of the main processing loop.
			#
			# Still need to increment the counting variable
			i=$(($i+1))
			continue
		else
			# This *is* the payload of interest.
			# Set the payload found flag variable
			payload_found=1
		fi
	fi


	# Clear out the log file before testing each payload if the log file is
	# non-empty
	if [ -s "$logfile" ]; then
		truncate --size=0 "$logfile"

		# Exit citing error if unable to truncate the log file
		if [ $? -ne 0 ]; then
			echo -e "${colour_error}ERROR: Unable to truncate the log file.${colour_reset}" >&2
			exit 1
		fi
	fi

	# The 'sentence' read into this script is (by definition/instruction) 
	# presented in the form:
	#   123\tHere is a sentence.
	# i.e.
	#   <PAYLOAD_NUM><TAB><PAYLOAD><NL>
	# As such, we cut around the separator tab to retrieve both the payload
	# and the payload number.
	payload_num=$(echo "$sentence" | cut -f1)
	payload=$(echo "$sentence" | cut -f2)

	# Send the payload
	# If it takes longer than 2 seconds to get a response then something has
	# gone seriously wrong.
	curl --silent -o/dev/null --connect-timeout 2 "$server/post" --data "payload=$payload"
	# Provide feedback via a warning message if the curl call did not succeed
	if [ $? -ne 0 ]; then
		echo -e "${colour_warning}WARNING: curl call to send payload $payload_num did not succeed.${colour_reset}" >&2
	fi

	# If sync mode has been specified then flush the log before grep-ing it
	if [ $sync_mode -eq 1 ]; then
		sync "$logfile"
	fi

	# Check if any *detection* rules were triggered.
	# Triggered detection rules will have their associated severity logged
	# (e.g. "[severity "CRITICAL"]"), so check for the presence of that.
	if grep --silent '\[severity ".*"\]' $logfile; then

		# -- Full log output mode
		if [ $full_log_output -eq 1 ]; then
			# If a "rule ID of interest" has been defined at the
			# command line then only show output if that specific
			# rule has been triggered
			if [ $rule_id_of_interest -ne 0 ]; then
				# If the rule ID cannot be found in the log then
				# skip the remainder of processing this payload
				# (means that rules were triggered but *not* the
				# rule of interest)
				if ! grep --silent '\[id "'$rule_id_of_interest'"\]' $logfile; then
					# Still need to increment the counting variable
					i=$(($i+1))
					continue
				fi
			fi

			# Print the triggering payload (line) number and the
			# payload itself
			echo -e "${colour_primary_bold}Number\tPayload${colour_reset}"
			echo -e "${colour_secondary}${payload_num}\t${payload}${colour_reset}"

			# If a "rule ID of interest" has been defined at the
			# command line then filter the log file to remove rules
			# that are not of interest before the printing step next
			if [ $rule_id_of_interest -ne 0 ]; then
				grep '\[severity ".*"\]' $logfile | grep '\[id "'$rule_id_of_interest'"\]' > $tmp_file
				cp $tmp_file $logfile
			fi

			# Print log lines for any rules that were triggered.
			# Use sed to clear our clutter from the log lines (e.g.
			# tags) leaving only the most relevant information about
			# the false positive.
			echo -e "${colour_primary_bold}Rules triggered${colour_reset}"
			grep '\[severity ".*"\]' $logfile | sed -E \
							   -e 's#\[tag "paranoia#\["paranoia#g' \
							   -e 's#\[tag[^]]+] ##g' \
							   -e 's#\[pid[^]]+] ##g' \
							   -e 's#\[line[^]]+] ##g' \
							   -e 's#\[security2[^]]+] ##g' \
							   -e 's#\[uri[^]]+] ##g' \
							   -e 's#\[hostname[^]]+] ##g' \
							   -e 's#\[client[^]]+] ##g' \
							   -e 's#\[unique_id[^]]+] ##g' \
							   -e 's# ModSecurity:#\n      ModSecurity:#g' \
							   -e 's# \[file #\n      \[file #g' \
							   -e 's#\] \[#\]\n      \[#g' \
							   -e 's#^#  #g'
			echo

		# -- Offending rule IDs only mode
		else
			# If a "rule ID of interest" has been defined at the
			# command line then only show output for that rule
			if [ $rule_id_of_interest -ne 0 ]; then
				# Process log lines that have an intact paranoia
				# level tag
				grep '\[severity ".*"\]' $logfile | grep '\[id "'$rule_id_of_interest'"\]' | grep "paranoia-level/[0-9]" | sed -E 's#^.*\[id "([0-9]*)"\].*paranoia-level/([0-9]).*$#\1 PL\2#' >> $tmp_file
				# Process log lines that are *missing* an intact
				# paranoia level tag
				grep '\[severity ".*"\]' $logfile | grep '\[id "'$rule_id_of_interest'"\]' | grep -v "paranoia-level/[0-9]" | sed -E 's#^.*\[id "([0-9]*)"\].*$#\1 PL MISSING#' >> $tmp_file

			# Default: show output for all rules
			else
				# Process log lines that have an intact paranoia
				# level tag
				grep '\[severity ".*"\]' $logfile | grep "paranoia-level/[0-9]" | sed -E 's#^.*\[id "([0-9]*)"\].*paranoia-level/([0-9]).*$#\1 PL\2#' >> $tmp_file
				# Process log lines that are *missing* an intact
				# paranoia level tag
				grep '\[severity ".*"\]' $logfile | grep -v "paranoia-level/[0-9]" | sed -E 's#^.*\[id "([0-9]*)"\].*$#\1 PL MISSING#' >> $tmp_file
			fi
		fi

	fi

	# -- Offending rule IDs only mode counter (to indicate on long runs that
	#    the script is working and has not failed)
	if [ $full_log_output -eq 0 ]; then
		if [ $(($i % 200)) -eq 0 ]; then
			num_lines_processed=$(($num_lines_processed+200))
			echo "Processed $num_lines_processed payloads" >&2
		fi
	fi

	# Increment the counting variable
	i=$(($i+1))
done


# -- Offending rule IDs only mode results summary
if [ $full_log_output -eq 0 ]; then
	# Echo a line to stderr for spacing
	echo >&2

	if [ $markdown_output -eq 0 ]; then
		# Print a header line
		echo "Freq.   ID #   Paranoia Level"
	else
		# Print header lines
		echo "| Freq.  | ID #   | Paranoia Level |"
		echo "| ------ | ------ | -------------- |"
	fi

	# Sort and print the intermediate results in the temporary file.
	# When testing uniqueness and counting, only test the first 6 characters
	# (i.e. the rule ID number). This means that lines like
	#   942200 PL2
	#   942200 PL MISSING
	# will be merged and counted as one set of false positives. This fixes
	# most missing paranoia level problems when testing a large enough
	# corpus (the "PL MISSING" lines get merged into the "PLX" lines for
	# counting purposes.)

	if [ $markdown_output -eq 0 ]; then
		sort -n $tmp_file | uniq --count --check-chars=6 | sort -rn
	else
		sort -n $tmp_file | uniq --count --check-chars=6 | sort -rn | sed -E -e 's#([^ ]) ([^ ])#\1 | \2#g' -e 's#^#|#' -e 's#$#            |#'
	fi
fi
