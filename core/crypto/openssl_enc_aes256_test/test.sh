#!/bin/sh

# Test AES-256-CBC encryption and decryption natively in OpenSSL and in the go program.

set -e

if [ -x "openssl_enc_aes256_test" ]; then
        TEST_TOOL=./openssl_enc_aes256_test
elif go version >/dev/null 2>&1; then
        TEST_TOOL="go run ."
else
        echo "No test tool found"
        exit 1
fi

SECRET="qwerty123"
export SECRET

DATA="$(cat <<EOF
Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec a diam lectus. 
Sed sit amet ipsum mauris. Maecenas congue ligula ac quam viverra nec consectetur 
ante hendrerit. Donec et mollis dolor. Praesent et diam eget libero egestas mattis 
sit amet vitae augue. Nam tincidunt congue enim, ut porta lorem lacinia consectetur. 
Donec ut libero sed arcu vehicula ultricies a non tortor. Lorem ipsum dolor sit amet, 
consectetur adipiscing elit. Aenean ut gravida lorem. Ut turpis felis, pulvinar a 
semper sed, adipiscing id dolor. Pellentesque auctor nisi id magna consequat sagittis. 
Curabitur dapibus enim sit amet elit pharetra tincidunt feugiat nisl imperdiet. Ut 
convallis libero in urna ultrices accumsan. Donec sed odio eros.
EOF
)"

openssl_cmd="openssl enc -d -aes-256-cbc -pbkdf2 -pass env:SECRET"
test_tool_cmd="${TEST_TOOL} -e"

echo "Testing tool encryption and openssl decryption"
echo "echo \"${DATA}\" | ${test_tool_cmd} | ${openssl_cmd}"

NEW_DATA="$(echo "${DATA}" | ${test_tool_cmd} | ${openssl_cmd})"
if [ "${DATA}" != "${NEW_DATA}" ]; then
        echo "Data mismatch"
        exit 1
fi

echo "PASSED: tool encryption and openssl decryption"
echo

openssl_cmd="openssl enc -aes-256-cbc -pbkdf2 -pass env:SECRET"
test_tool_cmd="${TEST_TOOL} -d"

echo "Testing openssl encryption and tool decryption"
echo "echo \"${DATA}\" | ${openssl_cmd} | ${test_tool_cmd}"

NEW_DATA="$(echo "${DATA}" | ${openssl_cmd} | ${test_tool_cmd})"
if [ "${DATA}" != "${NEW_DATA}" ]; then
        echo "Data mismatch"
        exit 1
fi

echo "PASSED: openssl encryption and tool decryption"
echo

