# See https://github.com/sebastien/cuisine/issues/79
fab -f 79_wrapper_script.py -H localhost test
set +x # This causes the problem, as well as something like echo "Hello" > /dev/null
# EOF
