from cuisine import run
from cuisine.utils import quoted


command = "test -e '/dev/null' && echo 'TRUE'"
quoted_command = quoted(command)
print(command, quoted_command)
run(f"sh -c {quoted_command}")
