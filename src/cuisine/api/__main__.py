import os
import sys
import argparse
from ..api import toInterface, toImplementation, toNamespace

__doc__ = """
Command-line tool to generate stubs/implementation for the flat-file
Cuisine API.
"""

parser = argparse.ArgumentParser(
    prog=os.path.basename(__file__.split(".")[0]),
    description="Generate Cuisine API stubs and implementation"
)
parser.add_argument("-o", "--output",    type=str,  dest="output", default="-",
                    help="Specifies an output file")
parser.add_argument("-t", "--type",      type=str,  dest="type",  default="stub",
                    help="The type of output, either stub or impl")
args = parser.parse_args(args=sys.argv[1:])
if args.type == "impl":
    processor = toImplementation
elif args.type == "repl":
    processor = toNamespace
elif args.type == "stub":
    processor = toInterface
else:
    raise ValueError("Expected impl, repl or stub")
out = sys.stdout if args.output == "-" else open(args.output, "wt")
for line in processor():
    out.write(line)
    out.write("\n")
# EOF
