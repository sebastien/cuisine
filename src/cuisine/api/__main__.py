import os
import sys
import argparse
from ..api import toSource
parser = argparse.ArgumentParser(
    prog=os.path.basename(__file__.split(".")[0]),
    description="Generate Cuisine API stubs and implementation"
)
parser.add_argument("-o", "--output",    type=str,  dest="output", default="-",
                    help="Specifies an output file")
parser.add_argument("-t", "--type",      type=str,  dest="type",  default="stub",
                    help="The type of output, either stub or impl")
args = parser.parse_args(args=sys.argv[1:])
out = sys.stdout if args.output == "-" else open("args.output", "wt")
for line in toSource(implementation=args.type != "stub"):
    out.write(line)
    out.write("\n")

# EOF
