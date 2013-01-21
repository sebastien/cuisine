import cuisine, os

TEXT = "file_write is broken"
PATH = "/tmp/cuisine-bug-124.txt"
if os.path.exists(PATH): os.unlink(PATH)

cuisine.connect("localhost")
cuisine.file_write(PATH, TEXT)
assert os.path.exists(PATH), "file_write did not create file %s" % (PATH)
text = file(PATH).read()
assert TEXT == text, "Expected: %s, got %s" % (repr(TEXT), repr(text))
print "OK"
# EOF
