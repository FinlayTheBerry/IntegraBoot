Minifi library source code with https://python-minifier.com/

Use the following minifier settings:
Combine Import statements: YES
Remove Pass statements: YES
Remove literal statements (docstrings): YES
Hoist Literals: NO
Rename Locals: NO
Rename Globals: NO
Convert Positional-Only Arguments to Normal Arguments: YES
Preserve any shebang line: NO
Remove assert statements: YES
Remove if statements conditional on __debug__ being True: YES
Remove return statements that are not required: YES
Remove brackets when raising builtin exceptions: YES
Evaluate constant expressions: YES
Remove annotations: YES
Remove variable annotations: YES
Remove function return annotations: YES
Remove function argument annotations: YES
Remove class attribute annotations: YES

Place minified source code into ./input.py then run the following:
zstd --ultra -22 -c input.py | base64 -w 0 > output.zst.b64 && rm input.py && featherpad output.zst.b64 && rm output.zst.b64

Additionally pefile.py must be patched in the following ways:
Remove "import ordlookup"
IntegraBoot never invokes the parts of pefile.py that call ordlookup.ordLookup so it's safe to remove this import.