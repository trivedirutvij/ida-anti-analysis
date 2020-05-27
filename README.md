# Anti-analysis detection:

This tool detects popular anti-analysis tools, basically. This is an Interactive Disassembler-based tool and as such works only inside IDA.

File description:

1. anti_analysis.py:

Various anti-analysis techniques detection and estimation

2. function_xrefs.py:

Pass an import function name and get cross references to it

3. imports.py

Get all imports for the artefact

Notes:

- While all three files can be run independently, anti_analysis.py incorporates the other two’s functionalities.
- These three are IDA Scripts and must be executed as such. Executing them in for example a normal command prompt will cause an error.
- All three files should be in the same folder
- The files utilize the Python environment provided in IDA in the class VM. Since the python environment is difficult to set up, no external modules have been imported.
- The Registry Key check for anti-sandboxing is not working as expected, will be addressed before final presentation

