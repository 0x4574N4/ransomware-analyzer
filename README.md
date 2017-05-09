# Ransomware Analyzer
Tool for analyzing the behaviour of encryption-based ransomware

## Summary
The basic idea of the project is file operations (open, move/rename, read and write, delete, mapping) monitoring followed by comparing of file states before opening and after closing one.

Monitoring library is looking for following changes in files:
+ difference between the initial and secondary file header (we call it signature),
+ entropy shift from low to high values (it means encryption process),
+ integrity disruption of file format (.zip, .docx, .pptx, .xlsx).

Technically this project consists of two tools. First tool is an injector, that gets snapshot of executed processes and tries to inject monitoring library to each one. Second tool is a monitoring library, which implements all the rest of the work.

In addition, tools have following features:
- prohibition of direct disk writing with boot loader dumping,
- shadow copies removing detection,
- Microsoft Crypto API function monitoring with cryptokeys dumping.

## Installation and quick start
Use Visual Studio 2010 for compiling project.

Put compiled executables into directory "C:\Windows\ransomware_analyzer\" and create there "log" and "dump".
