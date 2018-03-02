#!/usr/bin/env python3

from vt_scan import VERSION


with open("version.txt", "w") as f:
    f.write(VERSION)
