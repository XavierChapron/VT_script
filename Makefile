.PHONY: clean, version, copy, archive

clean:
	rm -f -r build
	rm -f -r dist
	rm -f *.spec
	rm -f *.pyc
	rm -f vt_script.zip
	rm -f version.txt
	rm -f -r vt_script

version:
	./export_version.py

copy: version
	rm -r -f vt_script
	mkdir vt_script
	cp dist/vt_scan.exe vt_script/
	cp dist/vt_scan_gui.exe vt_script/
	cp version.txt vt_script/
	cp README.md vt_script/
	cp README.txt vt_script/
	cp vt_scan.reg vt_script/

archive: copy
	zip -r vt_script vt_script
