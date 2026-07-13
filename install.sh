#!/usr/bin/env bash

[[ -z $(command -v pyinstaller) ]] && { \
	printf "\nERROR: Missing pyinstaller\nYou can run these scripts by calling \'\$ python3 <script>.py\'\nOr you can build binaries with any other method you like.\nOr install pyinstaller and run this script again.\n\n"
	exit 1
}

printf "\nThis script will automatically deposit 2 binaries called SEPinject and SEPclean into ~/.local/bin\nIf, on the slim chance you have other, unrelated binaries in this location with the same name, they will be overwritten.\n\nContinue? (N/y)"

read input
continue=${input^^}

[[ $continue == "Y" ]] && { \

	mkdir -p SEPinject SEPclean SEPsani SEPwalk SEPreap
	
	cd ./SEPinject || exit 1
	pyinstaller --onefile ../sepinject.py
	cd ..
	
	cd ./SEPclean || exit 1
	pyinstaller --onefile ../clean_cil.py
	cd ..

	cd ./SEPsani || exit 1
	pyinstaller --onefile ../SEPsani.py
	cd ..
	
	cd ./SEPwalk || exit 1
	pyinstaller --onefile ../SEPwalk.py
	cd ..

	cd ./SEPreap || exit 1
	pyinstaller --onefile ../SEPreap.py
	cd ..

	mkdir -p ~/.local/bin
	cp SEPinject/dist/sepinject 	~/.local/bin/SEPinject
	cp SEPclean/dist/clean_cil 	~/.local/bin/SEPclean
	cp SEPsani/dist/SEPsani 	~/.local/bin/SEPsani
	cp SEPwalk/dist/SEPwalk 	~/.local/bin/SEPwalk
	cp SEPreap/dist/SEPreap 	~/.local/bin/SEPreap
	cp sepcheck.sh 			~/.local/bin/SEPcheck && chmod +x ~/.local/bin/SEPcheck
	
	exit 0
}

exit 1
