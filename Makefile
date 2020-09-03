SHELL := /bin/bash
.PHONY = usage

usage:
	@echo -e \
		"Usage: \n"\
		"make pypack          - install all python needed packages\n"
		
pypack:
	@bash -c "pip install -r requirements.txt";
