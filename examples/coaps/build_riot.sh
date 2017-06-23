#!/bin/bash

# Configuration, ToDo: Remove hard coding
DIRECTORY_CC2538DK="bin/cc2538dk"
DIRECTORY_OPENMOTE="bin/openmote-cc2538"
THREADS=4
DELETION=0

# Delete old object files
if [ $DELETION == 1 ]; then
	if [ -d "$DIRECTORY_CC2538DK" ]; then
		echo "Removing old object files for CC2538DK..."
		rm -r $DIRECTORY_CC2538DK
	fi
	if [ -d "$DIRECTORY_OPENMOTE" ]; then
		echo "Removing old object files for OpenMote..."
		rm -r $DIRECTORY_OPENMOTE
	fi
fi

# Start new build
echo "Starting new build..."
echo "For CC2538DK:"
make -j$THREADS BOARD=cc2538dk
if [[ $? != 0 ]]; then
	exit 255
fi
echo "For OpenMote:"
make -j$THREADS BOARD=openmote-cc2538
if [[ $? != 0 ]]; then
	exit 255
fi
cp $DIRECTORY_OPENMOTE/coaps.elf coaps-riot-openmote.elf

# Get size of new build
OUTPUT_NEW="$(arm-none-eabi-size $DIRECTORY_CC2538DK/coaps.elf)"
RE_NEW="([0-9]{3,6})\s*([0-9]{3,6})\s*([0-9]{3,6})\s*([0-9]{3,6})"
[[ $OUTPUT_NEW =~ $RE_NEW ]]
	TEXT_NEW=${BASH_REMATCH[1]}
	BSS_NEW=${BASH_REMATCH[2]}
	DATA_NEW=${BASH_REMATCH[3]}
	DEC_NEW=${BASH_REMATCH[4]}
	
# Get size of old build
OUTPUT_OLD="$(cat build.old)"
RE_OLD="([0-9]{3,6}),([0-9]{3,6}),([0-9]{3,6}),([0-9]{3,6})"
[[ $OUTPUT_OLD =~ $RE_OLD ]]
	TEXT_OLD=${BASH_REMATCH[1]}
	BSS_OLD=${BASH_REMATCH[2]}
	DATA_OLD=${BASH_REMATCH[3]}
	DEC_OLD=${BASH_REMATCH[4]}

# Calculate differences
TEXT_DIF=`expr $TEXT_NEW - $TEXT_OLD`
BSS_DIF=`expr $BSS_NEW - $BSS_OLD`
DATA_DIF=`expr $DATA_NEW - $DATA_OLD`
DEC_DIF=`expr $DEC_NEW - $DEC_OLD`

# Print results
echo ""
echo "Old: TEXT($TEXT_OLD), BSS($BSS_OLD), DATA($DATA_OLD), DEC($DEC_OLD)"
echo "New: TEXT($TEXT_NEW), BSS($BSS_NEW), DATA($DATA_NEW), DEC($DEC_NEW)"
echo "Dif: TEXT($TEXT_DIF), BSS($BSS_DIF), DATA($DATA_DIF), DEC($DEC_DIF)"
echo "$TEXT_NEW,$BSS_NEW,$DATA_NEW,$DEC_NEW" > build.old