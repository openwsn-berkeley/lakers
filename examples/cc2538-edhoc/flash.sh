#! /usr/bin/sh

cargo build --target thumbv7m-none-eabi --no-default-features --features cc2538 --example cc2538-edhoc
#cargo build --release

# First convert the elf to binary.
mkdir -p ./tmp
llvm-objcopy -O binary $1 ./tmp/flash.bin 
cp $1 ./tmp/flash

# Flash the device
JLinkExe -Device cc2538sf53 -Speed 4000 -If JTAG -JTAGConf "-1,-1" -AutoConnect 1 -ExitOnError 1 -CommandFile jlink_commands.jlink
