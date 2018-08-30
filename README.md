# Introduction
This project contains Linux kernel modules used in VortiQa ADK (Application Development Kits) software meant to be used in Layerscape family of SoCs.

## Prerequisite
This project depends on Layerscape SDK (LSDK). These modules can be used in LS2088A and LS1088A targets of LSDK.

## Building
### Set environment
```
export CROSS_COMPILE=aarch64-linux-gnu-
export ARCH=arm64
export LSDK_DIR=/path/to/flexbuild
export KERNEL_PATH=$LSDK_DIR/build/linux/linux/arm64/output/LSDK-18.06-V4.9
```
### Compile
```
cd adk-kmod
make
```

