# Libbpf-bootstrap for android
Using libbpf-bootstrap to develop and cross-compile the ebpf kernel and user program of arm64 platform using wsl2 on x86_64 machine, libbpf-bootstrap can realize the CO-RE of eBPF.

# usage
* Prepare the environment
```
git clone --recursive https://github.com/revercc/libbpf-bootstrap-for-android.git
cd libbpf-bootstrap-for-android
sudo apt install gcc-aarch64-linux-gnu llvm clang 
wget https://dl.google.com/android/repository/android-ndk-r25c-linux.zip android-ndk-r25c-linux.zip
unzip android-ndk-r25c-linux
```
* The ndk is added to the environment variable
```
vim ~/.bshrc
export PATH=xxxxx/android-ndk-r25c/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH
```
* development

wsl + vscode + clangd
* build
```
cd src && make
```
