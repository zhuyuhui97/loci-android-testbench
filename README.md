# loci-android-testbench
Android testbench for network-based mobile malware analysis by LOCI team, University of Jinan.

This was developed for our work on network traffic-based mobile malware detection.
To handle a large number of collected apps, We test them on Android guest machines using this project to automatically handle the process of installing, running, and gathering generated network traffic.
We leverage ADB to run numerous commands to manipulate guest devices' Android environments in task loops.

## Features
- Managing and manipulating Android environments through ADB:
    - Concurrently manipulate multiple environments via USB, IP, and emulators. Up to 10 instances for our deployment;
    - Inject ADB commands, shell commands, and Android OS broadcasts;
    - Reset, initialize and clear user traces via recovery-mode and fastboot-mode;
    - Test guest Android environments and push prerequisites automatically.
- Running and testing target apps in guest Android environments:
    - Installing, launching, and removing apps via ADB (or android shell for malware with anti-remove technics);
    - Built-in task queue management for autonomous batch testing tasks.
- Capturing network traffics on device"
    - Raw traffic capturing based on `tcpdump`;
    - MitM attack based on `sslsplit` + `iptables`. (not included in public repo)
- Injecting input events to trigger UI widgets:
    - Random taps & key inputs;
    - Breadth/width traverse-based widget triggering.
- Autonomous task management:
    - Writing gathered files (`.pcap`) to the data storage;
    - Get new tasks from the local file system (extra scripts required).

<!-- ## Technical Overview -->

## Requirements

- Linux (only tested on this host OS)
- Platform tools and packaging tools from Android SDK, placed in `$PATH`:
    - `aapt` from packaging tools
    - `adb`, `fastboot` from platform tools
- Correct ADB privileges: http://www.janosgyerik.com/adding-udev-rules-for-usb-debugging-android-devices/
- Android environments with ADB and superuser enabled (CyanogenMod recommended for non-virtual devices)


## Usage Sample
1. Attach Android guests, List ADB devices via `adb devices`, and set ADB debug permissions on Android environments.
2. Setup configs in `config.json`.
3. Create the input directory (`config.json:input_dir`) and output directory (`config.json:output_dir`).
4. Initialize database, then mount remote file system (e.g. NAS folder for `.apk` & `.pcap` storage) on the input/output directory.
5. run `main.py`.

## Files of Interest

- `bin/`
    - `uaplugin*`: Binary files for breadth/width traverse-based widget triggering.
    - `tcpdump_armv7hf`: Cross-compiled `tcpdump` for ARM v7 SoCs.
- `apkpackage.py`: APK metadata extractor.
- `runner.py`: Execution loop and auxiliary codes for handling app testing process.
- `result_writer.py`: SQL result writer, etc.
- `main.py`: Bootstrapper and task queue initializer.
- `config.json`: Config file:
    - `:input_dir`: Where the script will load `.apk` files to build the task queue,
    - `:output_dir`: Where the script will store the collected `.pcap`.

## Acknowledgement

This projected was supported by Prof Zhenxiang Chen and [LOCI team](http://loci.ujn.edu.cn) at [University of Jinan](https://www.ujn.edu.cn).

This work and related literature works were supported by the National Natural Science Foundation of China under Grants No.61672262, No.61472164 and No.61702218, Project of Independent Cultivated Innovation Team of Jinan City under Grant No.2018GXRC002, the Shandong Provincial Key R&D Program under Grant No.2018CXG0706 and No.2019GGX101028, Project of Shandong Province Higher Educational Youth Innovation Science and Technology Program NO.2019KJN028.

Thanks Huawei Technologies for funding research projects on Android and IoT network security.

## About LOCI@University of Jinan
The Cyber Intelligence Lab (loci Lab) in the School of Information Science and Engineering at University of Jinan is directed by Prof. Zhenxiang Chen. The lab conducts research mainly on Internet traffic measurement and behavior analysis, mobile network security and privacy issues, and mobile malware detection. Recently, we are focusing on building an automatic and intelligent traffic collection and analysis system and using the network traffic to detect the malware behavior.

We are looking for extensive international collaborators and welcome scholars from the world to visit our Lab.

Site: http://loci.ujn.edu.cn

## Related Works and Literatures
Literature works used dataset collected by this code:
- *Liu et al.*
    IEdroid: Detecting Malicious Android Network Behavior Using Incremental Ensemble of Ensembles
    (ICPADS 2021)
    ([IEEE link](https://ieeexplore.ieee.org/abstract/document/9763749))
- *Zhang et al.*
    AndroCreme: Unseen Android Malware Detection Based on Inductive Conformal Learning 
    (TrustCom 2021)
    ([IEEE Link](https://ieeexplore.ieee.org/abstract/document/9724463))
- *Yan et al.*
    Effective detection of mobile malware behavior based on explainable deep neural network
    (Neurocomputing 2021)
    ([ScienceDirect Link](https://www.sciencedirect.com/science/article/pii/S092523122031657X))
- *Yan et al.*
    Network-based malware detection with a two-tier architecture for online incremental update
    (IWQoS 2020)
    ([IEEE Link](https://ieeexplore.ieee.org/abstract/document/9212829))

## Declaration
This code was designed for internal use only and to be reconstructed. Use it at your own risk!