# Disclaimer

This repository is no longer being maintained. Please prefer [`nso-tools`](https://github.com/dt-12345/nso-tools) instead. Note that it only supports 64-bit NSOs and NROs, not KIPs nor any 32-bit binary. If you are trying to load one of those, please refer to the [upstream repository](https://github.com/adubbz/ghidra-switch-loader) instead. To load an NSO/NRO with `nso-tools`:

1. Run `nso2elf -o main.nss main` (replace `main` with whatever your file is called, use `nro2elf` if loading an NRO)
2. In Ghidra, open the project you wish to load the binary into (if you don't have a project, create a new one by selecting `File` -> `New Project` -> `Non-Shared Project`, then enter a project name and finish)
3. Select `File` -> `Import File` (or press `I` on your keyboard) and select `main.nss` (or whatever your file was called)
4. On the import screen, go to `Options` -> `Image Base` and set it to `7100000000` (optional, but provides parity with the behavior of the extension)
5. Select `OK` and wait for the import to finish
6. Open the imported file in the CodeBrowser, you should be prompted to analyze the binary (if not, select `Analysis` -> `Auto Analyze...`)
7. Keep the default options and select `Analyze` then wait for analysis to finish (this can take a long time)

# Ghidra Switch Loader

A loader for Ghidra supporting a variety of Nintendo Switch file formats.

## Building

- Ensure you have ``JAVA_HOME`` set to the path of your JDK 21 installation.
- Set ``GHIDRA_INSTALL_DIR`` to your Ghidra install directory. This can be done in one of the following ways:
  - **Windows**: Running ``set GHIDRA_INSTALL_DIR=<Absolute path to Ghidra without quotations>``
  - **macos/Linux**: Running ``export GHIDRA_INSTALL_DIR=<Absolute path to Ghidra>``
  - Using ``-PGHIDRA_INSTALL_DIR=<Absolute path to Ghidra>`` when running ``./gradlew``
  - Adding ``GHIDRA_INSTALL_DIR`` to your Windows environment variables.
- Run ``./gradlew``
- You'll find the output zip file inside `/dist`

## Installation

- Start Ghidra and use the "Install Extensions" dialog (``File -> Install Extensions...``).
- Press the ``+`` button in the upper right corner.
- Select the zip file in the file browser, then restart Ghidra.
