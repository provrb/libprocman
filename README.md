<div align="center"> <h1>libprocman</h1> <p><em>Your toolkit for Windows process, token manipulation, and system-level operations.</em></p> <img alt="last-commit" src="https://img.shields.io/github/last-commit/provrb/libprocman?style=flat&logo=git&logoColor=white&color=0080ff"> <img alt="repo-top-language" src="https://img.shields.io/github/languages/top/provrb/libprocman?style=flat&color=0080ff"> <img alt="repo-language-count" src="https://img.shields.io/github/languages/count/provrb/libprocman?style=flat&color=0080ff"> </div>

A C++ library that grants access to advanced Windows internals, process management, and security token manipulation. Perfect for security research, automation, and low-level Windows programming.

## Table of Contents
- [Features](#features)
- [Building](#building)
- [Installation](#installation)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)
- [Legal Notice](#legal-notice)
- [Contact](#contact)

## Features
- ⚙️ **Process Management**: Retrieve process IDs, manage processes, and impersonate different user contexts.
- 🔐 **Token Manipulation**: Duplicate and elevate process tokens, impersonate SYSTEM or TrustedInstaller.
- ⚡️ **Native API Access**: Interact directly with low-level NT system calls.
- 💻 **Virtualization Detection**: Check if the code is running in a virtual machine.
- 💥 **Trigger BSOD**: Cause a Blue Screen of Death
- 🔑 **Windows Registry Access**: Create and modify registry keys.
- 🔒 **Security Contexts**: Query and change process security contexts.
- 🔄 **Dynamic Function Calls**: Dynamically call functions from loaded DLLs.
- 🖥️ **Start Windows Services**: Start and manage Windows services programmatically.
- 🗂️ **Add Processes to Startup**: Automatically add processes to system startup.

## Building
To build the tests executable:
1. Open your terminal and change to the project directory
2. Run the following command in the terminal.  **Note: Your g++ installation must support C++20!**
    - `cmake -B build -G Ninja`
3. Build the executable with the following command:
    - `cmake --build build`
4. Run the tests using:
    - `./build/libprocman.exe`

Any time you'd like to refactor or implement a new feature, you want to make sure your new features pass all tests.

## Installation
1. Go to the repositorys releases [page](https://github.com/provrb/libprocman/releases)
2. Choose your version; preferbly the latest release.

Depending on your use case, you can choose to pick from different file formats: 

1. **.CPP and .HPP file**: simply drag the files into your include directories and include the .hpp file
2. **.lib or .dll**: make sure to link the file to expose the functions.

## Usage
1. Include the procman.hpp and procman.cpp files in your project.
2. Create an instance of the ProcessManager class
3. Use the features provided by the class. Feel free to add your own functions!

## Contributing
Contributions are welcome! View the [contributing guidlines here!](./CONTRIBUTING.md)
## License
This project is licensed under the MIT License. See the [LICENSE](./LICENSE.md) file for details.

## Legal Notice
This software is intended for educational purposes only. By using this library, you acknowledge that you fully understand and accept the risks associated with manipulating system processes, tokens, and security contexts. The author and contributors assume no responsibility for any damage, loss of data, or system instability that may result from the use of this library. Use at your own risk. Unauthorized use or misuse of this library for malicious purposes may violate local laws and regulations.

## Contact
For inquiries or feature requests, open an issue on GitHub.