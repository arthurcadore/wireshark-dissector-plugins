# Dissector Plugins for Wireshrk

## This repository is dedicated to dissector (.lua) files to be used as plugins in Wireshark software. 

---
### Prerequisites: 

- Version 4.0.6-gac2f5a01286a of Wireshak or above.
- Git version 2.34.1 (for repository clone)

--- 
### Getting Started: 

First, navigate on the repository and find the dissector file you want to use. **Once the file is located, download and insert it on the following directory:**

- For Windows:
```
C:\Program Files\Wireshark\plugins\
```
The directory can change by the location of instalation of wireshak. 

- For linux (Ubuntu 22.04):

```
$HOME/.wireshark/plugins/
```
The directory can change by the location of instalation of wireshak. 

#### Once the file was inserted into wireshak plugins folder, restart wireshak app by close all running instances and start them again, after the wireshark initialization, the plugins will be readed and you'll can interpretate the protocols by file dissectors. 

---
