# Dissector Plugins for Wireshrk

## This repository contains Lua dissector files that serve as plugins for the Wireshark software.

---
### Prerequisites: 

- Version 4.0.6-gac2f5a01286a of Wireshak or above.
- Git version 2.34.1 (for repository clone)

--- 
### Getting Started: 

Clone the repository and locate the dissector file you wish to use. To do that, use the following command: 

```
git clone https://github.com/arthurcadore/wireshark-dissector-plugins
```

The file can be download directly by navigate in the repository and click on "download" button of the file visualizer. 

---
#### Once the file was downloaded, insert the file into the appropriate directory:

- For Windows:
```
C:\Program Files\Wireshark\plugins\
```
(The directory can change by the location of instalation of wireshak.)

- For linux (Ubuntu 22.04):

```
$HOME/.wireshark/plugins/
```
(The directory can change by the location of instalation of wireshak.)

#### Restart Wireshark:
Close all running instances of Wireshark and start it again. After Wireshark initializes, the plugins will be loaded, and you'll be able to interpret protocols using the dissector files.
---
