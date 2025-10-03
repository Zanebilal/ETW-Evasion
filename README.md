[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE)

# Evading ETW techniqes

Important — Read before using
This repository is intended only for defensive research, academic study, and improving detection capabilities. It must not be used to develop, improve, or deploy malware or any offensive capabilities outside of authorized, isolated laboratory environments.

# Overview

This project demonstrates how a can an attacker evade ETW and make its malware do things that ETW can't generate log's for it. since ETW is a valuable resource to EDR's attacker dont what there malware to be catched so they do there jobs which is evading any thing that detect there malware, and in this repo we represent three techniques used by them and i hope u use them for ethical purposes.

The goal is to help defenders, incident responders, and security engineers understand past research and the detection/mitigation strategy space — not to provide operational instructions for abuse.

 ⚠**Disclaimer:** This project is for **educational** purposes only. The author does **not condone** or support any malicious or illegal activity. Use responsibly in lab environments only.


## How It Works
to get an idea how this techniques works , i created a detailes blog for this techniques including code explanation and x64dbg images for simlicity .
the link to the blog post is :
https://medium.com/@zanebilal6/d8875e7385b9

## Getting Started

1. Clone the repository:
 ```bash
    git clone https://github.com/Zanebilal/ETW-Evasion
 ```
 2. chose the technique you want to implement in your project
 3. run the code

## License

This repository is licensed under the **MIT License** — see the [LICENSE](./LICENSE) file for details.
