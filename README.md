# Description
This repository contains config, code and results for the IT-forensical analysis performed as part of my master thesis *Deriving protective measures against ransomware based on a forensical analysis*.

## Config
Contains a config file storing paths, that are needed by some of the code files.

## Src
This folder contains Python code for converting Jupyter Notebooks into .py files (*convert_nbs.py*), a Python script converting the output of the analysis program *Regshot* to the format of *ProcMon* (*convert_regshot_data.py*), a Python script for getting the average length of the output of the analysis program *strings* using all files in a given directory (*strings_output_length_comparison.py*). It furthermore contains the Jupyter Notebook *ResultAnalysis.ipynb* and its converted version *ResultAnalysis.py* that visualizes the results got from *ProcMon* and *Regshot* while doing the dynamic analysis of ransomware.

## Results
The results gotten from the analysis of ransomware is stored in this file. It contains the results of *strings*, *regshot*, *ProcMon* and (if existing) screenshots and/or .txt files containg the ransome messages.