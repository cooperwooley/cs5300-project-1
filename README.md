# Heuristic Query Optimizer
### Author: Cooper Wooley
### Course: CS 5300
### Semester: Fall 2025

## Compiliation and Execution Instructions

This program requires you to have *graphviz*. The `run.sh` script downloads this, creates a virtual enviroment and runs the code. Simply run using

```sh
chmod +x run.sh
./run.sh <input_file_name>.txt
```

or

```sh
# To install graphviz if not using script
sudo apt update
sudo apt install graphviz

# To run the program
python3 src/main.py <input_file_name>.txt
```

## Input Requirements

This program needs an SQL text file as one of the arguments to run.

I assumed that all files begin with a schema and then with the query block, with the schema starting with the comment *"-- Schema Definitions --"*. (Might change in future)

## Output Description

This program creates and populates a folder `outputs/`. The files you are concerned about are `canonical.png` and `rule<num>.png*`. These are visual graphs of the query tree at each given step in the algorithm.

(Potential command line output for optimized query if considering bonus)