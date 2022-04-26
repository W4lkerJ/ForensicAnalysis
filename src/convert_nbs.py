import os
import subprocess


def convert_nbs():
    src_root = "/home/jevenari/PycharmProjects/ForensicalAnalysis/src"
    notebook_dir = f"{src_root}/notebooks"
    output_dir = f"{src_root}/converted"
    for notebook_name in os.listdir(notebook_dir):
        if notebook_name.endswith(".ipynb"):
            notebook_path = os.path.join(notebook_dir, notebook_name)
            subprocess.run(["jupyter", "nbconvert", "--to", "python", "--output-dir", output_dir, notebook_path])


if __name__ == '__main__':
    convert_nbs()
