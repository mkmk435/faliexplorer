import argparse


import pefile
import capstone as Cs


def disasm_


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('path', type=str, help='dir (including subdirectory) or file path to the driver(s) to analyze')

    args = parser.parse_args()

    driver = args.path

    print(f"ANALYZING DRIVER: {driver}")

