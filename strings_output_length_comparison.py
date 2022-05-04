import os
import subprocess


def get_strings_result_length(bin_path):
    output = subprocess.check_output(["strings", bin_path]).decode("utf-8")
    split_out = output.split("\n")
    out_len = len(split_out)

    return out_len


def get_avg_strings_length():
    bin_folder = "/usr/bin"

    results = {}
    for file in sorted(os.listdir(bin_folder)):
        print("Processing", file)
        try:
            full_path = os.path.join(bin_folder, file)

            strings_result_length = get_strings_result_length(full_path)
            results[file] = strings_result_length
        except Exception:
            print("Error - Skipping file")

    length_values = list(results.values())
    avg = round(sum(length_values) / len(length_values), 2)

    print(avg)


def main():
    get_avg_strings_length()


if __name__ == '__main__':
    main()
