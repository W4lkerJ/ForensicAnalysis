
def convert():
    malware = "cerber"
    malware_dir = f"/home/jevenari/PycharmProjects/ForensicalAnalysis/data/{malware}"
    regshot_result_path = str(f"{malware_dir}/regshot_results.csv",)
    header = "Type,Operation,Path"

    file_paths = [
        # Registry
        f"{malware_dir}/key_added",
        f"{malware_dir}/key_deleted",
        f"{malware_dir}/value_added",
        f"{malware_dir}/value_modified",
        f"{malware_dir}/value_deleted",

        # Files
        f"{malware_dir}/file_added",
        f"{malware_dir}/file_modified",
        f"{malware_dir}/file_deleted",

        # Folders
        f"{malware_dir}/folder_added",
        f"{malware_dir}/folder_modified",
        f"{malware_dir}/folder_deleted",
    ]

    overall_lines = []
    for file_path in file_paths:
        file_name = file_path.split("/")[-1]

        keys = file_name.split("_")

        regshot_type = keys[0]
        operation = keys[1]

        with open(file_path, "r") as file:
            lines = file.readlines()

        typed_lines = [f"{regshot_type},{operation},{line}" for line in lines]

        overall_lines = overall_lines + typed_lines

    with open(regshot_result_path, "w") as regshot_result_file:
        regshot_result_file.writelines(overall_lines)


if __name__ == '__main__':
    convert()
