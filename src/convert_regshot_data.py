import json


def get_paths(malware_dir):
    return [
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


def convert():
    # Config
    malware = "Cerber"
    config = json.load(open("/home/jevenari/PycharmProjects/ForensicalAnalysis/config/config.json"))
    data_config = config['Data']
    malware_config = config[malware]

    # Generating paths
    malware_dir = f"{data_config['Path']}/{malware}"
    regshot_result_path = str(f"{malware_dir}/regshot_{malware_config['Regshot']}",)
    file_paths = get_paths(malware_dir)

    overall_lines = ["Type,Operation,Path\n"]
    for file_path in file_paths:
        file_name = file_path.split("/")[-1]

        keys = file_name.split("_")

        regshot_type = keys[0].capitalize()
        operation = keys[1].capitalize()

        with open(file_path, "r") as file:
            lines = file.readlines()

        typed_lines = [f"{regshot_type},{operation},{line}\n" for line in lines]

        overall_lines = overall_lines + typed_lines

    with open(regshot_result_path, "w") as regshot_result_file:
        regshot_result_file.writelines(overall_lines)


if __name__ == '__main__':
    convert()
