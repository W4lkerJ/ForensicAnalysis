import os
import json


def parse_regshot_file(data_config, malware_config, malware):
    """
        Caution: Values modified does no split the values correctly into separate lines, since they can
        extend over multiple lines instead of just one.
    """

    regshot_file_path = f"{malware_config['Dynamic']}/regshot_{malware.lower()}.txt"
    result_dir = f"{data_config['Path']}/{malware}"

    with open(regshot_file_path, "r") as regshot_file:
        regshot_content = regshot_file.read()

        split_content = regshot_content.split("----------------------------------")

        # Remove header & footer
        split_content = split_content[1:]
        split_content = split_content[:-2]

        # A set of data consists of two lines:
        #   * <type> <operation>: <count>
        #   * <data>
        # Every set of data will be exported into a separate file determined by its type and operation
        for index in range(0, len(split_content), 2):
            type_operation_count = split_content[index]
            data = split_content[index + 1]

            # Generate filename to store data in using the regshot type and the operation
            split_type_operation = type_operation_count.split(":")[0].split()
            regshot_type = split_type_operation[0].lower()[:-1]
            operation = split_type_operation[-1].lower()

            # Handle the case that modified folders appear as "Folders changed"
            if operation == "changed":
                operation = "modified"

            file_name = f"{regshot_type}_{operation}"
            file_path = f"{result_dir}/{file_name}"

            # Remove starting newline
            data = data.strip("\n")
            data_lines = data.split("\n")
            data_lines_with_break = [data_line + "\n" for data_line in data_lines]

            with open(file_path, "w") as file:
                file.writelines(data_lines_with_break)


def convert(data_config, malware_config, malware):
    # Generating paths
    malware_dir = f"{data_config['Path']}/{malware}"
    regshot_result_path = str(f"{malware_dir}/{malware_config['Regshot']}",)
    file_paths = [f"{malware_dir}/{file}" for file in os.listdir(malware_dir)]

    overall_lines = ["Type;Operation;Path\n"]
    for file_path in file_paths:
        file_name = file_path.split("/")[-1]

        keys = file_name.split("_")

        regshot_type = keys[0].capitalize()
        operation = keys[1].capitalize()

        with open(file_path, "r") as file:
            lines = file.readlines()

        typed_lines = [f"{regshot_type};{operation};{line}" for line in lines]

        overall_lines = overall_lines + typed_lines

    with open(regshot_result_path, "w") as regshot_result_file:
        regshot_result_file.writelines(overall_lines)


def main():
    # Config
    malware = "Cerber"
    config = json.load(open("/home/jevenari/PycharmProjects/ForensicalAnalysis/config/config.json"))
    data_config = config['Data']
    malware_config = config[malware]

    # Parse the regshot into several machine-readable files
    parse_regshot_file(data_config, malware_config, malware)

    # Convert the different regshot files into a single one
    convert(data_config, malware_config, malware)


if __name__ == '__main__':
    main()
