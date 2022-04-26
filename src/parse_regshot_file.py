import json


def parse_regshot_file():
    """
        Caution: Values modified does no split the values correctly into separate lines, since they can
        extend over multiple lines instead of just one.
    """

    malware = "Cerber"
    config_path = "/home/jevenari/PycharmProjects/ForensicalAnalysis/config/config.json"
    config = json.load(open(config_path, "r"))
    config = config[malware]

    regshot_file_path = f"{config['Dynamic']}/regshot_{malware.lower()}.txt"
    result_dir = f"/home/jevenari/PycharmProjects/ForensicalAnalysis/data/{malware}"

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


if __name__ == '__main__':
    parse_regshot_file()
