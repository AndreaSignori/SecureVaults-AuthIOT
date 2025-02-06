from SVManager import SVManager

import re

if __name__ == "__main__":
    DB_NAME = "data/devices.db"
    # Define the regex pattern
    pattern = r"^\d+(?:,\d+)*$"

    manager = SVManager(DB_NAME)

    print("IoT device registration platform!")

    # input ID
    id: str = input("Enter the device id: ")

    # insert the device ID into the database
    manager.insert_device(id)

    while not bool(re.fullmatch(pattern, (sv := input("Enter the initial secure-vault for the device: ")))):
        print("The input should be have the following structure: x,y,z,... where x,y,z are integers!")

    # insert the initial secure-vault value
    manager.update_SV(id, sv)