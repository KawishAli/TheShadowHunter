import time

def readingFiles(location , cursor):
    try:
        file = open(location, "r")
        file.seek(cursor)
        data = file.read()
        complete_data_in_list = data.split("\n")
        for partial_data_in_list in complete_data_in_list[:-1]:
            time = partial_data_in_list.split(" [**] ")[0]
            alert_description = partial_data_in_list.split(" [**] ")[1]
            alert_classification = partial_data_in_list.split(" [**] ")[2]
            dateAndTime = time.split("-")
            date = dateAndTime[0]
            time = dateAndTime[1]
            description  = alert_description[alert_description.index(" ") + 1:]
            classification = alert_classification[17:alert_classification.index("]")]
            middle_data = alert_classification[alert_classification.index("]") + 3:]
            priority = middle_data[:middle_data.index("]")]
            transport_protocols = alert_classification[
                                  alert_classification.index("{") + 1:alert_classification.index("}")]
            sender_IPaddress = alert_classification[alert_classification.index("}")+2:].split("-> ")[0]
            reciver_IPaddress = alert_classification[alert_classification.index("}")+2:].split("-> ")[1]
            print(date)
            print(time)
            print(description)
            print(classification)
            print(priority)
            print(transport_protocols)
            print(sender_IPaddress)
            print(reciver_IPaddress)
            print("----------------------------------------------")
        return file.tell()
    finally:
        file.close()


location = "/var/log/snort/alert"
# file_tell = readingFiles(location , 0)
# print(file_tell)
cursor = 0
while True:
    try:
        file_tell = readingFiles(location , cursor)
        cursor = file_tell
        time.sleep(2)
    except KeyboardInterrupt:
        print("User have stopped the program")