import time
import pymongo

list_of_ristricted_IPs = []


def readingFiles(location, cursor):
    my_list = []
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
            description = alert_description[alert_description.index(" ") + 1:]
            classification = alert_classification[17:alert_classification.index("]")]
            middle_data = alert_classification[alert_classification.index("]") + 3:]
            priority = middle_data[:middle_data.index("]")]
            transport_protocols = alert_classification[
                                  alert_classification.index("{") + 1:alert_classification.index("}")]
            sender_IPaddress = alert_classification[alert_classification.index("}") + 2:].split("-> ")[0]
            receiver_IPaddress = alert_classification[alert_classification.index("}") + 2:].split("-> ")[1]

            if ":" in sender_IPaddress:
                IP = sender_IPaddress[:sender_IPaddress.index(":")]
                if IP not in list_of_ristricted_IPs:
                    list_of_ristricted_IPs.append(IP)
                    query = {"Date": date, "Time": time, "incoming_ip": IP}
                    DB_connection("alerts", query)
                    print("An alert is sent")

            elif ":" not in sender_IPaddress:
                if sender_IPaddress not in list_of_ristricted_IPs:
                    list_of_ristricted_IPs.append(sender_IPaddress)
                    query = {"Date": date, "Time": time, "incoming_ip": sender_IPaddress}
                    DB_connection("alerts", query)
                    print("An alert is sent")

            temp_dic = {"Date": date, "Time": time, "Description": description, "Classification": classification
                , "Transport_Protocol": transport_protocols,
                        "Sender_Address": sender_IPaddress, "Receiver_Address": receiver_IPaddress}
            print(temp_dic)
            my_list.append(temp_dic)
        if my_list:
            print(my_list)
            DB_connection("logs", my_list)
            print("data is entered correctly")
        my_list.clear()
        return file.tell()
    finally:
        file.close()


def Sending_data_to_DB(myclient, mydb, query):
    db = myclient["shadowhunters"]
    mycol = db[mydb]
    mycol.inert_one(query)


def DB_connection(mydb, query):
    myclient = pymongo.MongoClient("mongodb://182.180.96.204:27017")
    db = myclient["shadowhunters"]
    if mydb == "logs":
        mycol = db["logs"]
        mycol.insert_many(query)
    elif mydb == "alerts":
        mycol = db["alerts"]
        mycol.insert_one(query)
    myclient.close()


def accessing_local_DB():
    # myclient = pymongo.MongoClient("mongodb://192.168.18.6:27017")
    # mydb = myclient["shadowhunter-backend"]
    # mycol = mydb["VMdetails"]
    # for x in mycol.find():
    #     list_of_ristricted_IPs.append(x["onet_VM_ip"])
    list_of_ristricted_IPs.append("")
    list_of_ristricted_IPs.append("0.0.0.0")
    # myclient.close()



location = "/var/log/snort/alert"
cursor = 0
accessing_local_DB()
while True:
    try:
        file_tell = readingFiles(location, cursor)
        cursor = file_tell
        time.sleep(2)
    except KeyboardInterrupt:
        print("User have stopped the program")
