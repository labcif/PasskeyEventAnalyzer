import os
import sys
import csv
from lxml import etree
from bs4 import BeautifulSoup
from Evtx.Evtx import Evtx
from datetime import datetime


class PasskeyLog:
    def __init__(self):
        pass

    def set_EventType(self, value):
        self.type = value

    def set_TimeStamp(self, value):
        self.timestamp = value

    def set_TransactionId(self, value):
        self.transactionId = value

    def set_EventConclusion(self, value):
        self.result = value

    def set_UserId(self, value):
        self.userId = value

    def set_ComputerName(self, value):
        self.computerName = value

    def set_Device(self, value):
        self.device = value

    def set_Website(self, value):
        self.website = value

    def set_Browser(self, value):
        self.browser = value

    def set_BrowserPath(self, value):
        self.browserPath = value


def object_to_row(event):
    return [event.userId, event.transactionId, event.type, event.browser, event.browserPath,
            event.website, event.timestamp, event.computerName, event.device, event.result]


def read_evtx_file(evtx_file_path):
    print(
        "-------------------------------------------------------- Reading File ------------------------------------------------------------------")
    event_path = ".//{http://schemas.microsoft.com/win/2004/08/events/event}"
    reading = False
    event_list = []

    with Evtx(evtx_file_path) as evtx:
        for record in evtx.records():

            root = etree.fromstring(record.xml())
            soup = BeautifulSoup(record.xml(), 'xml')
            event_id = root.find(event_path + "EventID").text

            #####################################
            # 1000: Start Registration          #
            # 1001: Registration Success        #
            # 1002: Failed/Canceled             #
            # 1003: Start Authentication        #
            # 1004: Authentication Success      #
            # 1005: Failed/Canceled             #
            # 1006: Start sending Ctap Cmd      #
            # 1007: Success Ctap Cmd            #
            # 1008: Connection failed           #
            #####################################

            if event_id in ["1000", "1003"]:
                event = PasskeyLog()

                transaction_id = soup.find("Data", attrs={'Name': 'TransactionId'})
                if transaction_id:
                    event.set_TransactionId(transaction_id.text)
                    # event.set_TransactionId(root.getchildren()[1].getchildren()[0].text)

                event.set_TimeStamp(record.timestamp())

                computer_name = soup.find("System")
                if computer_name:
                    computer_name = computer_name.find("Computer")
                    if computer_name:
                        event.set_ComputerName(computer_name.text)
                        # event.set_ComputerName(root.find(event_path + 'Computer').text)

                user_id = soup.find("Security")
                if user_id:
                    user_id = user_id.get('UserID')
                    if user_id:
                        event.set_UserId(user_id)
                        # event.set_UserId(root.find(event_path + 'Security').attrib.values()[0])

                event.set_EventType("Authentication" if event_id == "1003" else "Registration")
                reading = True
            elif event_id in ["1001", "1004"]:
                reading = False
                event.set_EventConclusion("Success")
                event_list.append(event)
            elif event_id in ["1002", "1005"]:
                reading = False
                event.set_Device("N/A")
                event.set_EventConclusion("Incomplete")
                event_list.append(event)

            if reading and event_id == "2104" or event_id == "2106" or event_id == "1101" or event_id == "1103":
                type = None

                event_data = soup.find("EventData")
                if not event_data:
                    return

                device_path = event_data.find("Data", attrs={'Name': 'DevicePath'})
                if device_path:
                    event.set_Device(device_path.text)
                    if event.device is None:
                        event.device = event.computerName

                rp_id = event_data.find("Data", attrs={'Name': 'RpId'})
                if rp_id:
                    event.set_Website(rp_id.text)

                # TODO

                """
                
                for data in root.getchildren()[1].getchildren():
                    if "DevicePath" in data.values():
                        event.set_Device(data.text)
                        if (event.device is None):
                            event.device = event.computerName
                        break
                    elif "RpId" in data.values():
                        event.set_Website(data.text)
                        break
                    elif "ImageName" == data.text:
                        type = data.text
                        continue
                    elif (type == "ImageName" and "Value" in data.values()):
                        event.set_BrowserPath(data.text)
                        event.set_Browser(os.path.splitext(os.path.basename(event.browserPath))[0].capitalize())
                        break
                
                """

        # Print for presentation purposes
        #####################################
        for event in event_list:
            print("User Id:", event.userId)
            print("ID:", event.transactionId)
            print("Event:", event.type)
            print("Result:", event.result)
            print("Browser Info: [", event.browser, "]", event.browserPath)
            print("Website:", event.website)
            print("Time:", event.timestamp)
            print("Computer Name:", event.computerName)
            print("Auth Device:", event.device)
            print("-----------------------------------------------")
        print("Total Events:", len(event_list))
        print("-----------------------------------------------")
        ######################################

        # Create the output folder if it doesn't exist
        os.makedirs("output_files", exist_ok=True)

        # Gets current time and assigns name to new file
        current_time = datetime.now().strftime("%d-%m-%Y_%Hh%Mm%Ss")
        csv_file_path = os.path.join("output_files", f"passkey_logins_{current_time}.csv")

        with open(csv_file_path, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            # header line
            writer.writerow(
                ['userId', 'transaction_id', 'type', 'browser', 'browserPath', 'website', 'timestamp', 'computerName',
                 'device', 'result'])
            # Input each event to a line
            for event in event_list:
                writer.writerow(object_to_row(event))

        print(f"CSV file successfully created .")


if __name__ == "__main__":
    # Replace 'path_to_evtx_file.evtx' with the actual path to your EVTX file
    # evtx_file_path1 = r'event-logs\antes\Microsoft-Windows-WebAuthN%4Operational.evtx'
    # evtx_file_path2 = r'event-logs\depois_depois\Microsoft-Windows-WebAuthN%4Operational.evtx'
    evtx_file_path3 = r'event-logs\recente\Microsoft-Windows-WebAuthN%4Operational.evtx'
    # evtx_file_path4 = r'event-logs\windows10\Microsoft-Windows-WebAuthN%4Operational.evtx'
    if len(sys.argv) == 2:
        read_evtx_file(sys.argv[1])
    else:
        # read_evtx_file(evtx_file_path1)
        # read_evtx_file(evtx_file_path2)
        read_evtx_file(evtx_file_path3)
        # read_evtx_file(evtx_file_path4)
