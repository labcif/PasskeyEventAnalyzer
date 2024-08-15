import os
import sys
from bs4 import BeautifulSoup
from Evtx.Evtx import Evtx
from utils import functions as own_functions
from scripts.artifact_report import ArtifactHtmlReport
from scripts.ilapfuncs import logfunc

#--------------------------------------------------------------------
# Read the 'Microsoft-Windows-WebAuthN%4Operational.evtx' EVTX file
# extracting FIDO2 interactions: i) registrations 
# and ii) authentications
#--------------------------------------------------------------------


class PasskeyLog:
    def __init__(self):
        self.userId = None
        self.transactionId = None
        self.type = None
        self.result = None
        self.timestamp = None
        self.timestamp2 = None
        self.computerName = None
        self.device = None
        self.website = None
        self.browser = None
        self.browserPath = None

    def set_event_type(self, value):
        self.type = value

    def set_timestamp(self, value):
        self.timestamp = value

    def set_timestamp2(self,value):
        self.timestamp2 = value

    def set_transaction_id(self, value):
        self.transactionId = value

    def set_event_conclusion(self, value):
        self.result = value

    def set_user_id(self, value):
        self.userId = value

    def set_computer_name(self, value):
        self.computerName = value

    def set_device(self, value):
        self.device = value

    def set_website(self, value):
        self.website = value

    def set_browser(self, value):
        self.browser = value

    def set_browser_path(self, value):
        self.browserPath = value


def object_to_row(event):
    return [event.timestamp2,event.userId, event.transactionId, event.type, event.browser, event.browserPath,
            event.website, event.timestamp, event.computerName, event.device, event.result]


def read_evtx_file(evtx_file_path, report_folder, output_format, start_date=None, end_date=None):
    event_list = []
    count_registrations = 0
    count_authentications = 0

    logfunc("---Analyzing EVTX file---")
    with Evtx(evtx_file_path) as evtx:
        event = None
        for record in evtx.records():

            if start_date and record.timestamp() < start_date:
                continue
            if end_date and record.timestamp() > end_date and event:
                continue

            soup = BeautifulSoup(record.xml(), 'xml')

            event_id = soup.find("EventID")
            if event_id:
                event_id = event_id.text

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
                    event.set_transaction_id(transaction_id.text)

                event.set_timestamp(record.timestamp().strftime("%Y-%m-%d %H:%M:%S"))

                event.set_timestamp2(record.timestamp().strftime("%Y%m%d%H%M%S"))

                computer_name = soup.find("System")
                computer_name = computer_name.find("Computer")
                if computer_name:
                    event.set_computer_name(computer_name.text)

                user_id = soup.find("Security")
                user_id = user_id.get('UserID')
                if user_id:
                    event.set_user_id(user_id)

                event.set_event_type("Authentication" if event_id == "1003" else "Registration")
                if event_id == "1003":
                    count_authentications = count_authentications + 1
                else:
                    count_registrations = count_registrations + 1
                logfunc(f'\tOperation detected: Type: {event.type} Day: {event.timestamp}')

            elif event and event_id in ["1001", "1004"]:
                event.set_event_conclusion("Success")
                event_list.append((event.timestamp2, event.userId, event.transactionId, event.type, event.browser, event.browserPath,
                                   event.website, event.timestamp, event.computerName, event.device, event.result))
                event = None
                continue
            elif event and event_id in ["1002", "1005"]:
                event.set_event_conclusion("Incomplete")
                event_list.append((event.timestamp2,event.userId, event.transactionId, event.type, event.browser, event.browserPath,
                                   event.website, event.timestamp, event.computerName, event.device, event.result))
                event = None
                continue

            if event and (event_id == "2104" or event_id == "2106" or event_id == "1101" or event_id == "1103"):
                event_data = soup.find("EventData")

                if event_data:
                    device = event_data.find("Data", attrs={'Name': 'DevicePath'})
                    rp_id = event_data.find("Data", attrs={'Name': 'RpId'})
                    image_name = event_data.find("Data", attrs={'Name': 'Name'})

                    if rp_id:
                        event.set_website(rp_id.text)
                    elif image_name:
                        if image_name.text == "ImageName":
                            data_value = event_data.find("Data", attrs={'Name': 'Value'})
                            if data_value:
                                event.set_browser_path(data_value.text)
                                event.set_browser(os.path.splitext(os.path.basename(event.browserPath))[0].capitalize())

                    if device:
                        if device.text:
                            event.set_device(device.text)
                        else:
                            event.set_device(computer_name.text + ' (This Device)')

##FIXME
##        data_headers = (
##                'User ID', 'Transaction ID', 'Type', 'Browser', 'Browser Path', 'Website', 'Timestamp', \
##                'Computer Name', 'Device', 'Result')
        data_headers_L = (
                'Timeline','User ID', 'Transaction ID', 'Type', 'Browser', 'Browser Path', 'Website', 'Date/Time', \
                'Computer Name', 'Device', 'Result')

        if output_format == 'csv':
            event_list.insert(0, data_headers_L)
            own_functions.write_csv(os.path.join(report_folder, 'passkey_logs.csv'), event_list)

            ## logfunc('---Success, ' + str(len(event_list)) + ' Passkey operations registered---')
            info_passkey_success_to_log(count_registrations, count_authentications)

        ##    logfunc('---Success, ' + str(len(event_list)) + ' Passkey operations registered---')


        elif output_format == 'html':
            if len(event_list) > 0:
                report = ArtifactHtmlReport('Passkeys - Event Log')
                report.start_artifact_report(report_folder, 'Passkeys - Event Log')
                report.add_script()

                report.write_artifact_data_table(data_headers_L, event_list, evtx_file_path)
                report.end_artifact_report()
##                logfunc('---Success, ' + str(len(event_list)) + ' Passkey operations ---')
##            else:
##                logfunc('Passkeys - Event Log data available')
            info_passkey_success_to_log(count_registrations, count_authentications)

        elif output_format == 'xlsx':
            event_list.insert(0, data_headers_L)
            own_functions.write_excel(os.path.join(report_folder, 'passkeys_artifacts_data.xlsx'),
                                                            'Passkey Logs', event_list, is_rewrite=False)
##            logfunc('---Success, ' + str(len(event_list)) + ' Passkey operations ---')
##            logfunc('---INFO: registrations=' + str(count_registrations) + '; authentications=' + str(count_authentications) + '---')
            info_passkey_success_to_log(count_registrations, count_authentications)

#--------------------------------------------------------------------
# Formats and writes info when at least one device is found
# 2024-07-26
#--------------------------------------------------------------------
def info_passkey_success_to_log(numRegistrations,numAuthentications):
    
    if numRegistrations > 1:
        end_num_registrations_S = "s"
    else:
        end_num_registrations_S = ""

    if numAuthentications > 1:
        end_num_authentication_S = "s"
    else:
        end_num_authentication_S = ""

    num_total_operations = numRegistrations + numAuthentications
    if num_total_operations == 0:
        log_S = f"---INFO: no FIDO2's webAuthN operations found"
    else:
        num_registrations_S = f"{numRegistrations} registration{end_num_registrations_S}"
        num_authentication_S = f"{numAuthentications} authentication{end_num_authentication_S}"

        log_S = f"---Success, {num_total_operations} operations found ({num_registrations_S} + {num_authentication_S})---"
        logfunc(log_S)
##        log_S = f"---Success, {num_registrations_S} + {num_authentication_S}---"
##        logfunc(log_S)            

