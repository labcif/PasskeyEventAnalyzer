import os
import sys
import codecs
from lxml import etree
from Evtx.Evtx import Evtx

def read_evtx_file(evtx_file_path):
    event_path = ".//{http://schemas.microsoft.com/win/2004/08/events/event}"
    with Evtx(evtx_file_path) as evtx:
        for record in evtx.records():
            root = etree.fromstring(record.xml())
            event_id = root.find(event_path+ "EventID")
            #print(f"EVENT ID: {event_id.text}")
            if event_id.text == "1101" or event_id.text == "1103":
                #print(f"{record.xml()}")


                #DEBUGING PURPOSES
                eventData = root.getchildren()[1].getchildren()
                Sys = root.getchildren()[0].getchildren()
                registry = root.find(event_path + "Security").attrib.values()[0]
                #------------------------------------------------------------------

                if event_id.text == "1103":
                    print("Use Type: AUTHENTICATION")
                else:
                    print("Use Type: REGISTRATION")
                print(f"Record Id: {root.find(event_path + 'EventRecordID').text}")
                print(f"Event Id: {event_id.text}")
                print(f"Timestamp: {record.timestamp()}")
                print(f"Computer Name: {root.find(event_path+ 'Computer').text}")
                print(f"Registry: {root.find(event_path+ 'Security').attrib.values()[0]}")
                print(f"Website: {eventData[1].text}")
                print("========================================================")




if __name__ == "__main__":
    # Replace 'path_to_evtx_file.evtx' with the actual path to your EVTX file
    evtx_file_path = r'event-logs\depois\Microsoft-Windows-WebAuthN%4Operational_depois.evtx'
    if len(sys.argv) == 2:
        read_evtx_file(sys.argv[1])
    else:
        read_evtx_file(evtx_file_path)
