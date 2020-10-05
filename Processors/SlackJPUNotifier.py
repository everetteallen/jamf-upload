#!/usr/bin/python
#
# Copyright 2017 Graham Pugh
# Copyright 2020 Everette Allen
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import, print_function

import requests

from autopkglib import Processor, ProcessorError  # pylint: disable=import-error
from datetime import datetime


# Set the webhook_url to the one provided by Slack when you create the webhook at https://my.slack.com/services/new/incoming-webhook/

__all__ = ["SlackJPUNotifier"]


class SlackJPUNotifier(Processor):
    description = (
        "Posts to Slack via webhook based on output of a JamfPackageUploader run. "
        "Takes elements from "
        "https://gist.github.com/devStepsize/b1b795309a217d24566dcc0ad136f784"
        "and "
        "https://github.com/autopkg/nmcspadden-recipes/blob/master/PostProcessors/Yo.py"
    )
    input_variables = {
        "JSS_URL": {"required": False, "description": ("JSS_URL.")},
        "category": {"required": False, "description": ("Package Category.")},
        "pkg_name": {"required": False, "description": ("Title (NAME)")},
        "jamfpackageuploader_summary_result": {
            "required": False,
            "description": ("Description of interesting results."),
        },
        "slackjpu_webhook_url": {"required": False, "description": ("Slack webhook.")},
        "slackjpu_always_report" : {"required": False, "description": ("Should report or not")},
    }
    output_variables = {}

    __doc__ = description
    
    def slack_post(self, slack_data, notifiy_status):
        # Only report if there are changes to the package or if slackjpu_should_report is set to true
        if notify_status or should_report:
            response = requests.post(webhook_url, json=slack_data)
            if response.status_code != 200:
                raise ValueError(
                    f"Request to slack returned an error {response.status_code}, "
                    "the response is:\n{response.text}"
                )
        return    

    def main(self):
        JSS_URL = self.env.get("JSS_URL")
        webhook_url = self.env.get("slackjpu_webhook_url")
        JPUTitle = "New Item Upload Attempt to JSS"
        JPUIcon = ":star:" 
        
        # Don't notify unless there is something to report or set to always report
        try:
            should_report = self.env.get("slackjpu_should_report")
        except:
            should_report = False
            
        # add block for each processor until we can figure out how to loop over the processor list EGA
        
        # jamfpackageuploader  summary if available
        try:
            jamfpackageuploader_summary_result = self.env.get("jamfpackageuploader_summary_result")
            jamfpackageuploader_version = jamfpackageuploader_summary_result["data"]["version"]
            jamfpackageuploader_category = jamfpackageuploader_summary_result["data"]["category"]
            jamfpackageuploader_pkg_name = jamfpackageuploader_summary_result["data"]["pkg_name"]
            jamfpackageuploader_pkg_path = jamfpackageuploader_summary_result["data"]["pkg_path"]
            jamfpackageuploader_pkg_status = jamfpackageuploader_summary_result["data"]["pkg_status"]
            jamfpackageuploader_pkg_date = jamfpackageuploader_summary_result["data"]["pkg_date"]
            notify_status = True 
        except:
            jamfpackageuploader_pkg_status = "Error Processing Package Upload Summary"
            JPUTitle = "JamfPackageUploader Summary Unavailable"
            JPUIcon = ":alarm_clock:"
            jamfpackageuploader_version = jamfpackageuploader_category = jamfpackageuploader_pkg_name = jamfpackageuploader_pkg_path = jamfpackageuploader_pkg_status = jamfpackageuploader_pkg_date = "Unknown"
                 
        # VirusTotal data if available
        # set VIRUSTOTAL_ALWAYS_REPORT to true to report
        try:
            virus_total_analyzer_summary_result = self.env.get("virus_total_analyzer_summary_result")
            virus_total_analyzer_vtname = virus_total_analyzer_summary_result["data"]["name"]
            virus_total_analyzer_ratio = virus_total_analyzer_summary_result["data"]["ratio"]
            virus_total_analyzer_permalink = virus_total_analyzer_summary_result["data"]["permalink"]
        except:
            ratio = "Unavailable"   
        
        slack_text = (
            f"*{JPUTitle}* on URL:*{JSS_URL}*\n*{JPUIcon}* Title: *{jamfpackageuploader_pkg_name}* at Version: *{jamfpackageuploader_version}* in Category: *{jamfpackageuploader_category}* Has Status: *{jamfpackageuploader_pkg_status}*\nVirus Total Result: *{virus_total_analyzer_ratio}*\nTimeStamp:*{jamfpackageuploader_pkg_date}*\n"
        )
        
        self.slack_post(slack_text, notify_status)
        

        # jamfcategoryuploader summary if available
        notify_status = False
        try:
            jamfcategoryuploader_summary_result = self.env.get("jamfcategoryuploader_summary_result")
            jamfcategoryuploader_category = jamfcategoryuploader_summary_result["data"]["category"]
            jamfcategoryuploader_priority = jamfcategoryuploader_summary_result["data"]["priority"]
            notify_status = True
        except:
            JPUTitle = "JamfCategoryUploader Summary Unavailable"
            JPUIcon = ":alarm_clock:"        
            jamfcategoryuploader_category = jamfcategoryuploader_priority = "Unknown"
        
        slack_text = (
            f"*{JPUTitle}* on URL:*{JSS_URL}*\n*{JPUIcon}* Category: *{jamfcategoryuploader_category}* With Priority: *{jamfcategoryuploader_priority}*\n"
        )

        slack_data = {"text": slack_text}
        self.slack_post(slack_text, notify_status)
        
        
        # jamfcomputergroupuploader summary if available
        notify_status = False
        try:
            jamfcomputergroupuploader_summary_result = self.env.get("jamfcomputergroupuploader_summary_result")
            jamfcomputergroupuploader_group = jamfcomputergroupuploader_summary_result["data"]["group"]
            jamfcomputergroupuploader_template = jamfcomputergroupuploader_summary_result["data"]["template"]
            notify_status = True
        except:
            JPUTitle = "JamfCategoryUploader Summary Unavailable"
            JPUIcon = ":alarm_clock:"        
            jamfcomputergroupuploader_group = jamfcomputergroupuploader_template = "Unknown"
        
        slack_text = (
            f"*{JPUTitle}* on URL:*{JSS_URL}*\n*{JPUIcon}* The Group: *{jamfcomputergroupuploader_group}* was created with Template: *{jamfcomputergroupuploader_template}*\n"
        )
        slack_data = {"text": slack_text}
        self.slack_post(slack_text, notify_status)
        
        # jamfextensionattributeuploader summary if available
        notify_status = False
        try:
            jamfextensionattributeuploader_summary_result = self.env.get("jamfextensionattributeuploader_summary_result")
            jamfextensionattributeuploader_name = jamfextensionattributeuploader_summary_result["data"]["name"]
            jamfextensionattributeuploader_path = jamfextensionattributeuploader_summary_result["data"]["path"]
            notify_status = True
        except:
            JPUTitle = "JamfExtentionAttributeUploader Summary Unavailable"
            JPUIcon = ":alarm_clock:"        
            jamfextensionattributeuploader_name = jamfextensionattributeuploader_path = "Unknown"
        
        slack_text = (
            f"*{JPUTitle}* on URL:*{JSS_URL}*\n*{JPUIcon}* The Extention Attribute: *{jamfextensionattributeuploader_name}* was created with Path: *{jamfextensionattributeuploader_path}*\n"
        )
        slack_data = {"text": slack_text}
        self.slack_post(slack_text, notify_status)
        
        # jamfpolicyuploader summary if available
        notify_status = False
        try:
            jamfscriptuploader_summary_result = self.env.get("jamfscriptuploader_summary_result")
            jamfpolicyuploader_policy_name = jamfpolicyuploader_summary_result["data"]["policy"]
            jamfpolicyuploader_template = jamfpolicyuploader_summary_result["data"]["template"]
            jamfpolicyuploader_icon = jamfpolicyuploader_summary_result["data"]["icon"]
            notify_status = True
        except:
            JPUTitle = "JamfPolicyUploader Summary Unavailable"
            JPUIcon = ":alarm_clock:"        
            jamfpolicyuploader_policy_name = jamfpolicyuploader_policy_template = jamfpolicyuploader_policy_icon = "Unknown"
        
        slack_text = (
            f"*{JPUTitle}* on URL:*{JSS_URL}*\n*{JPUIcon}* The Policy: *{jamfpolicyuploader_policy_name}* was created with Template: *{jamfpolicyuploader_template}* and Icon: *{jamfpolicyuploader_icon}*\n"
        )
        slack_data = {"text": slack_text}
        self.slack_post(slack_text, notify_status)
        
        
        # jamfscriptuploadersummary if available
        notify_status = False
        try:
            jamfscriptuploader_summary_result = self.env.get("jamfscriptuploader_summary_result")
            jamfscriptuploader_script_name = jamfscriptuploader_summary_result["data"]["script"]
            jamfscriptuploader_path = jamfscriptuploader_summary_result["data"]["path"]
            jamfscriptuploader_category = jamfscriptuploader_summary_result["data"]["category"]
            jamfscriptuploader_priority = jamfscriptuploader_summary_result["data"]["priority"]
            jamfscriptuploader_os_req = jamfscriptuploader_summary_result["data"]["os_req"]
            jamfscriptuploader_info = jamfscriptuploader_summary_result["data"]["info"]
            jamfscriptuploader_notes = jamfscriptuploader_summary_result["data"]["notes"]
            jamfscriptuploader_p4 = jamfscriptuploader_summary_result["data"]["P4"]
            jamfscriptuploader_p5 = jamfscriptuploader_summary_result["data"]["P5"]
            jamfscriptuploader_p6 = jamfscriptuploader_summary_result["data"]["P6"]
            jamfscriptuploader_p7 = jamfscriptuploader_summary_result["data"]["P7"]
            jamfscriptuploader_p8 = jamfscriptuploader_summary_result["data"]["P8"]
            jamfscriptuploader_p9 = jamfscriptuploader_summary_result["data"]["P9"]
            jamfscriptuploader_p10 = jamfscriptuploader_summary_result["data"]["P10"]
            jamfscriptuploader_p11 = jamfscriptuploader_summary_result["data"]["P11"]
            notify_status = True
        except:
            JPUTitle = "JamfScriptUploader Summary Unavailable"
            JPUIcon = ":alarm_clock:"        
            jamfscriptuploader_script_name = jamfscriptuploader_path = jamfscriptuploader_category = jamfscriptuploader_priority = jamfscriptuploader_os_req = jamfscriptuploader_info = jamfscriptuploader_notes = jamfscriptuploader_p4 = jamfscriptuploader_p5 = jamfscriptuploader_p6 = jamfscriptuploader_p7 = jamfscriptuploader_p8 = jamfscriptuploader_p9 = jamfscriptuploader_p10 = jamfscriptuploader_p11 = "Unknown"
        
        # We could test for empty values on the other summary items and report if not blank but too much info for a useful notification. EGA
        slack_text = (
            f"*{JPUTitle}* on URL:*{JSS_URL}*\n*{JPUIcon}* The Script: *{jamfscriptuploader_script_name}* was created with Path: *{jamfscriptuploader_path}*, Category: *{jamfscriptuploader_category}*, and Priority: *{jamfscriptuploader_priority}*\n"
        )
        slack_data = {"text": slack_text}
        self.slack_post(slack_text, notify_status)
        
        # jamfxxxxuploader summary when available
        # expand here are now processor sumaries are created EGA
        
        # notify that the processor run is complete
        JPUIcon = ":Star:"
        now = datetime.now()
        notify_date = date_time = now.strftime("%m/%d/%Y, %H:%M:%S")
        slack_text = (
            f"---------- *{JPUIcon}* End of processor run for URL:*{JSS_URL}* on *{notify_date}* -----------\n"
        )
        slack_data = {"text": slack_text}
        self.slack_post(slack_text, notify_status)
        



if __name__ == "__main__":
    processor = SlackJPUNotifier()
    processor.execute_shell()
