#!/usr/local/autopkg/python

"""
JamfComputerGroupUploader processor for uploading items to Jamf Pro using AutoPkg
    by G Pugh

"""

# import variables go here. Do not import unused modules
import json
import re
import requests
import os.path
from base64 import b64encode
from pathlib import Path
from time import sleep
from requests_toolbelt.utils import dump
from autopkglib import Processor, ProcessorError  # pylint: disable=import-error


class JamfComputerGroupUploader(Processor):
    """A processor for AutoPkg that will upload an item to a Jamf Cloud or on-prem server."""

    input_variables = {
        "JSS_URL": {
            "required": True,
            "description": "URL to a Jamf Pro server that the API user has write access "
            "to, optionally set as a key in the com.github.autopkg "
            "preference file.",
        },
        "API_USERNAME": {
            "required": True,
            "description": "Username of account with appropriate access to "
            "jss, optionally set as a key in the com.github.autopkg "
            "preference file.",
        },
        "API_PASSWORD": {
            "required": True,
            "description": "Password of api user, optionally set as a key in "
            "the com.github.autopkg preference file.",
        },
        "group_name": {
            "required": False,
            "description": "Computer Group name",
            "default": "",
        },
        "group_template": {
            "required": False,
            "description": "Full path to the XML template",
        },
        "replace_group": {
            "required": False,
            "description": "Overwrite an existing Computer Group if True.",
            "default": False,
        },
    }

    output_variables = {
        "jamfcomputergroupuploader_summary_result": {
            "description": "Description of interesting results.",
        },
    }

    def substitute_assignable_keys(self, data):
        """substitutes any key in the inputted text using the %MY_KEY% nomenclature"""
        # whenever %MY_KEY% is found in a template, it is replaced with the assigned value of MY_KEY. This did done case-insensitively
        for custom_key in self.env:
            self.output(
                (
                    f"Replacing any instances of '{custom_key}' with",
                    f"'{str(self.env.get(custom_key))}'",
                ),
                verbose_level=2,
            )
            try:
                data = re.sub(
                    f"%{custom_key}%",
                    lambda _: str(self.env.get(custom_key)),
                    data,
                    flags=re.IGNORECASE,
                )
            except re.error:
                self.output(
                    (
                        f"WARNING: Could not replace instances of '{custom_key}' with",
                        f"'{str(self.env.get(custom_key))}'",
                    ),
                    verbose_level=2,
                )
        return data

    def logging_hook(self, response, *args, **kwargs):
        data = dump.dump_all(response)
        self.output(
            data, verbose_level=2,
        )

    def get_path_to_file(self, filename):
        """AutoPkg is not very good at finding dependent files. This function will look 
        inside the search directories for any supplied file """
        # if the supplied file is not a path, use the override directory or
        # ercipe dir if no override
        recipe_dir = self.env.get("RECIPE_DIR")
        filepath = os.path.join(recipe_dir, filename)
        if os.path.exists(filepath):
            self.output(f"File found at: {filepath}")
            return filepath

        # if not found, search RECIPE_SEARCH_DIRS to look for it
        search_dirs = self.env.get("RECIPE_SEARCH_DIRS")
        for d in search_dirs:
            for path in Path(d).rglob(filename):
                matched_filepath = str(path)
                break
        if matched_filepath:
            self.output(f"File found at: {matched_filepath}")
            return matched_filepath

    def check_api_obj_id_from_name(self, jamf_url, object_type, object_name, enc_creds):
        """check if a Classic API object with the same name exists on the server"""
        # define the relationship between the object types and their URL
        # we could make this shorter with some regex but I think this way is clearer
        object_types = {
            "package": "packages",
            "computer_group": "computergroups",
            "policy": "policies",
            "extension_attribute": "computerextensionattributes",
        }
        object_list_types = {
            "package": "packages",
            "computer_group": "computer_groups",
            "policy": "policies",
            "extension_attribute": "computer_extension_attributes",
        }
        headers = {
            "authorization": "Basic {}".format(enc_creds),
            "accept": "application/json",
        }
        url = "{}/JSSResource/{}".format(jamf_url, object_types[object_type])
        r = requests.get(url, headers=headers)
        if r.status_code == 200:
            object_list = json.loads(r.text)
            self.output(
                object_list, verbose_level=2,
            )
            obj_id = 0
            for obj in object_list[object_list_types[object_type]]:
                self.output(
                    obj, verbose_level=2,
                )
                # we need to check for a case-insensitive match
                if obj["name"].lower() == object_name.lower():
                    obj_id = obj["id"]
            return obj_id

    def upload_computergroup(
        self, jamf_url, enc_creds, group_name, group_template, obj_id=None
    ):
        """Upload computer group"""

        # import template from file and replace any keys in the template
        if os.path.exists(group_template):
            with open(group_template, "r") as file:
                template_contents = file.read()
        else:
            raise ProcessorError("Template does not exist!")

        # if JSS_INVENTORY_NAME is not given, make it equivalent to %NAME%.app
        # (this is to allow use of legacy JSSImporter group templates)
        try:
            self.env["JSS_INVENTORY_NAME"]
        except KeyError:
            try:
                self.env["JSS_INVENTORY_NAME"] = self.env["NAME"] + ".app"
            except KeyError:
                pass

        # substitute user-assignable keys
        template_contents = self.substitute_assignable_keys(template_contents)

        headers = {
            "authorization": "Basic {}".format(enc_creds),
            "Accept": "application/xml",
            "Content-type": "application/xml",
        }
        # if we find an object ID we put, if not, we post
        if obj_id:
            url = "{}/JSSResource/computergroups/id/{}".format(jamf_url, obj_id)
        else:
            url = "{}/JSSResource/computergroups/id/0".format(jamf_url)

        http = requests.Session()
        http.hooks["response"] = [self.logging_hook]
        self.output("Computer Group data:", verbose_level=2)
        self.output(template_contents, verbose_level=2)

        self.output("Uploading Computer Group...")

        count = 0
        while True:
            count += 1
            self.output(
                "Computer Group upload attempt {}".format(count), verbose_level=2
            )
            if obj_id:
                r = http.put(url, headers=headers, data=template_contents, timeout=60)
            else:
                r = http.post(url, headers=headers, data=template_contents, timeout=60)
            if r.status_code == 200 or r.status_code == 201:
                self.output(
                    "Computer Group '{}' uploaded successfully".format(group_name)
                )
                break
            if r.status_code == 409:
                # TODO when using verbose mode we could get the reason for the conflict from the output
                raise ProcessorError(
                    "WARNING: Computer Group upload failed due to a conflict"
                )
            if count > 5:
                self.output(
                    "WARNING: Computer Group upload did not succeed after 5 attempts"
                )
                self.output("\nHTTP POST Response Code: {}".format(r.status_code))
                raise ProcessorError("ERROR: Computer Group upload failed ")
            sleep(30)

    def main(self):
        """Do the main thing here"""
        self.jamf_url = self.env.get("JSS_URL")
        self.jamf_user = self.env.get("API_USERNAME")
        self.jamf_password = self.env.get("API_PASSWORD")
        self.group_name = self.env.get("group_name")
        self.group_template = self.env.get("group_template")
        self.replace = self.env.get("replace_group")
        # handle setting replace in overrides
        if not self.replace or self.replace == "False":
            self.replace = False

        # clear any pre-existing summary result
        if "jamfcomputergroupuploader_summary_result" in self.env:
            del self.env["jamfcomputergroupuploader_summary_result"]

        # encode the username and password into a basic auth b64 encoded string
        credentials = f"{self.jamf_user}:{self.jamf_password}"
        enc_creds_bytes = b64encode(credentials.encode("utf-8"))
        enc_creds = str(enc_creds_bytes, "utf-8")

        # handle files with no path
        if "/" not in self.group_template:
            self.group_template = self.get_path_to_file(self.group_template)

        # now start the process of uploading the object
        self.output(f"Checking for existing '{self.group_name}' on {self.jamf_url}")

        # check for existing - requires obj_name
        obj_type = "computer_group"
        obj_id = self.check_api_obj_id_from_name(
            self.jamf_url, obj_type, self.group_name, enc_creds
        )

        if obj_id:
            self.output(
                "Computer group '{}' already exists: ID {}".format(
                    self.group_name, obj_id
                )
            )
            if self.replace:
                self.output(
                    "Replacing existing Computer Group as 'replace_group' is set to {}".format(
                        self.replace
                    ),
                    verbose_level=1,
                )
                self.upload_computergroup(
                    self.jamf_url,
                    enc_creds,
                    self.group_name,
                    self.group_template,
                    obj_id,
                )
            else:
                self.output(
                    "Not replacing existing Computer Group. Use replace_group='True' to enforce.",
                    verbose_level=1,
                )
                return
        else:
            # post the item
            self.upload_computergroup(
                self.jamf_url, enc_creds, self.group_name, self.group_template,
            )

        # output the summary
        self.env["jamfcomputergroupuploader_summary_result"] = {
            "summary_text": "The following computer groups were created or updated in Jamf Pro:",
            "report_fields": ["group", "template"],
            "data": {"group": self.group_name, "template": self.group_template,},
        }


if __name__ == "__main__":
    PROCESSOR = JamfComputerGroupUploader()
    PROCESSOR.execute_shell()
