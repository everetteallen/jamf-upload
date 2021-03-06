#!/usr/local/autopkg/python

"""
JamfPolicyUploader processor for uploading items to Jamf Pro using AutoPkg
    by G Pugh

"""

# import variables go here. Do not import unused modules
import json
import mimetypes
import re
import requests
import os.path
import xml.etree.ElementTree as ElementTree
from base64 import b64encode
from pathlib import Path
from time import sleep
from requests_toolbelt.utils import dump
from autopkglib import Processor, ProcessorError  # pylint: disable=import-error


class JamfPolicyUploader(Processor):
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
        "policy_name": {
            "required": False,
            "description": "Policy name",
            "default": "",
        },
        "icon": {
            "required": False,
            "description": "Full path to Self Service icon",
            "default": "",
        },
        "policy_template": {
            "required": False,
            "description": "Full path to the XML template",
        },
        "replace_policy": {
            "required": False,
            "description": "Overwrite an existing policy if True.",
            "default": False,
        },
        "replace_icon": {
            "required": False,
            "description": "Overwrite an existing policy icon if True.",
            "default": False,
        },
    }

    output_variables = {
        "jamfpolicyuploader_summary_result": {
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
        matched_filepath = ""
        for d in search_dirs:
            for path in Path(d).rglob(filename):
                matched_filepath = str(path)
                break
        if matched_filepath:
            self.output(f"File found at: {matched_filepath}")
            return matched_filepath

    def get_api_obj_value_from_id(
        self, jamf_url, object_type, obj_id, obj_path, enc_creds
    ):
        """get the value of an item in a Classic API object"""
        # define the relationship between the object types and their URL
        # we could make this shorter with some regex but I think this way is clearer
        object_types = {
            "package": "packages",
            "computer_group": "computergroups",
            "policy": "policies",
            "extension_attribute": "computerextensionattributes",
        }
        headers = {
            "authorization": "Basic {}".format(enc_creds),
            "accept": "application/json",
        }
        url = "{}/JSSResource/{}/id/{}".format(
            jamf_url, object_types[object_type], obj_id
        )
        r = requests.get(url, headers=headers)
        if r.status_code == 200:
            obj_content = json.loads(r.text)
            self.output(obj_content, verbose_level=2)

            # convert an xpath to json
            xpath_list = obj_path.split("/")
            value = obj_content[object_type]
            for i in range(0, len(xpath_list)):
                if xpath_list[i]:
                    try:
                        value = value[xpath_list[i]]
                        self.output(value, verbose_level=2)
                    except KeyError:
                        value = ""
                        break
            if value:
                self.output(
                    "Value of '{}': {}".format(obj_path, value), verbose_level=2
                )
            return value

    def upload_policy(
        self, jamf_url, enc_creds, policy_name, policy_template, obj_id=None
    ):
        """Upload computer group"""

        # import template from file and replace any keys in the template
        if os.path.exists(policy_template):
            with open(policy_template, "r") as file:
                template_contents = file.read()
        else:
            raise ProcessorError("Template does not exist!")

        # substitute user-assignable keys
        template_contents = self.substitute_assignable_keys(template_contents)

        headers = {
            "authorization": "Basic {}".format(enc_creds),
            "Accept": "application/xml",
            "Content-type": "application/xml",
        }
        # if we find an object ID we put, if not, we post
        if obj_id:
            url = "{}/JSSResource/policies/id/{}".format(jamf_url, obj_id)
        else:
            url = "{}/JSSResource/policies/id/0".format(jamf_url)

        http = requests.Session()
        http.hooks["response"] = [self.logging_hook]
        self.output("Policy data:", verbose_level=2)
        self.output(template_contents, verbose_level=2)

        self.output("Uploading Policy...")

        count = 0
        while True:
            count += 1
            self.output("Policy upload attempt {}".format(count), verbose_level=2)
            if obj_id:
                r = http.put(url, headers=headers, data=template_contents, timeout=60)
            else:
                r = http.post(url, headers=headers, data=template_contents, timeout=60)
            if r.status_code == 200 or r.status_code == 201:
                self.output("Policy '{}' uploaded successfully".format(policy_name))
                break
            if r.status_code == 409:
                # TODO when using verbose mode we could get the reason for the conflict from the output
                raise ProcessorError("WARNING: Policy upload failed due to a conflict")
            if count > 5:
                self.output("WARNING: Policy upload did not succeed after 5 attempts")
                self.output("\nHTTP POST Response Code: {}".format(r.status_code))
                raise ProcessorError("ERROR: Policy upload failed ")
            sleep(30)
        return r

    def upload_policy_icon(
        self,
        jamf_url,
        enc_creds,
        policy_name,
        policy_icon_path,
        replace_icon,
        obj_id=None,
    ):
        """Upload an icon to the policy that was just created"""
        # check that the policy exists.
        # Use the obj_id if we have it, or use name if we don't have it yet
        # We may need a wait loop here for new policies
        if not obj_id:
            # check for existing policy
            self.output("\nChecking '{}' on {}".format(policy_name, jamf_url))
            obj_id = self.check_api_obj_id_from_name(
                jamf_url, "policy", policy_name, enc_creds
            )
            if not obj_id:
                raise ProcessorError(
                    "ERROR: could not locate ID for policy '{}' so cannot upload icon".format(
                        policy_name
                    )
                )

        # Now grab the name of the existing icon using the API
        existing_icon = self.get_api_obj_value_from_id(
            jamf_url,
            "policy",
            obj_id,
            "self_service/self_service_icon/filename",
            enc_creds,
        )
        if existing_icon:
            self.output(
                "Existing policy icon is '{}'".format(existing_icon), verbose_level=1
            )
        # If the icon naame matches that we already have, don't upload again
        #  unless --replace-icon is set
        policy_icon_name = os.path.basename(policy_icon_path)
        if existing_icon == policy_icon_name:
            self.output(
                "Policy icon '{}' already exists: ID {}".format(existing_icon, obj_id)
            )

        if existing_icon != policy_icon_name or replace_icon:
            url = "{}/JSSResource/fileuploads/policies/id/{}".format(jamf_url, obj_id)

            headers = {
                "authorization": "Basic {}".format(enc_creds),
            }
            http = requests.Session()
            http.hooks["response"] = [self.logging_hook]

            self.output("Uploading icon...")
            #  resource construction grabbed from python-jss / misc_endpoints.py
            content_type = mimetypes.guess_type(policy_icon_name)[0]
            resource = {
                "name": (policy_icon_name, open(policy_icon_path, "rb"), content_type)
            }

            count = 0
            while True:
                count += 1
                self.output("Icon upload attempt {}".format(count), verbose_level=2)
                r = http.post(url, headers=headers, files=resource, timeout=60)
                if r.status_code == 200 or r.status_code == 201:
                    self.output(
                        "Icon '{}' uploaded successfully".format(policy_icon_name)
                    )
                    break
                if r.status_code == 409:
                    # TODO when using verbose mode we could get the reason for the conflict from the output
                    raise ProcessorError(
                        "WARNING: Icon upload failed due to a conflict"
                    )
                if count > 5:
                    print("WARNING: Icon upload did not succeed after 5 attempts")
                    print("\nHTTP POST Response Code: {}".format(r.status_code))
                    raise ProcessorError("ERROR: Icon upload failed")
                sleep(30)
        else:
            self.output("Not replacing icon. Set replace_icon='True' to enforce...")
        return policy_icon_name

    def main(self):
        """Do the main thing here"""
        self.jamf_url = self.env.get("JSS_URL")
        self.jamf_user = self.env.get("API_USERNAME")
        self.jamf_password = self.env.get("API_PASSWORD")
        self.policy_name = self.env.get("policy_name")
        self.policy_template = self.env.get("policy_template")
        self.icon = self.env.get("icon")
        self.replace = self.env.get("replace_policy")
        # handle setting replace in overrides
        if not self.replace or self.replace == "False":
            self.replace = False
        self.replace_icon = self.env.get("replace_icon")
        # handle setting replace in overrides
        if not self.replace_icon or self.replace_icon == "False":
            self.replace_icon = False

        # clear any pre-existing summary result
        if "jamfpolicyuploader_summary_result" in self.env:
            del self.env["jamfpolicyuploader_summary_result"]

        # encode the username and password into a basic auth b64 encoded string
        credentials = f"{self.jamf_user}:{self.jamf_password}"
        enc_creds_bytes = b64encode(credentials.encode("utf-8"))
        enc_creds = str(enc_creds_bytes, "utf-8")

        # handle files with no path
        if "/" not in self.policy_template:
            self.policy_template = self.get_path_to_file(self.policy_template)

        # now start the process of uploading the object
        self.output(f"Checking for existing '{self.policy_name}' on {self.jamf_url}")

        # check for existing - requires obj_name
        obj_type = "policy"
        obj_id = self.check_api_obj_id_from_name(
            self.jamf_url, obj_type, self.policy_name, enc_creds
        )

        if obj_id:
            self.output(
                "Policy '{}' already exists: ID {}".format(self.policy_name, obj_id)
            )
            if self.replace:
                self.output(
                    "Replacing existing policy as 'replace_policy' is set to {}".format(
                        self.replace
                    ),
                    verbose_level=1,
                )
                r = self.upload_policy(
                    self.jamf_url,
                    enc_creds,
                    self.policy_name,
                    self.policy_template,
                    obj_id,
                )
            else:
                self.output(
                    "Not replacing existing policy. Use replace_policy='True' to enforce.",
                    verbose_level=1,
                )
                return
        else:
            # post the item
            r = self.upload_policy(
                self.jamf_url, enc_creds, self.policy_name, self.policy_template,
            )

        # now upload the icon to the policy if specified in the args
        if self.icon:
            # handle files with no path
            if "/" not in self.icon:
                self.icon = self.get_path_to_file(self.icon)

            # get the policy_id returned from the HTTP response
            try:
                policy_id = ElementTree.fromstring(r.text).findtext("id")
                policy_icon_name = self.upload_policy_icon(
                    self.jamf_url,
                    enc_creds,
                    self.policy_name,
                    self.icon,
                    self.replace_icon,
                    policy_id,
                )
            except UnboundLocalError:
                policy_icon_name = self.upload_policy_icon(
                    self.jamf_url,
                    enc_creds,
                    self.policy_name,
                    self.icon,
                    self.replace_icon,
                )

        # output the summary
        self.env["jamfpolicyuploader_summary_result"] = {
            "summary_text": "The following policies were created or updated in Jamf Pro:",
            "report_fields": ["policy", "template", "icon"],
            "data": {
                "policy": self.policy_name,
                "template": self.policy_template,
                "icon": policy_icon_name,
            },
        }


if __name__ == "__main__":
    PROCESSOR = JamfPolicyUploader()
    PROCESSOR.execute_shell()
