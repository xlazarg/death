#!/usr/bin/env python3

import json
import sys

# Take positional argument if exists, otherwise use default path to NDJSON input file

rules_file = sys.argv[1] if len(sys.argv) > 1 else "rules.ndjson"

# Set desired field values to be modified in the rules file
# Set value to `None` to disable modification for that field

enabled = True                 # whether the rule is activated after import
interval = 1                   # how often the rule is run, in minutes
lookback_offset = 1            # how far back in time past the interval to search, in minutes
index = ["logs-*"]             # the index(es) to search in

# List any optional fields added by Sigma CLI to be removed from the import file

excluded_fields = {}

# For instance, the following fields are not available in Elastic Security before version 8.3 but added by Sigma CLI
# They would need to be dropped before import if running an older version

#excluded_fields = {
#    "related_integrations",
#    "required_fields",
#    "setup"
#}

# Read in the file contents and convert its lines to a list

with open(rules_file, "r") as f:
    lines = f.readlines()

# Loop through each line, parse the data from JSON, and modify the specified field values in place
# For each custom field, check that the value set above is not `None` and that the field exists before modifying it

with open(rules_file, "w") as f:
    for line in lines:
        data = json.loads(line)

        # if excluded_fields is not empty, filter out each item in the data

        if len(excluded_fields) > 0:
            data = {k: v for k, v in data.items() if k not in excluded_fields}

        if enabled is not None and "enabled" in data:
            data["enabled"] = enabled

        if interval is not None and "interval" in data:
            data["interval"] = f"{interval}m"

        if lookback_offset is not None and interval is not None and "from" in data:
            data["from"] = f"now-{lookback_offset + interval}m"

        if index is not None and "index" in data:
            data["index"] = index

        f.write(json.dumps(data) + "\n")
