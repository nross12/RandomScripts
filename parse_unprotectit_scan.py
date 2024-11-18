import argparse
import pprint

def parse_content(raw_text):
    lines = raw_text.split("\n")

    data = {"Scan Result": None, "Sample Information": {}, "Important Imports": [], 
            "Matching Rules": [], "Matching Techniques": []}

    current_section = None

    for line in lines:
        line = line.strip()
        if not line:
            continue

        if line.startswith("Scan Result:"):
            data["Scan Result"] = line.split(":", 1)[1].strip()
        elif line == "Sample Information":
            current_section = "Sample Information"
        elif line == "Important Imports":
            current_section = "Important Imports"
        elif line == "Matching Rules":
            current_section = "Matching Rules"
        elif line == "Matching Techniques":
            current_section = "Matching Techniques"
        elif current_section == "Sample Information" and "\t" in line:
            key, value = map(str.strip, line.split("\t", 1))
            data["Sample Information"][key] = value
        elif current_section == "Important Imports":
            data["Important Imports"].append(line)
        elif current_section == "Matching Rules" and "\t" in line:
            rule_name, rule_type = map(str.strip, line.split("\t", 1))
            data["Matching Rules"].append({"Rule Name": rule_name, "Rule Type": rule_type})
        elif current_section == "Matching Techniques" and "\t" in line:
            parts = line.split("\t")
            technique = {
                "Technique Name": parts[0].strip(),
                "Technique ID's": parts[1].strip() if len(parts) > 1 else None,
                "Snippet(s)": parts[2].strip() if len(parts) > 2 else None,
                "Rules(s)": parts[3].strip() if len(parts) > 3 else None,
                "OS": parts[4].strip() if len(parts) > 4 else None,
            }
            
            data["Matching Techniques"].append(technique)

    return data
    

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parse a scan result text file.")
    parser.add_argument("input_file", help="Path to the input text file")

    args = parser.parse_args()

    try:
        with open(args.input_file, "r", encoding="utf-8") as file:
            raw_text = file.read()
    except FileNotFoundError:
        print(f"Error: The file '{args.input_file}' was not found.")
        return
    except Exception as e:
        print(f"Error: An error occurred while reading the file: {e}")
        return

    data = parse_content(raw_text)

    pprint.pprint(data)