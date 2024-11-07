import os

OLD_PACKAGE = "hackingBuddyGPT"
NEW_PACKAGE = "herbieP"

def replace_in_file(file_path, old_text, new_text):
    with open(file_path, 'r') as file:
        content = file.read()
    content = content.replace(old_text, new_text)
    with open(file_path, 'w') as file:
        file.write(content)

def update_imports(root_dir):
    for root, _, files in os.walk(root_dir):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                replace_in_file(file_path, OLD_PACKAGE, NEW_PACKAGE)

# Example usage
update_imports("src")

print("Renaming complete! Don't forget to test your changes!")
