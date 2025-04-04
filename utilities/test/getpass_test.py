import getpass

# Prompt the user for a password without displaying it
password = getpass.getpass("Password: ")

print("You entered a password, but it was hidden!")
print(password)