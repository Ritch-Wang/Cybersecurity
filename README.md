## Cybersecurity Portfolio

# passwordtest.py
The Python file will check the strength of the given password that we use in our daily lives and it suggests what needs to be added to make our passwords more secured.

To run it:
python3 passwordtest.py

Then it will ask to enter the password: ....

Then it will give the feedbacks of what needs to be added in the password to make it strong. 

# zerotrust.py
The python file will ask for a password to setup for the file called myvault.txt. Run the following in the terminal:
1. >>> python3 zerotrust.py setup (this will create a field asking for your password and then it will send a QR code in which after scanning it, you will receive a TOTP code which will be needed for later
2. >>> echo "Dont forget to do Portfolio" >> ~/.myvault.txt
3. >>> python3 zerotrust.py access (Will ask for the password to access the file and the TOTP code that is in obtained after scanning the QR code. After a successful verification, it will then display the contents of myvault.txt. This implementation is only acting as gateways, however it doesnt mean that it encrypts the content of the file.
